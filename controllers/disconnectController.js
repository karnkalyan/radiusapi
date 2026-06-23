// controllers/disconnectController.js
const db = require('../config/db');
const { exec } = require('child_process');
const util = require('util');
require('dotenv').config();

const execAsync = util.promisify(exec);

// ─────────────────────────────────────────────────────────────
// Get NAS secret + ports from nas table by IP
// ports column = auth port (1812)
// CoA disconnect always uses 3799
// ─────────────────────────────────────────────────────────────
async function getNasSecret(nasIp) {
  const [rows] = await db.execute(
    `SELECT nasname, shortname, secret, ports
     FROM nas
     WHERE nasname = ?
     LIMIT 1`,
    [nasIp]
  );

  if (!rows.length) {
    throw new Error(`NAS not found in DB for IP: ${nasIp}`);
  }

  return {
    secret:    rows[0].secret,
    shortname: rows[0].shortname,
    authPort:  rows[0].ports || 1812,
    coaPort:   parseInt(process.env.NAS_COA_PORT) || 3799
  };
}

// ─────────────────────────────────────────────────────────────
// Get single active session from radacct by username
// ─────────────────────────────────────────────────────────────
async function getActiveSession(username) {
  const [rows] = await db.execute(
    `SELECT
       acctsessionid,
       nasipaddress,
       framedipaddress,
       acctstarttime,
       acctupdatetime,
       acctinputoctets,
       acctoutputoctets,
       callingstationid,
       nasportid,
       nasporttype
     FROM radacct
     WHERE username = ?
       AND acctstoptime IS NULL
     ORDER BY acctstarttime DESC
     LIMIT 1`,
    [username]
  );
  return rows[0] || null;
}

// ─────────────────────────────────────────────────────────────
// Get ALL active sessions from radacct by username
// ─────────────────────────────────────────────────────────────
async function getAllActiveSessions(username) {
  const [rows] = await db.execute(
    `SELECT
       acctsessionid,
       nasipaddress,
       framedipaddress,
       acctstarttime,
       acctupdatetime,
       acctinputoctets,
       acctoutputoctets,
       callingstationid,
       nasportid,
       nasporttype
     FROM radacct
     WHERE username = ?
       AND acctstoptime IS NULL
     ORDER BY acctstarttime DESC`,
    [username]
  );
  return rows;
}

// ─────────────────────────────────────────────────────────────
// Send Disconnect-Request to NAS via radclient
// Secret fetched from nas table dynamically
// ─────────────────────────────────────────────────────────────
async function sendDisconnectRequest(sessionId, username, nasIp) {
  const { secret, coaPort, shortname } = await getNasSecret(nasIp);

  console.log(`[disconnect] NAS: ${shortname} (${nasIp}:${coaPort}) Session: ${sessionId}`);

  const payload =
    `Acct-Session-Id=${sessionId},` +
    `User-Name=${username},` +
    `NAS-IP-Address=${nasIp}`;

  const cmd = `echo "${payload}" | radclient -x ${nasIp}:${coaPort} disconnect ${secret}`;

  try {
    const { stdout, stderr } = await execAsync(cmd, { timeout: 10000 });
    const output = stdout + stderr;

    console.log(`[disconnect] radclient output:\n${output}`);

    if (output.includes('Disconnect-ACK')) {
      return { success: true,  code: 'ACK', nas: shortname, raw: output };
    } else if (output.includes('Disconnect-NAK')) {
      return { success: false, code: 'NAK', nas: shortname, raw: output };
    } else {
      return { success: false, code: 'NO_RESPONSE', nas: shortname, raw: output };
    }
  } catch (err) {
    console.error(`[disconnect] radclient error: ${err.message}`);
    return { success: false, code: 'ERROR', nas: shortname, raw: err.message };
  }
}

// ─────────────────────────────────────────────────────────────
// Helper: Format bytes to human readable
// ─────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

// ─────────────────────────────────────────────────────────────
// Helper: Format session for response
// ─────────────────────────────────────────────────────────────
function formatSession(s) {
  return {
    session_id:   s.acctsessionid,
    nas_ip:       s.nasipaddress,
    framed_ip:    s.framedipaddress,
    mac:          s.callingstationid,
    nas_port:     s.nasportid,
    nas_port_type:s.nasporttype,
    started_at:   s.acctstarttime,
    updated_at:   s.acctupdatetime,
    data_in:      formatBytes(s.acctinputoctets),
    data_out:     formatBytes(s.acctoutputoctets),
    data_in_raw:  s.acctinputoctets  || 0,
    data_out_raw: s.acctoutputoctets || 0,
  };
}

// ─────────────────────────────────────────────────────────────
// GET /api/sessions
// List ALL active sessions (paginated)
// ─────────────────────────────────────────────────────────────
async function listActiveSessions(req, res) {
  try {
    const limit  = Math.min(parseInt(req.query.limit)  || 100, 1000);
    const offset = parseInt(req.query.offset) || 0;

    const [rows] = await db.execute(
      `SELECT
         username,
         nasipaddress,
         acctsessionid,
         framedipaddress,
         acctstarttime,
         acctupdatetime,
         callingstationid,
         nasportid,
         nasporttype,
         acctinputoctets,
         acctoutputoctets
       FROM radacct
       WHERE acctstoptime IS NULL
       ORDER BY acctstarttime DESC
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    const [[{ total }]] = await db.execute(
      `SELECT COUNT(*) as total FROM radacct WHERE acctstoptime IS NULL`
    );

    return res.json({
      total,
      count:    rows.length,
      limit,
      offset,
      sessions: rows.map(formatSession).map((s, i) => ({
        username: rows[i].username,
        ...s
      }))
    });

  } catch (err) {
    console.error('[listActiveSessions] Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────
// GET /api/sessions/:username
// Get active session info for a specific user
// ─────────────────────────────────────────────────────────────
async function getSessionInfo(req, res) {
  try {
    const { username } = req.params;
    const session = await getActiveSession(username);

    if (!session) {
      return res.status(404).json({
        online:   false,
        username,
        message:  'No active session found'
      });
    }

    return res.json({
      online:   true,
      username,
      ...formatSession(session)
    });

  } catch (err) {
    console.error('[getSessionInfo] Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────
// POST /api/disconnect/:username
// Disconnect latest active session of a user
// ─────────────────────────────────────────────────────────────
async function disconnectUser(req, res) {
  try {
    const { username } = req.params;

    // Step 1: Get active session from radacct
    const session = await getActiveSession(username);
    if (!session) {
      return res.status(404).json({
        success:  false,
        username,
        error:    'No active session found'
      });
    }

    // Step 2: Fetch NAS secret from nas table + send Disconnect-Request
    let result;
    try {
      result = await sendDisconnectRequest(
        session.acctsessionid,
        username,
        session.nasipaddress
      );
    } catch (nasErr) {
      return res.status(422).json({
        success: false,
        username,
        error:   nasErr.message,
        tip:     'Make sure this NAS IP exists in the nas table'
      });
    }

    // Step 3: Return result
    // NAS will send Accounting-Stop → radacct auto-updates (no manual update needed)
    return res.status(result.success ? 200 : 502).json({
      success:    result.success,
      username,
      nas:        result.nas,
      code:       result.code,
      session_id: session.acctsessionid,
      nas_ip:     session.nasipaddress,
      framed_ip:  session.framedipaddress,
      mac:        session.callingstationid,
      message:    result.success
                    ? 'Session disconnected successfully'
                    : `Disconnect failed: ${result.code}`
    });

  } catch (err) {
    console.error('[disconnectUser] Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────
// POST /api/disconnect/:username/all
// Disconnect ALL active sessions of a user
// ─────────────────────────────────────────────────────────────
async function disconnectAllSessions(req, res) {
  try {
    const { username } = req.params;

    // Step 1: Get all active sessions
    const sessions = await getAllActiveSessions(username);
    if (!sessions.length) {
      return res.status(404).json({
        success:  false,
        username,
        error:    'No active sessions found'
      });
    }

    // Step 2: Send disconnect to each session concurrently
    const results = await Promise.all(
      sessions.map(async (s) => {
        try {
          const r = await sendDisconnectRequest(
            s.acctsessionid,
            username,
            s.nasipaddress
          );
          return {
            session_id: s.acctsessionid,
            nas_ip:     s.nasipaddress,
            nas:        r.nas,
            framed_ip:  s.framedipaddress,
            mac:        s.callingstationid,
            success:    r.success,
            code:       r.code
          };
        } catch (err) {
          return {
            session_id: s.acctsessionid,
            nas_ip:     s.nasipaddress,
            framed_ip:  s.framedipaddress,
            success:    false,
            code:       'NAS_NOT_FOUND',
            error:      err.message
          };
        }
      })
    );

    const successCount = results.filter(r => r.success).length;
    const failCount    = results.filter(r => !r.success).length;

    return res.status(200).json({
      username,
      total:         results.length,
      disconnected:  successCount,
      failed:        failCount,
      success:       successCount > 0,
      sessions:      results,
      message:       successCount === results.length
                       ? 'All sessions disconnected successfully'
                       : `${successCount}/${results.length} sessions disconnected`
    });

  } catch (err) {
    console.error('[disconnectAllSessions] Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────
// POST /api/disconnect/session/:sessionId
// Disconnect by exact session ID
// ─────────────────────────────────────────────────────────────
async function disconnectBySessionId(req, res) {
  try {
    const { sessionId } = req.params;

    // Lookup session in radacct
    const [rows] = await db.execute(
      `SELECT
         username,
         acctsessionid,
         nasipaddress,
         framedipaddress,
         callingstationid
       FROM radacct
       WHERE acctsessionid = ?
         AND acctstoptime IS NULL
       LIMIT 1`,
      [sessionId]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        error:   'Session not found or already stopped',
        sessionId
      });
    }

    const session = rows[0];

    let result;
    try {
      result = await sendDisconnectRequest(
        session.acctsessionid,
        session.username,
        session.nasipaddress
      );
    } catch (nasErr) {
      return res.status(422).json({
        success: false,
        error:   nasErr.message,
        tip:     'Make sure this NAS IP exists in the nas table'
      });
    }

    return res.status(result.success ? 200 : 502).json({
      success:    result.success,
      username:   session.username,
      nas:        result.nas,
      code:       result.code,
      session_id: session.acctsessionid,
      nas_ip:     session.nasipaddress,
      framed_ip:  session.framedipaddress,
      mac:        session.callingstationid,
      message:    result.success
                    ? 'Session disconnected successfully'
                    : `Disconnect failed: ${result.code}`
    });

  } catch (err) {
    console.error('[disconnectBySessionId] Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
}

// ─────────────────────────────────────────────────────────────
// GET /api/nas
// List all NAS devices from nas table
// ─────────────────────────────────────────────────────────────
async function listNasDevices(req, res) {
  try {
    const [rows] = await db.execute(
      `SELECT id, nasname, shortname, type, ports, community, description
       FROM nas
       ORDER BY id ASC`
    );
    // Note: secret is intentionally excluded from response
    return res.json({ total: rows.length, nas: rows });
  } catch (err) {
    console.error('[listNasDevices] Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
}

module.exports = {
  listActiveSessions,
  getSessionInfo,
  disconnectUser,
  disconnectAllSessions,
  disconnectBySessionId,
  listNasDevices
};