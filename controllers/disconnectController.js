// controllers/disconnectController.js
const db = require('../config/db');
const { spawn } = require('child_process');
require('dotenv').config();

function runRadclient(nasIp, coaPort, secret, payload) {
  return new Promise((resolve) => {
    const child = spawn('radclient', [
      '-x',
      `${nasIp}:${coaPort}`,
      'disconnect',
      secret
    ]);

    let output = '';

    child.stdout.on('data', data => output += data.toString());
    child.stderr.on('data', data => output += data.toString());

    child.on('error', err => {
      resolve({ success: false, code: 'ERROR', raw: err.message });
    });

    child.on('close', () => {
      if (output.includes('Disconnect-ACK')) {
        resolve({ success: true, code: 'ACK', raw: output });
      } else if (output.includes('Disconnect-NAK')) {
        resolve({ success: false, code: 'NAK', raw: output });
      } else {
        resolve({ success: false, code: 'NO_RESPONSE', raw: output });
      }
    });

    child.stdin.write(payload);
    child.stdin.end();
  });
}

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
    secret: rows[0].secret,
    shortname: rows[0].shortname,
    authPort: rows[0].ports || 1812,
    coaPort: parseInt(process.env.NAS_COA_PORT || '3799', 10)
  };
}

async function getActiveSession(username) {
  const [rows] = await db.execute(
    `SELECT
       username,
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

async function getAllActiveSessions(username) {
  const [rows] = await db.execute(
    `SELECT
       username,
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

async function sendDisconnectRequest(session) {
  const { secret, coaPort, shortname } = await getNasSecret(session.nasipaddress);

  const payload = [
    `User-Name = "${session.username}"`,
    `Acct-Session-Id = "${session.acctsessionid}"`,
    `Framed-IP-Address = ${session.framedipaddress}`,
    `NAS-IP-Address = ${session.nasipaddress}`
  ].join('\n') + '\n';

  console.log(`[disconnect] NAS ${shortname} ${session.nasipaddress}:${coaPort}`);
  console.log(`[disconnect] Session ${session.acctsessionid}`);

  const result = await runRadclient(
    session.nasipaddress,
    coaPort,
    secret,
    payload
  );

  return {
    ...result,
    nas: shortname,
    nas_ip: session.nasipaddress,
    framed_ip: session.framedipaddress,
    session_id: session.acctsessionid
  };
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';

  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));

  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

function formatSession(s) {
  return {
    username: s.username,
    session_id: s.acctsessionid,
    nas_ip: s.nasipaddress,
    framed_ip: s.framedipaddress,
    mac: s.callingstationid,
    nas_port: s.nasportid,
    nas_port_type: s.nasporttype,
    started_at: s.acctstarttime,
    updated_at: s.acctupdatetime,
    data_in: formatBytes(s.acctinputoctets),
    data_out: formatBytes(s.acctoutputoctets),
    data_in_raw: s.acctinputoctets || 0,
    data_out_raw: s.acctoutputoctets || 0
  };
}

async function listActiveSessions(req, res) {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
    const offset = parseInt(req.query.offset, 10) || 0;

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
      `SELECT COUNT(*) AS total
       FROM radacct
       WHERE acctstoptime IS NULL`
    );

    return res.json({
      success: true,
      total,
      count: rows.length,
      limit,
      offset,
      sessions: rows.map(formatSession)
    });
  } catch (err) {
    console.error('[listActiveSessions] Error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
}

async function getSessionInfo(req, res) {
  try {
    const { username } = req.params;
    const session = await getActiveSession(username);

    if (!session) {
      return res.status(404).json({
        success: false,
        online: false,
        username,
        message: 'No active session found'
      });
    }

    return res.json({
      success: true,
      online: true,
      ...formatSession(session)
    });
  } catch (err) {
    console.error('[getSessionInfo] Error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
}

async function disconnectUser(req, res) {
  try {
    const { username } = req.params;
    const session = await getActiveSession(username);

    if (!session) {
      return res.status(404).json({
        success: false,
        username,
        error: 'No active session found'
      });
    }

    const result = await sendDisconnectRequest(session);

    return res.status(result.success ? 200 : 502).json({
      success: result.success,
      username,
      nas: result.nas,
      code: result.code,
      session_id: session.acctsessionid,
      nas_ip: session.nasipaddress,
      framed_ip: session.framedipaddress,
      mac: session.callingstationid,
      message: result.success
        ? 'Session disconnected successfully'
        : `Disconnect failed: ${result.code}`,
      raw: result.raw
    });
  } catch (err) {
    console.error('[disconnectUser] Error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
}

async function disconnectAllSessions(req, res) {
  try {
    const { username } = req.params;
    const sessions = await getAllActiveSessions(username);

    if (!sessions.length) {
      return res.status(404).json({
        success: false,
        username,
        error: 'No active sessions found'
      });
    }

    const results = await Promise.all(
      sessions.map(async session => {
        try {
          const result = await sendDisconnectRequest(session);

          return {
            success: result.success,
            code: result.code,
            session_id: session.acctsessionid,
            nas_ip: session.nasipaddress,
            framed_ip: session.framedipaddress,
            mac: session.callingstationid,
            nas: result.nas,
            raw: result.raw
          };
        } catch (err) {
          return {
            success: false,
            code: 'ERROR',
            session_id: session.acctsessionid,
            nas_ip: session.nasipaddress,
            framed_ip: session.framedipaddress,
            error: err.message
          };
        }
      })
    );

    const disconnected = results.filter(r => r.success).length;
    const failed = results.length - disconnected;

    return res.json({
      success: disconnected > 0,
      username,
      total: results.length,
      disconnected,
      failed,
      sessions: results
    });
  } catch (err) {
    console.error('[disconnectAllSessions] Error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
}

async function disconnectBySessionId(req, res) {
  try {
    const { sessionId } = req.params;

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
        error: 'Session not found or already stopped',
        sessionId
      });
    }

    const session = rows[0];
    const result = await sendDisconnectRequest(session);

    return res.status(result.success ? 200 : 502).json({
      success: result.success,
      username: session.username,
      nas: result.nas,
      code: result.code,
      session_id: session.acctsessionid,
      nas_ip: session.nasipaddress,
      framed_ip: session.framedipaddress,
      mac: session.callingstationid,
      message: result.success
        ? 'Session disconnected successfully'
        : `Disconnect failed: ${result.code}`,
      raw: result.raw
    });
  } catch (err) {
    console.error('[disconnectBySessionId] Error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
}

async function listNasDevices(req, res) {
  try {
    const [rows] = await db.execute(
      `SELECT id, nasname, shortname, type, ports, community, description
       FROM nas
       ORDER BY id ASC`
    );

    return res.json({
      success: true,
      total: rows.length,
      nas: rows
    });
  } catch (err) {
    console.error('[listNasDevices] Error:', err);
    return res.status(500).json({ success: false, error: err.message });
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