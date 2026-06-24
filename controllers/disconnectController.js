// controllers/disconnectController.js
const db = require('../config/db');
const { spawn, execFile } = require('child_process');
require('dotenv').config();

const LOG_PREFIX = '[RADIUS-DISCONNECT]';

function nowIso() {
  return new Date().toISOString();
}

function maskSecret(secret) {
  if (!secret) return null;
  const s = String(secret);
  if (s.length <= 4) return '*'.repeat(s.length);
  return `${s.slice(0, 2)}${'*'.repeat(Math.max(0, s.length - 4))}${s.slice(-2)}`;
}

function logInfo(message, data = null) {
  if (data !== null) {
    console.log(`${nowIso()} ${LOG_PREFIX} ${message}`, data);
  } else {
    console.log(`${nowIso()} ${LOG_PREFIX} ${message}`);
  }
}

function logError(message, errOrData = null) {
  if (errOrData !== null) {
    console.error(`${nowIso()} ${LOG_PREFIX} ${message}`, errOrData);
  } else {
    console.error(`${nowIso()} ${LOG_PREFIX} ${message}`);
  }
}

function checkRadclientBinary() {
  return new Promise((resolve) => {
    execFile('which', ['radclient'], (err, stdout, stderr) => {
      if (err) {
        return resolve({
          found: false,
          path: null,
          error: stderr || err.message
        });
      }

      resolve({
        found: true,
        path: stdout.trim(),
        error: null
      });
    });
  });
}

function runRadclient(nasIp, coaPort, secret, payload) {
  return new Promise(async (resolve) => {
    const startedAt = Date.now();

    logInfo('Preparing radclient disconnect request', {
      nasIp,
      coaPort,
      secretLength: secret ? String(secret).length : 0,
      secretMasked: maskSecret(secret),
      payload
    });

    const binaryCheck = await checkRadclientBinary();
    logInfo('radclient binary check', binaryCheck);

    const args = [
      '-x',
      `${nasIp}:${coaPort}`,
      'disconnect',
      secret
    ];

    logInfo('Starting radclient process', {
      command: 'radclient',
      args: [
        '-x',
        `${nasIp}:${coaPort}`,
        'disconnect',
        maskSecret(secret)
      ]
    });

    const child = spawn('radclient', args);

    let stdout = '';
    let stderr = '';
    let resolved = false;

    const timeoutMs = parseInt(process.env.RADCLIENT_TIMEOUT_MS || '15000', 10);

    const timeout = setTimeout(() => {
      if (resolved) return;

      resolved = true;

      logError('radclient timeout reached, killing process', {
        timeoutMs,
        nasIp,
        coaPort
      });

      try {
        child.kill('SIGKILL');
      } catch (killErr) {
        logError('Failed to kill radclient after timeout', killErr.message);
      }

      resolve({
        success: false,
        code: 'TIMEOUT',
        raw: stdout + stderr,
        stdout,
        stderr,
        exitCode: null,
        signal: 'SIGKILL',
        durationMs: Date.now() - startedAt
      });
    }, timeoutMs);

    child.stdout.on('data', (data) => {
      const text = data.toString();
      stdout += text;
      logInfo('radclient stdout chunk', text);
    });

    child.stderr.on('data', (data) => {
      const text = data.toString();
      stderr += text;
      logError('radclient stderr chunk', text);
    });

    child.on('error', (err) => {
      if (resolved) return;

      resolved = true;
      clearTimeout(timeout);

      logError('radclient spawn error', {
        message: err.message,
        code: err.code,
        errno: err.errno,
        syscall: err.syscall,
        path: err.path,
        spawnargs: err.spawnargs
      });

      resolve({
        success: false,
        code: 'ERROR',
        raw: err.message,
        stdout,
        stderr,
        spawnError: {
          message: err.message,
          code: err.code,
          errno: err.errno,
          syscall: err.syscall,
          path: err.path
        },
        exitCode: null,
        signal: null,
        durationMs: Date.now() - startedAt
      });
    });

    child.on('close', (exitCode, signal) => {
      if (resolved) return;

      resolved = true;
      clearTimeout(timeout);

      const output = stdout + stderr;
      const durationMs = Date.now() - startedAt;

      logInfo('radclient process closed', {
        exitCode,
        signal,
        durationMs,
        stdout,
        stderr,
        output
      });

      if (output.includes('Disconnect-ACK')) {
        return resolve({
          success: true,
          code: 'ACK',
          raw: output,
          stdout,
          stderr,
          exitCode,
          signal,
          durationMs
        });
      }

      if (output.includes('Disconnect-NAK')) {
        return resolve({
          success: false,
          code: 'NAK',
          raw: output,
          stdout,
          stderr,
          exitCode,
          signal,
          durationMs
        });
      }

      if (exitCode !== 0) {
        return resolve({
          success: false,
          code: 'ERROR',
          raw: output || `radclient exited with code ${exitCode}`,
          stdout,
          stderr,
          exitCode,
          signal,
          durationMs
        });
      }

      return resolve({
        success: false,
        code: 'NO_RESPONSE',
        raw: output,
        stdout,
        stderr,
        exitCode,
        signal,
        durationMs
      });
    });

    child.stdin.on('error', (err) => {
      logError('radclient stdin error', err.message);
    });

    logInfo('Writing payload to radclient stdin');
    child.stdin.write(payload);
    child.stdin.end();
  });
}

async function getNasSecret(nasIp) {
  logInfo('Looking up NAS secret from DB', { nasIp });

  const [rows] = await db.execute(
    `SELECT nasname, shortname, secret, ports
     FROM nas
     WHERE nasname = ?
     LIMIT 1`,
    [nasIp]
  );

  logInfo('NAS DB lookup result', {
    nasIp,
    found: rows.length > 0,
    count: rows.length,
    nas: rows.length
      ? {
          nasname: rows[0].nasname,
          shortname: rows[0].shortname,
          ports: rows[0].ports,
          secretLength: rows[0].secret ? String(rows[0].secret).length : 0,
          secretMasked: maskSecret(rows[0].secret)
        }
      : null
  });

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
  logInfo('Looking up latest active session by username', { username });

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

  logInfo('Active session lookup result', {
    username,
    found: rows.length > 0,
    session: rows[0] || null
  });

  return rows[0] || null;
}

async function getAllActiveSessions(username) {
  logInfo('Looking up all active sessions by username', { username });

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

  logInfo('All active sessions lookup result', {
    username,
    count: rows.length,
    sessions: rows.map((s) => ({
      username: s.username,
      acctsessionid: s.acctsessionid,
      nasipaddress: s.nasipaddress,
      framedipaddress: s.framedipaddress,
      callingstationid: s.callingstationid,
      acctstarttime: s.acctstarttime,
      acctupdatetime: s.acctupdatetime
    }))
  });

  return rows;
}

async function sendDisconnectRequest(session) {
  logInfo('sendDisconnectRequest started', {
    session
  });

  if (!session) {
    throw new Error('Session is required');
  }

  if (!session.username) {
    throw new Error('Session username is missing');
  }

  if (!session.acctsessionid) {
    throw new Error('Session acctsessionid is missing');
  }

  if (!session.nasipaddress) {
    throw new Error('Session nasipaddress is missing');
  }

  if (!session.framedipaddress) {
    throw new Error('Session framedipaddress is missing');
  }

  const { secret, coaPort, shortname } = await getNasSecret(session.nasipaddress);

  const payload = [
    `User-Name = "${session.username}"`,
    `Acct-Session-Id = "${session.acctsessionid}"`,
    `Framed-IP-Address = ${session.framedipaddress}`,
    `NAS-IP-Address = ${session.nasipaddress}`
  ].join('\n') + '\n';

  logInfo('Disconnect payload built', {
    nas: shortname,
    nasIp: session.nasipaddress,
    coaPort,
    sessionId: session.acctsessionid,
    framedIp: session.framedipaddress,
    username: session.username,
    payload
  });

  const result = await runRadclient(
    session.nasipaddress,
    coaPort,
    secret,
    payload
  );

  const finalResult = {
    ...result,
    nas: shortname,
    nas_ip: session.nasipaddress,
    framed_ip: session.framedipaddress,
    session_id: session.acctsessionid
  };

  logInfo('sendDisconnectRequest completed', {
    success: finalResult.success,
    code: finalResult.code,
    nas: finalResult.nas,
    nas_ip: finalResult.nas_ip,
    framed_ip: finalResult.framed_ip,
    session_id: finalResult.session_id,
    exitCode: finalResult.exitCode,
    signal: finalResult.signal,
    durationMs: finalResult.durationMs,
    raw: finalResult.raw
  });

  return finalResult;
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
    logInfo('GET /api/sessions request', {
      query: req.query,
      user: req.user ? { id: req.user.id, username: req.user.username, email: req.user.email } : null
    });

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

    logInfo('GET /api/sessions response prepared', {
      total,
      count: rows.length,
      limit,
      offset
    });

    return res.json({
      success: true,
      total,
      count: rows.length,
      limit,
      offset,
      sessions: rows.map(formatSession)
    });
  } catch (err) {
    logError('[listActiveSessions] Error', {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
}

async function getSessionInfo(req, res) {
  try {
    const { username } = req.params;

    logInfo('GET /api/sessions/:username request', {
      username,
      user: req.user ? { id: req.user.id, username: req.user.username, email: req.user.email } : null
    });

    const session = await getActiveSession(username);

    if (!session) {
      logInfo('No active session found for username', { username });

      return res.status(404).json({
        success: false,
        online: false,
        username,
        message: 'No active session found'
      });
    }

    logInfo('Active session found for username', {
      username,
      session
    });

    return res.json({
      success: true,
      online: true,
      ...formatSession(session)
    });
  } catch (err) {
    logError('[getSessionInfo] Error', {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
}

async function disconnectUser(req, res) {
  try {
    const { username } = req.params;

    logInfo('POST /api/disconnect/:username request', {
      username,
      user: req.user ? { id: req.user.id, username: req.user.username, email: req.user.email } : null
    });

    const session = await getActiveSession(username);

    if (!session) {
      logInfo('Disconnect failed because no active session exists', { username });

      return res.status(404).json({
        success: false,
        username,
        error: 'No active session found'
      });
    }

    logInfo('Disconnecting latest active session', {
      username,
      session
    });

    const result = await sendDisconnectRequest(session);

    const responseBody = {
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
      raw: result.raw,
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode,
      signal: result.signal,
      durationMs: result.durationMs,
      spawnError: result.spawnError || null
    };

    logInfo('POST /api/disconnect/:username response', responseBody);

    return res.status(result.success ? 200 : 502).json(responseBody);
  } catch (err) {
    logError('[disconnectUser] Error', {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
}

async function disconnectAllSessions(req, res) {
  try {
    const { username } = req.params;

    logInfo('POST /api/disconnect/:username/all request', {
      username,
      user: req.user ? { id: req.user.id, username: req.user.username, email: req.user.email } : null
    });

    const sessions = await getAllActiveSessions(username);

    if (!sessions.length) {
      logInfo('Disconnect all failed because no active sessions exist', { username });

      return res.status(404).json({
        success: false,
        username,
        error: 'No active sessions found'
      });
    }

    logInfo('Disconnecting all active sessions', {
      username,
      count: sessions.length,
      sessions
    });

    const results = await Promise.all(
      sessions.map(async (session) => {
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
            raw: result.raw,
            stdout: result.stdout,
            stderr: result.stderr,
            exitCode: result.exitCode,
            signal: result.signal,
            durationMs: result.durationMs,
            spawnError: result.spawnError || null
          };
        } catch (err) {
          logError('Error disconnecting one session in disconnectAllSessions', {
            session,
            message: err.message,
            stack: err.stack
          });

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

    const disconnected = results.filter((r) => r.success).length;
    const failed = results.length - disconnected;

    const responseBody = {
      success: disconnected > 0,
      username,
      total: results.length,
      disconnected,
      failed,
      sessions: results
    };

    logInfo('POST /api/disconnect/:username/all response', responseBody);

    return res.json(responseBody);
  } catch (err) {
    logError('[disconnectAllSessions] Error', {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
}

async function disconnectBySessionId(req, res) {
  try {
    const { sessionId } = req.params;

    logInfo('POST /api/disconnect/session/:sessionId request', {
      sessionId,
      user: req.user ? { id: req.user.id, username: req.user.username, email: req.user.email } : null
    });

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

    logInfo('Session ID DB lookup result', {
      sessionId,
      found: rows.length > 0,
      count: rows.length,
      session: rows[0] || null
    });

    if (!rows.length) {
      logInfo('Disconnect by session ID failed: session not active or not found', {
        sessionId
      });

      return res.status(404).json({
        success: false,
        error: 'Session not found or already stopped',
        sessionId
      });
    }

    const session = rows[0];

    logInfo('Disconnecting exact session', {
      session
    });

    const result = await sendDisconnectRequest(session);

    const responseBody = {
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
      raw: result.raw,
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode,
      signal: result.signal,
      durationMs: result.durationMs,
      spawnError: result.spawnError || null
    };

    logInfo('POST /api/disconnect/session/:sessionId response', responseBody);

    return res.status(result.success ? 200 : 502).json(responseBody);
  } catch (err) {
    logError('[disconnectBySessionId] Error', {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
}

async function listNasDevices(req, res) {
  try {
    logInfo('GET /api/nas-devices request', {
      user: req.user ? { id: req.user.id, username: req.user.username, email: req.user.email } : null
    });

    const [rows] = await db.execute(
      `SELECT id, nasname, shortname, type, ports, community, description
       FROM nas
       ORDER BY id ASC`
    );

    logInfo('GET /api/nas-devices response prepared', {
      total: rows.length
    });

    return res.json({
      success: true,
      total: rows.length,
      nas: rows
    });
  } catch (err) {
    logError('[listNasDevices] Error', {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({
      success: false,
      error: err.message
    });
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