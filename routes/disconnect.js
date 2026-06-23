// routes/disconnect.js
const express = require('express');
const { verify } = require('../middleware/jwt');
const {
  listActiveSessions,
  getSessionInfo,
  disconnectUser,
  disconnectAllSessions,
  disconnectBySessionId,
  listNasDevices
} = require('../controllers/disconnectController');

const router = express.Router();

// ── NAS ──────────────────────────────────────────────────────
// GET  /api/nas                        → List all NAS devices
router.get('/nas-devices', verify, listNasDevices);

// ── Sessions ─────────────────────────────────────────────────
// GET  /api/sessions                   → List all active sessions
router.get('/sessions', verify, listActiveSessions);

// GET  /api/sessions/:username         → Get session info for user
router.get('/sessions/:username', verify, getSessionInfo);

// ── Disconnect ───────────────────────────────────────────────
// POST /api/disconnect/:username       → Disconnect latest session
router.post('/disconnect/:username', verify, disconnectUser);

// POST /api/disconnect/:username/all   → Disconnect ALL sessions
router.post('/disconnect/:username/all', verify, disconnectAllSessions);

// POST /api/disconnect/session/:sessionId → Disconnect by session ID
router.post('/disconnect/session/:sessionId', verify, disconnectBySessionId);

module.exports = router;