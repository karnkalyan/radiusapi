const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const SALT_ROUNDS = 10;

async function initApiUsers() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS api_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(64) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('admin','ops','support') DEFAULT 'support',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);

  const [[{ cnt }]] = await db.execute(`SELECT COUNT(*) as cnt FROM api_users`);
  if (cnt === 0) {
    const { MASTER_USER, MASTER_PASS } = process.env;
    const hash = await bcrypt.hash(MASTER_PASS, SALT_ROUNDS);
    await db.execute(
      `INSERT INTO api_users (username, password_hash, role) VALUES (?, ?, 'admin')`,
      [MASTER_USER, hash]
    );
    console.log('[+] Default API user created.');
  }
}

async function login(req, res) {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const [rows] = await db.execute(`SELECT * FROM api_users WHERE username = ?`, [username]);
  if (!rows.length) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const user = rows[0];
  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = jwt.sign(
    { sub: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_TTL || '1h' }
  );

  res.json({ token });
}

module.exports = { initApiUsers, login };
