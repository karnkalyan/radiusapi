const express = require('express');
const db = require('../config/db');
const { verify } = require('../middleware/jwt');

const router = express.Router();

const TABLES = {
  nas: 'id',
  nasreload: 'nasipaddress',
  radcheck: 'id',
  radreply: 'id',
  radgroupcheck: 'id',
  radgroupreply: 'id',
  radusergroup: 'id',
  radacct: 'RadAcctId',
  radpostauth: 'id',
  radippool: 'id',
};

// Custom POST for radcheck
router.post(`/radcheck`, verify, async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const keys = Object.keys(req.body);
  const vals = keys.map(k => req.body[k]);

  const q = `INSERT INTO radcheck (${keys.map(k => `\`${k}\``).join(',')})
             VALUES (${keys.map(_ => '?').join(',')})`;

  const [result] = await db.execute(q, vals);

  const [rows] = await db.execute(
    `SELECT * FROM radcheck WHERE id = ?`,
    [result.insertId]
  );

  res.status(201).json(rows[0]);
});


// Generic CRUD routes
for (const [table, pk] of Object.entries(TABLES)) {

  // GET ALL with limit + offset + latest first
  router.get(`/${table}`, verify, async (req, res) => {
    try {

      const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
      const offset = parseInt(req.query.offset) || 0;

      const [rows] = await db.query(
        `SELECT * FROM \`${table}\`
         ORDER BY \`${pk}\` DESC
         LIMIT ? OFFSET ?`,
        [limit, offset]
      );

      res.json(rows);

    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Database error' });
    }
  });


  // GET by ID
  router.get(`/${table}/:id`, verify, async (req, res) => {

    const [rows] = await db.execute(
      `SELECT * FROM \`${table}\` WHERE \`${pk}\` = ?`,
      [req.params.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'NotFound' });
    }

    res.json(rows[0]);
  });


  // POST (skip radcheck)
  if (table !== 'radcheck') {

    router.post(`/${table}`, verify, async (req, res) => {

      const keys = Object.keys(req.body);
      const vals = keys.map(k => req.body[k]);

      const q = `INSERT INTO \`${table}\`
                 (${keys.map(k => `\`${k}\``).join(',')})
                 VALUES (${keys.map(_ => '?').join(',')})`;

      const [result] = await db.execute(q, vals);

      const [rows] = await db.execute(
        `SELECT * FROM \`${table}\` WHERE \`${pk}\` = ?`,
        [result.insertId]
      );

      res.status(201).json(rows[0]);
    });

  }


  // UPDATE
  router.put(`/${table}/:id`, verify, async (req, res) => {

    const keys = Object.keys(req.body);
    const vals = keys.map(k => req.body[k]);

    const set = keys.map(k => `\`${k}\` = ?`).join(', ');

    await db.execute(
      `UPDATE \`${table}\`
       SET ${set}
       WHERE \`${pk}\` = ?`,
      [...vals, req.params.id]
    );

    const [rows] = await db.execute(
      `SELECT * FROM \`${table}\` WHERE \`${pk}\` = ?`,
      [req.params.id]
    );

    res.json(rows[0]);
  });


  // DELETE
  router.delete(`/${table}/:id`, verify, async (req, res) => {

    const [result] = await db.execute(
      `DELETE FROM \`${table}\` WHERE \`${pk}\` = ?`,
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'NotFound' });
    }

    res.status(204).end();
  });

}


// Custom GET by username
router.get('/radcheck/username/:username', verify, async (req, res) => {

  const [rows] = await db.execute(
    `SELECT * FROM radcheck
     WHERE username = ?
     ORDER BY id DESC`,
    [req.params.username]
  );

  if (!rows.length) {
    return res.status(404).json({ error: 'NotFound' });
  }

  res.json(rows);

});

module.exports = router;