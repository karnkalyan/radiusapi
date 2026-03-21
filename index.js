const express = require('express');
require('dotenv').config();

const { initApiUsers, login } = require('./controllers/apiController');
const apiRoutes = require('./routes/apiRoutes');

const app = express();
app.use(express.json());

app.post('/login', login);
app.use('/api', apiRoutes);

app.get('/health', (_, res) => res.json({ status: 'ok' }));

initApiUsers().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`🔥 API ready at http://localhost:${port}`));
});
