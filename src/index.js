const express = require('express');
const cors = require('cors');
const pool = require('./db');
const routes = require('./routes');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use('/api', routes);

app.get('/ping', (req, res) => {
  res.json({ ok: true, service: 'gym-api', time: new Date().toISOString() });
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS gyms (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS members (
        id INT AUTO_INCREMENT PRIMARY KEY,
        gym_id INT NOT NULL,
        member_code VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        parentage VARCHAR(255) NOT NULL,
        address TEXT NOT NULL,
        phone VARCHAR(20) NOT NULL,
        gender VARCHAR(10) DEFAULT 'Male',
        joined_on DATE NOT NULL,
        photo_url TEXT,
        aadhaar_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (gym_id) REFERENCES gyms(id) ON DELETE CASCADE
      )
    `);

    console.log('Database tables ready');
  } catch (e) {
    console.error('DB init error:', e.message);
  }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`Gym API running on port ${PORT}`);
  await initDB();
});
