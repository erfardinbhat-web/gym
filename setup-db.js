// One-time script: creates the tables on the Aiven MySQL database.
// Run from the gym-api folder with DATABASE_URL set to the Aiven Service URI.
const mysql = require('mysql2/promise');

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('Set DATABASE_URL first (Aiven Service URI).');
    process.exit(1);
  }

  const conn = await mysql.createConnection({
    uri: url,
    ssl: { rejectUnauthorized: false },
  });

  await conn.query(`
    CREATE TABLE IF NOT EXISTS gyms (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(190) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await conn.query(`
    CREATE TABLE IF NOT EXISTS members (
      id INT AUTO_INCREMENT PRIMARY KEY,
      gym_id INT NOT NULL,
      member_code VARCHAR(20) NOT NULL,
      name VARCHAR(150) NOT NULL,
      parentage VARCHAR(150) NOT NULL,
      address VARCHAR(255) NOT NULL,
      phone VARCHAR(20) NOT NULL,
      gender VARCHAR(20) NOT NULL,
      joined_on DATE NOT NULL,
      photo_url TEXT,
      aadhaar_url TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_gym_phone (gym_id, phone),
      INDEX idx_gym (gym_id),
      FOREIGN KEY (gym_id) REFERENCES gyms(id) ON DELETE CASCADE
    )
  `);

  const [tables] = await conn.query('SHOW TABLES');
  console.log('Tables now in database:', tables);
  await conn.end();
}

main().catch((e) => {
  console.error('Failed:', e.message);
  process.exit(1);
});