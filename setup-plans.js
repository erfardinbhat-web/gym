// One-time script: adds the plans and payments tables.
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
    CREATE TABLE IF NOT EXISTS plans (
      id INT AUTO_INCREMENT PRIMARY KEY,
      gym_id INT NOT NULL,
      name VARCHAR(100) NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      duration_months INT NOT NULL DEFAULT 1,
      payment_link VARCHAR(500),
      qr_url TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_plans_gym (gym_id),
      FOREIGN KEY (gym_id) REFERENCES gyms(id) ON DELETE CASCADE
    )
  `);

  await conn.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      gym_id INT NOT NULL,
      member_id INT NOT NULL,
      plan_id INT NULL,
      plan_name VARCHAR(100) NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      paid_on DATE NOT NULL,
      valid_until DATE NOT NULL,
      note VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_pay_member (member_id),
      INDEX idx_pay_gym (gym_id),
      FOREIGN KEY (gym_id) REFERENCES gyms(id) ON DELETE CASCADE,
      FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE,
      FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE SET NULL
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