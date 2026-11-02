const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: 'v7qas8.h.filess.io',
  port: 3306,
  user: 'gymdb_shelterbus',
  password: 'a0d7312e83a0ee9b1abc2d044094f9e3a1c8b3db',
  database: 'gymdb_shelterbus',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  timezone: '+00:00',
});

module.exports = pool;