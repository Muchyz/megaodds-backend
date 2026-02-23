// services/db.js
const { Pool } = require("pg");

let db;
try {
  db = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 5432,
    ssl: { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });

  db.connect((err, client, release) => {
    if (err) console.error("❌ DB Connection Error:", err.message);
    else {
      console.log("✅ Connected to PostgreSQL (Neon) Database");
      release();
    }
  });
} catch (error) {
  console.error("❌ DB Setup Error:", error.message);
}

module.exports = { db };