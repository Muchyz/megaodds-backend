// services/db.js
const mysql = require("mysql2");

let db;
try {
  db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    ssl: { rejectUnauthorized: false },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  db.getConnection((err, conn) => {
    if (err) console.error("❌ DB Connection Error:", err.message);
    else {
      console.log("✅ Connected to MySQL Database");
      conn.release();
    }
  });
} catch (error) {
  console.error("❌ DB Setup Error:", error.message);
}

module.exports = { db };
