// routes/auth.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = (db) => {
  const router = express.Router();

  router.post("/register", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required" });

    try {
      const hash = await bcrypt.hash(password, 10);
      db.query(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        [email, hash],
        (err) => {
          if (err) {
            if (err.code === "ER_DUP_ENTRY")
              return res.status(409).json({ message: "User already exists" });
            return res.status(500).json({ message: "Database error" });
          }
          res.json({ message: "Registered successfully" });
        }
      );
    } catch {
      res.status(500).json({ message: "Server error" });
    }
  });

  router.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required" });

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, rows) => {
      if (err) return res.status(500).json({ message: "Server error" });
      if (!rows.length) return res.status(401).json({ message: "Invalid credentials" });

      const user = rows[0];
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ message: "Invalid credentials" });

      const token = jwt.sign(
        { id: user.id, email: user.email, is_vip: user.is_vip, is_admin: user.is_admin },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );
      res.json({ token, is_vip: user.is_vip, is_admin: user.is_admin });
    });
  });

  return router;
};
