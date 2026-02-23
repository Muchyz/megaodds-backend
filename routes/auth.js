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
      await db.query(
        "INSERT INTO users (email, password) VALUES ($1, $2)",
        [email, hash]
      );
      res.json({ message: "Registered successfully" });
    } catch (err) {
      if (err.code === "23505")
        return res.status(409).json({ message: "User already exists" });
      res.status(500).json({ message: "Server error" });
    }
  });

  router.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required" });

    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
      if (!result.rows.length)
        return res.status(401).json({ message: "Invalid credentials" });

      const user = result.rows[0];
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ message: "Invalid credentials" });

      const token = jwt.sign(
        { id: user.id, email: user.email, is_vip: user.is_vip, is_admin: user.is_admin },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );
      res.json({ token, is_vip: user.is_vip, is_admin: user.is_admin });
    } catch (err) {
      res.status(500).json({ message: "Server error" });
    }
  });

  return router;
};
