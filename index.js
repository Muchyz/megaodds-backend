const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

/* =======================
   MIDDLEWARE
======================= */
app.use(
  cors({
    origin: "https://megaodds.vercel.app",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// 🔑 IMPORTANT: handle preflight requests
app.options("*", cors());

app.use(express.json());

/* =======================
   CLOUDINARY CONFIG
======================= */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "vip-features",
    allowed_formats: ["jpg", "png", "jpeg", "webp"],
  },
});

const upload = multer({ storage });

/* =======================
   DATABASE
======================= */
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
});

db.getConnection((err, conn) => {
  if (err) {
    console.error("❌ DB error:", err.message);
  } else {
    console.log("✅ Connected to Railway MySQL");
    conn.release();
  }
});

/* =======================
   JWT
======================= */
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(auth.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

const isAdmin = (req, res, next) => {
  if (!req.user.is_admin)
    return res.status(403).json({ message: "Admin only" });
  next();
};

/* =======================
   AUTH
======================= */
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users (email, password) VALUES (?,?)",
      [email, hash],
      (err) => {
        if (err) {
          console.error("Register error:", err);
          return res.status(409).json({ message: "User exists" });
        }
        res.json({ message: "Registered" });
      }
    );
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email=?",
    [email],
    async (err, rows) => {
      if (err) {
        console.error("Login DB error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (!rows.length) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const user = rows[0];
      const ok = await bcrypt.compare(password, user.password);

      if (!ok) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const token = jwt.sign(
        {
          id: user.id,
          is_vip: user.is_vip,
          is_admin: user.is_admin,
        },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      res.json({ token, is_vip: user.is_vip });
    }
  );
});

/* =======================
   FEATURES
======================= */

// GET (VIP)
app.get("/features", verifyToken, (req, res) => {
  if (!req.user.is_vip)
    return res.status(403).json({ message: "VIP only" });

  db.query("SELECT * FROM features ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ message: "DB error" });
    res.json(rows);
  });
});

// CREATE (ADMIN)
app.post(
  "/features",
  verifyToken,
  isAdmin,
  upload.single("image"),
  (req, res) => {
    const { title, description } = req.body;
    const image_url = req.file?.path || null;

    db.query(
      "INSERT INTO features (title, description, image_url) VALUES (?,?,?)",
      [title, description, image_url],
      (err) => {
        if (err) return res.status(500).json({ message: "Create failed" });
        res.json({ message: "Feature added" });
      }
    );
  }
);

// UPDATE
app.put(
  "/features/:id",
  verifyToken,
  isAdmin,
  upload.single("image"),
  (req, res) => {
    const { title, description } = req.body;
    const image_url = req.file?.path;

    const sql = image_url
      ? "UPDATE features SET title=?, description=?, image_url=? WHERE id=?"
      : "UPDATE features SET title=?, description=? WHERE id=?";

    const values = image_url
      ? [title, description, image_url, req.params.id]
      : [title, description, req.params.id];

    db.query(sql, values, (err) => {
      if (err) return res.status(500).json({ message: "Update failed" });
      res.json({ message: "Feature updated" });
    });
  }
);

// DELETE
app.delete("/features/:id", verifyToken, isAdmin, (req, res) => {
  db.query("DELETE FROM features WHERE id=?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: "Delete failed" });
    res.json({ message: "Feature deleted" });
  });
});

/* =======================
   HEALTH
======================= */
app.get("/", (_, res) => res.send("🚀 API running"));

/* =======================
   START
======================= */
app.listen(PORT, () => {
  console.log(`🔥 Server running on port ${PORT}`);
});