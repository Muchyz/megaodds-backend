#!/bin/bash
# ============================================
# MEGA-ODDS BACKEND SETUP SCRIPT
# Run this in your backend project folder
# Usage: bash setup.sh
# ============================================

set -e  # Stop on any error

echo "🚀 Setting up Mega-Odds modular backend..."
echo ""

# ── Create folder structure ──────────────────
mkdir -p middleware services routes
echo "✅ Folders created: middleware/ services/ routes/"

# ══════════════════════════════════════════════
# MIDDLEWARE/AUTH.JS
# ══════════════════════════════════════════════
cat > middleware/auth.js << 'EOF'
// middleware/auth.js
const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "No token provided" });
  try {
    req.user = jwt.verify(auth.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

const isAdmin = (req, res, next) => {
  if (Number(req.user.is_admin) !== 1)
    return res.status(403).json({ message: "Admin only" });
  next();
};

module.exports = { verifyToken, isAdmin };
EOF
echo "✅ middleware/auth.js"

# ══════════════════════════════════════════════
# SERVICES/DB.JS
# ══════════════════════════════════════════════
cat > services/db.js << 'EOF'
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
EOF
echo "✅ services/db.js"

# ══════════════════════════════════════════════
# SERVICES/INTASEND.JS
# ══════════════════════════════════════════════
cat > services/intasend.js << 'EOF'
// services/intasend.js
const IntaSend = require("intasend-node");

let intasend;
try {
  intasend = new IntaSend(
    process.env.INTASEND_PUBLISHABLE_KEY,
    process.env.INTASEND_SECRET_KEY,
    false // false = LIVE production mode
  );
  console.log("✅ Intasend SDK initialized (LIVE mode)");
} catch (err) {
  console.error("❌ Intasend SDK init error:", err.message);
}

module.exports = { intasend };
EOF
echo "✅ services/intasend.js"

# ══════════════════════════════════════════════
# SERVICES/CLOUDINARY.JS
# ══════════════════════════════════════════════
cat > services/cloudinary.js << 'EOF'
// services/cloudinary.js
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");

let upload;

if (process.env.CLOUDINARY_CLOUD_NAME) {
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

  upload = multer({ storage });
  console.log("✅ Cloudinary configured");
} else {
  console.log("⚠️  Cloudinary not configured");
  upload = multer({ dest: "uploads/" });
}

module.exports = { cloudinary, upload };
EOF
echo "✅ services/cloudinary.js"

# ══════════════════════════════════════════════
# ROUTES/AUTH.JS
# ══════════════════════════════════════════════
cat > routes/auth.js << 'EOF'
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
EOF
echo "✅ routes/auth.js"

# ══════════════════════════════════════════════
# ROUTES/PICKS.JS
# ══════════════════════════════════════════════
cat > routes/picks.js << 'EOF'
// routes/picks.js
const express = require("express");
const { verifyToken, isAdmin } = require("../middleware/auth");

module.exports = (db) => {
  const router = express.Router();

  // Public: yesterday's picks
  router.get("/yesterday", (_req, res) => {
    db.query(
      "SELECT * FROM picks WHERE pick_type = 'yesterday' ORDER BY created_at DESC",
      (err, rows) => {
        if (err) return res.status(500).json({ message: "DB error" });
        res.json(rows);
      }
    );
  });

  // Public: today's picks
  router.get("/today", (_req, res) => {
    db.query(
      "SELECT * FROM picks WHERE pick_type = 'today' ORDER BY created_at DESC",
      (err, rows) => {
        if (err) return res.status(500).json({ message: "DB error" });
        res.json(rows);
      }
    );
  });

  // Public: single pick
  router.get("/:id", (req, res) => {
    db.query("SELECT * FROM picks WHERE id = ?", [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ message: "DB error" });
      if (!rows.length) return res.status(404).json({ message: "Pick not found" });
      res.json(rows[0]);
    });
  });

  // Admin: create pick
  router.post("/", verifyToken, isAdmin, (req, res) => {
    const { team1, team2, time, prediction, odds, status, isVIP, pickType } = req.body;

    if (!team1 || !team2 || !time || !pickType)
      return res.status(400).json({ message: "Missing required fields: team1, team2, time, pickType" });

    const finalPrediction = isVIP ? "Locked" : (prediction || "");
    const finalOdds       = isVIP ? "--"      : (odds       || "");

    db.query(
      "INSERT INTO picks (team1, team2, time, prediction, odds, status, is_vip, pick_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [team1, team2, time, finalPrediction, finalOdds, status || "Pending", isVIP ? 1 : 0, pickType],
      (err, result) => {
        if (err) return res.status(500).json({ message: "Failed to create pick" });
        res.status(201).json({ message: "Pick created successfully", id: result.insertId });
      }
    );
  });

  // Admin: update pick
  router.put("/:id", verifyToken, isAdmin, (req, res) => {
    const { team1, team2, time, prediction, odds, status, isVIP } = req.body;

    const finalPrediction = isVIP ? "Locked" : (prediction || "");
    const finalOdds       = isVIP ? "--"      : (odds       || "");

    db.query(
      "UPDATE picks SET team1=?, team2=?, time=?, prediction=?, odds=?, status=?, is_vip=? WHERE id=?",
      [team1, team2, time, finalPrediction, finalOdds, status, isVIP ? 1 : 0, req.params.id],
      (err, result) => {
        if (err) return res.status(500).json({ message: "Failed to update pick" });
        if (result.affectedRows === 0)
          return res.status(404).json({ message: "Pick not found" });
        res.json({ message: "Pick updated successfully" });
      }
    );
  });

  // Admin: delete pick
  router.delete("/:id", verifyToken, isAdmin, (req, res) => {
    db.query("DELETE FROM picks WHERE id = ?", [req.params.id], (err, result) => {
      if (err) return res.status(500).json({ message: "Failed to delete pick" });
      if (result.affectedRows === 0)
        return res.status(404).json({ message: "Pick not found" });
      res.json({ message: "Pick deleted successfully" });
    });
  });

  return router;
};
EOF
echo "✅ routes/picks.js"

# ══════════════════════════════════════════════
# ROUTES/FEATURES.JS
# ══════════════════════════════════════════════
cat > routes/features.js << 'EOF'
// routes/features.js
const express = require("express");
const { verifyToken, isAdmin } = require("../middleware/auth");

module.exports = (db, upload) => {
  const router = express.Router();

  router.get("/", verifyToken, (req, res) => {
    if (Number(req.user.is_vip) !== 1)
      return res.status(403).json({ message: "VIP only" });
    db.query("SELECT * FROM features ORDER BY id DESC", (err, rows) => {
      if (err) return res.status(500).json({ message: "DB error" });
      res.json(rows);
    });
  });

  router.post("/", verifyToken, isAdmin, upload.single("image"), (req, res) => {
    const { title, description } = req.body;
    const image_url = req.file ? req.file.path : null;
    db.query(
      "INSERT INTO features (title, description, image_url) VALUES (?, ?, ?)",
      [title, description, image_url],
      (err) => {
        if (err) return res.status(500).json({ message: "Create failed" });
        res.json({ message: "Feature added" });
      }
    );
  });

  router.put("/:id", verifyToken, isAdmin, upload.single("image"), (req, res) => {
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
  });

  router.delete("/:id", verifyToken, isAdmin, (req, res) => {
    db.query("DELETE FROM features WHERE id=?", [req.params.id], (err) => {
      if (err) return res.status(500).json({ message: "Delete failed" });
      res.json({ message: "Feature deleted" });
    });
  });

  return router;
};
EOF
echo "✅ routes/features.js"

# ══════════════════════════════════════════════
# ROUTES/PAYMENTS.JS
# ══════════════════════════════════════════════
cat > routes/payments.js << 'EOF'
// routes/payments.js
const express = require("express");
const { verifyToken } = require("../middleware/auth");

module.exports = (db, intasend) => {
  const router = express.Router();

  router.post("/initiate", verifyToken, async (req, res) => {
    const { amount, phone_number, plan_name } = req.body;
    if (!amount || !phone_number || !plan_name)
      return res.status(400).json({ success: false, message: "Missing required fields" });

    let phone = phone_number.replace(/[\s\+\-]/g, "");
    if (phone.startsWith("0"))    phone = "254" + phone.substring(1);
    if (!phone.startsWith("254")) phone = "254" + phone;

    if (!/^254[17]\d{8}$/.test(phone))
      return res.status(400).json({ success: false, message: "Invalid phone number. Use 07XXXXXXXX or 254XXXXXXXXX" });

    if (!intasend)
      return res.status(500).json({ success: false, message: "Payment service not configured" });

    try {
      const apiRef = `MEGA-${Date.now()}-${req.user.id}`;
      const collection = intasend.collection();
      const response = await collection.mpesaStkPush({
        first_name: "Customer",
        last_name: "",
        email: req.user.email || "customer@megaodds.com",
        host: "https://megaodds.vercel.app",
        amount: parseFloat(amount),
        phone_number: phone,
        api_ref: apiRef,
        narrative: `Payment for ${plan_name}`,
      });

      const invoiceId =
        response.invoice?.invoice_id || response.invoice?.id || response.id || apiRef;

      db.query(
        "INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [req.user.id, amount, phone, plan_name, invoiceId, apiRef, "PENDING"],
        (err) => { if (err) console.error("⚠️ Payment DB save error:", err.message); }
      );

      res.json({ success: true, message: "STK Push sent! Enter your M-Pesa PIN.", invoice_id: invoiceId, api_ref: apiRef });
    } catch (error) {
      const msg = error?.response?.data?.detail || error?.response?.data?.message || error?.message || "Payment initiation failed.";
      res.status(500).json({ success: false, message: msg });
    }
  });

  router.get("/status/:invoice_id", verifyToken, async (req, res) => {
    if (!intasend)
      return res.status(500).json({ success: false, message: "Payment service not configured" });
    try {
      const collection = intasend.collection();
      const response = await collection.status(req.params.invoice_id);
      const paymentState = response.invoice?.state || response.state || response.status;

      if (paymentState === "COMPLETE" || paymentState === "COMPLETED") {
        db.query("UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = ?", [req.params.invoice_id]);
        db.query("UPDATE users SET is_vip = 1 WHERE id = ?", [req.user.id]);
      }
      res.json({ success: true, status: paymentState, invoice: response.invoice || response });
    } catch (error) {
      res.status(500).json({ success: false, message: "Failed to check payment status" });
    }
  });

  router.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
    try {
      const event = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
      const invoiceId = event.invoice?.invoice_id || event.invoice_id;
      const state     = event.invoice?.state      || event.state;
      const apiRef    = event.invoice?.api_ref    || event.api_ref;

      if (state === "COMPLETE" || state === "COMPLETED") {
        db.query("UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = ? OR api_ref = ?", [invoiceId, apiRef]);
        db.query("SELECT user_id FROM payments WHERE invoice_id = ? OR api_ref = ?", [invoiceId, apiRef], (err, rows) => {
          if (!err && rows.length > 0) {
            db.query("UPDATE users SET is_vip = 1 WHERE id = ?", [rows[0].user_id]);
            console.log(`✅ User ${rows[0].user_id} upgraded via webhook`);
          }
        });
      }
      res.status(200).json({ received: true });
    } catch (error) {
      res.status(500).json({ error: "Webhook processing failed" });
    }
  });

  router.get("/history", verifyToken, (req, res) => {
    db.query(
      "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC",
      [req.user.id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: "Failed to fetch history" });
        res.json(rows);
      }
    );
  });

  return router;
};
EOF
echo "✅ routes/payments.js"

# ══════════════════════════════════════════════
# INDEX.JS (overwrite the old one)
# ══════════════════════════════════════════════
cat > index.js << 'EOF'
// ==========================================
// MEGA-ODDS BACKEND — Modular Entry Point
// ==========================================

process.on('uncaughtException', (error) => {
  console.error('💥 UNCAUGHT EXCEPTION:', error.message);
});
process.on('unhandledRejection', (reason) => {
  console.error('💥 UNHANDLED REJECTION:', reason);
});

require("dotenv").config();

const express = require("express");
const cors    = require("cors");
const app     = express();
const PORT    = process.env.PORT || 5000;

app.use(cors({
  origin: [
    "https://megaodds.vercel.app",
    "http://localhost:3000",
    "http://localhost:5173"
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());
app.use((req, _res, next) => {
  console.log(`📨 ${req.method} ${req.path}`);
  next();
});

const { db }       = require("./services/db");
const { intasend } = require("./services/intasend");
const { upload }   = require("./services/cloudinary");

app.use("/",            require("./routes/auth")(db));
app.use("/api/picks",   require("./routes/picks")(db));
app.use("/features",    require("./routes/features")(db, upload));
app.use("/api/payment", require("./routes/payments")(db, intasend));

app.get("/", (_req, res) => res.send("🚀 Mega-Odds API Running ✅"));
app.get("/health", (_req, res) => res.json({
  status: "online",
  timestamp: new Date().toISOString(),
  uptime: process.uptime(),
  database: db ? "connected" : "disconnected",
  intasend: intasend ? "initialized" : "not initialized",
}));

app.use((err, _req, res, _next) => {
  console.error("💥 Express error:", err);
  res.status(500).json({ message: "Internal server error" });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🔥 SERVER RUNNING ON PORT ${PORT}`);
  console.log(`📍 Health: http://localhost:${PORT}/health\n`);
});

process.on("SIGTERM", () => {
  server.close(() => {
    if (db) db.end();
    process.exit(0);
  });
});
EOF
echo "✅ index.js"

# ══════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════
echo ""
echo "🎉 =================================="
echo "🎉  ALL FILES CREATED SUCCESSFULLY!"
echo "🎉 =================================="
echo ""
echo "📁 Structure:"
echo "   index.js"
echo "   middleware/auth.js"
echo "   services/db.js"
echo "   services/intasend.js"
echo "   services/cloudinary.js"
echo "   routes/auth.js"
echo "   routes/picks.js"
echo "   routes/features.js"
echo "   routes/payments.js"
echo ""
echo "▶️  Start the server with: node index.js"
