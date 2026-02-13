const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const axios = require("axios");
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
   INTASEND CONFIG
======================= */
const INTASEND_SECRET_KEY = process.env.INTASEND_SECRET_KEY;
const INTASEND_PUBLISHABLE_KEY = process.env.INTASEND_PUBLISHABLE_KEY;
const INTASEND_API_URL = "https://payment.intasend.com/api/v1";

/* =======================
   JWT MIDDLEWARE
======================= */
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

/* =======================
   ADMIN CHECK
======================= */
const isAdmin = (req, res, next) => {
  if (Number(req.user.is_admin) !== 1) {
    return res.status(403).json({ message: "Admin only" });
  }
  next();
};

/* =======================
   AUTH ROUTES
======================= */
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users (email, password) VALUES (?, ?)",
      [email, hash],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ message: "User already exists" });
          }
          return res.status(500).json({ message: "Database error" });
        }
        res.json({ message: "Registered successfully" });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, rows) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (!rows.length) return res.status(401).json({ message: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        is_vip: user.is_vip,
        is_admin: user.is_admin,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, is_vip: user.is_vip, is_admin: user.is_admin });
  });
});

/* =======================
   FEATURES ROUTES
======================= */
app.get("/features", verifyToken, (req, res) => {
  if (Number(req.user.is_vip) !== 1) {
    return res.status(403).json({ message: "VIP only" });
  }

  db.query("SELECT * FROM features ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ message: "DB error" });
    res.json(rows);
  });
});

app.post("/features", verifyToken, isAdmin, upload.single("image"), (req, res) => {
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

app.put("/features/:id", verifyToken, isAdmin, upload.single("image"), (req, res) => {
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

app.delete("/features/:id", verifyToken, isAdmin, (req, res) => {
  db.query("DELETE FROM features WHERE id=?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: "Delete failed" });
    res.json({ message: "Feature deleted" });
  });
});

/* =======================
   PICKS ROUTES
======================= */

// Get yesterday's picks (PUBLIC)
app.get("/api/picks/yesterday", (req, res) => {
  db.query(
    "SELECT * FROM picks WHERE pick_type = 'yesterday' ORDER BY created_at DESC",
    (err, rows) => {
      if (err) {
        console.error("DB error:", err);
        return res.status(500).json({ message: "DB error" });
      }
      res.json(rows);
    }
  );
});

// Get today's picks (PUBLIC)
app.get("/api/picks/today", (req, res) => {
  db.query(
    "SELECT * FROM picks WHERE pick_type = 'today' ORDER BY created_at DESC",
    (err, rows) => {
      if (err) {
        console.error("DB error:", err);
        return res.status(500).json({ message: "DB error" });
      }
      res.json(rows);
    }
  );
});

// Get single pick by ID (PUBLIC)
app.get("/api/picks/:id", (req, res) => {
  db.query("SELECT * FROM picks WHERE id = ?", [req.params.id], (err, rows) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).json({ message: "DB error" });
    }
    if (!rows.length) {
      return res.status(404).json({ message: "Pick not found" });
    }
    res.json(rows[0]);
  });
});

// Create new pick (ADMIN ONLY)
app.post("/api/picks", verifyToken, isAdmin, (req, res) => {
  const { team1, team2, time, prediction, odds, status, isVIP, pickType } = req.body;

  // Validation
  if (!team1 || !team2 || !time || !pickType) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  // If VIP, lock prediction and odds
  const finalPrediction = isVIP ? "Locked" : prediction;
  const finalOdds = isVIP ? "--" : odds;

  db.query(
    "INSERT INTO picks (team1, team2, time, prediction, odds, status, is_vip, pick_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [team1, team2, time, finalPrediction, finalOdds, status || "Pending", isVIP ? 1 : 0, pickType],
    (err, result) => {
      if (err) {
        console.error("Create pick error:", err);
        return res.status(500).json({ message: "Failed to create pick" });
      }
      res.status(201).json({ 
        message: "Pick created successfully",
        id: result.insertId 
      });
    }
  );
});

// Update pick (ADMIN ONLY)
app.put("/api/picks/:id", verifyToken, isAdmin, (req, res) => {
  const { team1, team2, time, prediction, odds, status, isVIP } = req.body;

  // If VIP, lock prediction and odds
  const finalPrediction = isVIP ? "Locked" : prediction;
  const finalOdds = isVIP ? "--" : odds;

  db.query(
    "UPDATE picks SET team1=?, team2=?, time=?, prediction=?, odds=?, status=?, is_vip=? WHERE id=?",
    [team1, team2, time, finalPrediction, finalOdds, status, isVIP ? 1 : 0, req.params.id],
    (err, result) => {
      if (err) {
        console.error("Update pick error:", err);
        return res.status(500).json({ message: "Failed to update pick" });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Pick not found" });
      }
      res.json({ message: "Pick updated successfully" });
    }
  );
});

// Delete pick (ADMIN ONLY)
app.delete("/api/picks/:id", verifyToken, isAdmin, (req, res) => {
  db.query("DELETE FROM picks WHERE id=?", [req.params.id], (err, result) => {
    if (err) {
      console.error("Delete pick error:", err);
      return res.status(500).json({ message: "Failed to delete pick" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Pick not found" });
    }
    res.json({ message: "Pick deleted successfully" });
  });
});

/* =======================
   INTASEND PAYMENT ROUTES
======================= */

// Initiate M-Pesa STK Push
app.post("/api/payment/initiate", verifyToken, async (req, res) => {
  const { amount, phone_number, plan_name } = req.body;

  // Validate input
  if (!amount || !phone_number || !plan_name) {
    return res.status(400).json({ 
      success: false,
      message: "Missing required fields: amount, phone_number, or plan_name" 
    });
  }

  // Format phone number (remove +, spaces, ensure starts with 254)
  let formattedPhone = phone_number.replace(/[\s\+]/g, '');
  if (formattedPhone.startsWith('0')) {
    formattedPhone = '254' + formattedPhone.substring(1);
  }
  if (!formattedPhone.startsWith('254')) {
    formattedPhone = '254' + formattedPhone;
  }

  // Validate phone number format (254XXXXXXXXX)
  if (!/^254[17]\d{8}$/.test(formattedPhone)) {
    return res.status(400).json({ 
      success: false,
      message: "Invalid Kenyan phone number format. Use 07XX XXX XXX or 254XXX XXX XXX" 
    });
  }

  try {
    // Create unique reference
    const apiRef = `MEGA-${Date.now()}-${req.user.id}`;

    // Prepare Intasend STK Push request
    const response = await axios.post(
      `${INTASEND_API_URL}/payment/mpesa-stk-push/`,
      {
        amount: parseFloat(amount),
        phone_number: formattedPhone,
        api_ref: apiRef,
        narrative: `Payment for ${plan_name}`,
        currency: "KES"
      },
      {
        headers: {
          "Authorization": `Bearer ${INTASEND_SECRET_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    console.log("Intasend STK Push Response:", response.data);

    // Store payment record in database
    db.query(
      "INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [
        req.user.id, 
        amount, 
        formattedPhone, 
        plan_name, 
        response.data.invoice?.invoice_id || response.data.id,
        apiRef,
        'PENDING'
      ],
      (err) => {
        if (err) {
          console.error("Error storing payment:", err);
        }
      }
    );

    res.json({
      success: true,
      message: "STK Push sent successfully. Please check your phone.",
      invoice_id: response.data.invoice?.invoice_id || response.data.id,
      tracking_id: response.data.id || response.data.invoice?.id,
      api_ref: apiRef
    });

  } catch (error) {
    console.error("Intasend STK Push Error:", error.response?.data || error.message);
    
    res.status(500).json({ 
      success: false,
      message: error.response?.data?.error || error.response?.data?.detail || "Payment initiation failed. Please try again."
    });
  }
});

// Check payment status
app.get("/api/payment/status/:invoice_id", verifyToken, async (req, res) => {
  try {
    const response = await axios.get(
      `${INTASEND_API_URL}/payment/status/`,
      {
        params: {
          invoice_id: req.params.invoice_id
        },
        headers: {
          "Authorization": `Bearer ${INTASEND_SECRET_KEY}`
        }
      }
    );

    console.log("Payment Status Response:", response.data);

    const paymentState = response.data.invoice?.state || response.data.state;

    // Update payment status in database
    if (paymentState === 'COMPLETE' || paymentState === 'COMPLETED') {
      db.query(
        "UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = ?",
        [req.params.invoice_id],
        (err) => {
          if (err) console.error("Error updating payment status:", err);
        }
      );

      // Update user VIP status
      db.query(
        "UPDATE users SET is_vip = 1 WHERE id = ?",
        [req.user.id],
        (err) => {
          if (err) console.error("Error updating VIP status:", err);
          else console.log(`✅ User ${req.user.id} upgraded to VIP`);
        }
      );
    }

    res.json({
      success: true,
      status: paymentState,
      invoice: response.data.invoice || response.data
    });

  } catch (error) {
    console.error("Status Check Error:", error.response?.data || error.message);
    
    res.status(500).json({ 
      success: false,
      message: "Failed to check payment status"
    });
  }
});

// Webhook for payment notifications
app.post("/api/payment/webhook", express.raw({type: 'application/json'}), (req, res) => {
  try {
    const event = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    
    console.log("📥 Payment Webhook Received:", JSON.stringify(event, null, 2));

    const invoiceId = event.invoice?.invoice_id || event.invoice_id;
    const state = event.invoice?.state || event.state;
    const apiRef = event.invoice?.api_ref || event.api_ref;

    if (state === 'COMPLETE' || state === 'COMPLETED') {
      // Update payment status
      db.query(
        "UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = ? OR api_ref = ?",
        [invoiceId, apiRef],
        (err, result) => {
          if (err) {
            console.error("Webhook payment update error:", err);
          } else {
            console.log(`✅ Payment ${invoiceId} marked as COMPLETE`);
          }
        }
      );

      // Get user from payment and update VIP status
      db.query(
        "SELECT user_id FROM payments WHERE invoice_id = ? OR api_ref = ?",
        [invoiceId, apiRef],
        (err, rows) => {
          if (!err && rows.length > 0) {
            const userId = rows[0].user_id;
            db.query(
              "UPDATE users SET is_vip = 1 WHERE id = ?",
              [userId],
              (err) => {
                if (err) {
                  console.error("Webhook VIP update error:", err);
                } else {
                  console.log(`✅ User ${userId} upgraded to VIP via webhook`);
                }
              }
            );
          }
        }
      );
    } else if (state === 'FAILED') {
      db.query(
        "UPDATE payments SET status = 'FAILED' WHERE invoice_id = ? OR api_ref = ?",
        [invoiceId, apiRef],
        (err) => {
          if (err) console.error("Webhook failed payment update error:", err);
        }
      );
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error("❌ Webhook Processing Error:", error);
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

// Get user's payment history
app.get("/api/payment/history", verifyToken, (req, res) => {
  db.query(
    "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC",
    [req.user.id],
    (err, rows) => {
      if (err) {
        console.error("Payment history error:", err);
        return res.status(500).json({ message: "Failed to fetch payment history" });
      }
      res.json(rows);
    }
  );
});

/* =======================
   HEALTH CHECK
======================= */
app.get("/", (_, res) => {
  res.send("🚀 Mega-Odds API Running - Intasend M-Pesa Integrated");
});

/* =======================
   START SERVER
======================= */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🔥 Server running on port ${PORT}`);
  console.log(`💳 Intasend M-Pesa Integration Active`);
});
