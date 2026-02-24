// ==========================================
// MEGA-ODDS BACKEND — Modular Entry Point
// ==========================================

process.on("uncaughtException", (error) => {
  console.error("💥 UNCAUGHT EXCEPTION:", error.message);
});
process.on("unhandledRejection", (reason) => {
  console.error("💥 UNHANDLED REJECTION:", reason);
});

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 5000;

// ── Middleware ──────────────────────────────
app.use(
  cors({
    origin: [
      "https://megaodds.vercel.app",
      "http://localhost:3000",
      "http://localhost:5173",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// IMPORTANT: webhook route needs raw body — mount BEFORE express.json()
// express.json() is applied per-route in the payments router for all other routes
app.use((req, res, next) => {
  if (req.originalUrl === "/api/payment/webhook") {
    next(); // skip global json parsing; payments router handles it raw
  } else {
    express.json()(req, res, next);
  }
});

app.use((req, _res, next) => {
  console.log(`📨 ${req.method} ${req.path}`);
  next();
});

// ── Shared services ─────────────────────────
const { db }            = require("./services/db");
const { paystackClient } = require("./services/paystack"); // ← replaced intasend
const { upload }        = require("./services/cloudinary");

// ── Routes ──────────────────────────────────
app.use("/",            require("./routes/auth")(db));
app.use("/api/picks",   require("./routes/picks")(db));
app.use("/api/reviews", require("./routes/reviews")(db));
app.use("/features",    require("./routes/features")(db, upload));
app.use("/api/payment", require("./routes/payments")(db, paystackClient)); // ← updated

// ── Health ──────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({
    status: "online",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: db ? "connected" : "disconnected",
    paystack: paystackClient ? "initialized" : "not initialized",
  });
});

// ── Global error handler ────────────────────
app.use((err, _req, res, _next) => {
  console.error("💥 Express error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// ── Start ───────────────────────────────────
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
