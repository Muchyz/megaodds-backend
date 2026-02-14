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
const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 5000;

// ── Middleware ──────────────────────────────
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

// ── Shared services (db, intasend, cloudinary) ──
const { db }        = require("./services/db");
const { intasend }  = require("./services/intasend");
const { upload }    = require("./services/cloudinary");

// ── Routes ──────────────────────────────────
app.use("/",            require("./routes/auth")(db));
app.use("/api/picks",   require("./routes/picks")(db));
app.use("/features",    require("./routes/features")(db, upload));
app.use("/api/payment", require("./routes/payments")(db, intasend));

// ── Health ──────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({
    status: "online",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: db ? "connected" : "disconnected",
    intasend: intasend ? "initialized" : "not initialized",
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
