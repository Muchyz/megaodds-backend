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
