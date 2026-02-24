// services/paystack.js
const axios = require("axios");

let paystackClient;

try {
  if (!process.env.PAYSTACK_SECRET_KEY) {
    throw new Error("PAYSTACK_SECRET_KEY is not set in environment variables");
  }

  paystackClient = axios.create({
    baseURL: "https://api.paystack.co",
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    timeout: 30000,
  });

  console.log("✅ Paystack SDK initialized (LIVE mode)");
} catch (err) {
  console.error("❌ Paystack SDK init error:", err.message);
}

module.exports = { paystackClient };
