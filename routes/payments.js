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

      try {
        await db.query(
          "INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status) VALUES ($1, $2, $3, $4, $5, $6, $7)",
          [req.user.id, amount, phone, plan_name, invoiceId, apiRef, "PENDING"]
        );
      } catch (err) {
        console.error("⚠️ Payment DB save error:", err.message);
      }

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
        await db.query("UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = $1", [req.params.invoice_id]);
        await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [req.user.id]);
      }
      res.json({ success: true, status: paymentState, invoice: response.invoice || response });
    } catch (error) {
      res.status(500).json({ success: false, message: "Failed to check payment status" });
    }
  });

  router.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
    try {
      const event = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
      const invoiceId = event.invoice?.invoice_id || event.invoice_id;
      const state     = event.invoice?.state      || event.state;
      const apiRef    = event.invoice?.api_ref    || event.api_ref;

      if (state === "COMPLETE" || state === "COMPLETED") {
        await db.query(
          "UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = $1 OR api_ref = $2",
          [invoiceId, apiRef]
        );
        const result = await db.query(
          "SELECT user_id FROM payments WHERE invoice_id = $1 OR api_ref = $2",
          [invoiceId, apiRef]
        );
        if (result.rows.length > 0) {
          await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [result.rows[0].user_id]);
          console.log(`✅ User ${result.rows[0].user_id} upgraded via webhook`);
        }
      }
      res.status(200).json({ received: true });
    } catch (error) {
      res.status(500).json({ error: "Webhook processing failed" });
    }
  });

  router.get("/history", verifyToken, async (req, res) => {
    try {
      const result = await db.query(
        "SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC",
        [req.user.id]
      );
      res.json(result.rows);
    } catch (err) {
      res.status(500).json({ message: "Failed to fetch history" });
    }
  });

  return router;
};
