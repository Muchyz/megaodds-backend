// routes/payments.js
const express = require("express");
const crypto = require("crypto");
const { verifyToken } = require("../middleware/auth");

module.exports = (db, paystackClient) => {
  const router = express.Router();

  // ─────────────────────────────────────────────────────
  // Helper: detect M-Pesa vs Airtel from phone number
  // Safaricom (M-Pesa): 0700-0729, 0740-0749, 0757-0759,
  //                     0768-0769, 0790-0799, 0110-0119, 0112, 0113
  // Airtel: 0730-0739, 0750-0756, 0780-0789, 0100-0109, 0111
  // ─────────────────────────────────────────────────────
  const detectProvider = (phone254) => {
    // phone254 is in format 2547XXXXXXXX or 2541XXXXXXXX
    const local = phone254.replace(/^254/, "0"); // convert to 07XX or 01XX
    const prefix3 = local.substring(0, 3); // e.g. "072"
    const prefix4 = local.substring(0, 4); // e.g. "0722"

    const mpesaPrefixes = [
      "0700","0701","0702","0703","0704","0705","0706","0707","0708","0709",
      "0710","0711","0712","0713","0714","0715","0716","0717","0718","0719",
      "0720","0721","0722","0723","0724","0725","0726","0727","0728","0729",
      "0740","0741","0742","0743","0744","0745","0746","0747","0748","0749",
      "0757","0758","0759","0768","0769",
      "0790","0791","0792","0793","0794","0795","0796","0797","0798","0799",
      "0110","0111","0112","0113","0114","0115","0116","0117","0118","0119",
    ];

    if (mpesaPrefixes.includes(prefix4)) return "mpesa";
    return "airtel"; // default fallback
  };

  // ─────────────────────────────────────────────────────
  // POST /api/payment/initiate
  // Triggers STK push via Paystack Mobile Money (M-Pesa / Airtel)
  // ─────────────────────────────────────────────────────
  router.post("/initiate", verifyToken, async (req, res) => {
    const { amount, phone_number, plan_name, reference_number } = req.body;

    if (!amount || !phone_number || !plan_name) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    // Normalize phone to 254XXXXXXXXX
    let phone = phone_number.replace(/[\s\+\-]/g, "");
    if (phone.startsWith("0"))    phone = "254" + phone.substring(1);
    if (!phone.startsWith("254")) phone = "254" + phone;

    if (!/^254[17]\d{8}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: "Invalid phone number. Use 07XXXXXXXX or 254XXXXXXXXX",
      });
    }

    if (!paystackClient) {
      return res.status(500).json({ success: false, message: "Payment service not configured" });
    }

    try {
      const apiRef = reference_number || `MEGA-${Date.now()}-${req.user.id}`;
      const provider = detectProvider(phone);

      const chargePayload = {
        email: req.user.email || "customer@megaodds.com",
        amount: Math.round(parseFloat(amount) * 100), // Paystack uses lowest currency unit (cents/kobos)
        currency: "KES",
        mobile_money: {
          phone,
          provider, // "mpesa" or "airtel"
        },
        reference: apiRef,
        metadata: {
          plan_name,
          user_id: req.user.id,
          custom_fields: [
            { display_name: "Plan", variable_name: "plan_name", value: plan_name },
            { display_name: "User ID", variable_name: "user_id", value: String(req.user.id) },
          ],
        },
      };

      const response = await paystackClient.post("/charge", chargePayload);
      const data = response.data.data;

      // Save to DB
      try {
        await db.query(
          `INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [req.user.id, amount, phone, plan_name, data.reference, apiRef, "PENDING"]
        );
      } catch (dbErr) {
        console.error("⚠️ Payment DB save error:", dbErr.message);
      }

      // Paystack returns these statuses for mobile money:
      // "send_otp"    → STK push sent, waiting for PIN
      // "pay_offline" → user needs to complete on their phone
      // "success"     → already completed (rare for mobile money)
      const stkPushed = ["send_otp", "pay_offline", "pending"].includes(data.status);

      if (stkPushed || data.status === "success") {
        return res.json({
          success: true,
          message:
            provider === "mpesa"
              ? "✅ STK Push sent! Check your phone and enter your M-Pesa PIN."
              : "✅ Payment prompt sent! Check your phone and approve the Airtel Money request.",
          invoice_id: data.reference,
          api_ref: apiRef,
          provider,
          status: data.status,
        });
      }

      // Unexpected status — fall through to manual
      return res.status(500).json({
        success: false,
        message: `Unexpected payment status: ${data.status}. Please use manual payment.`,
      });
    } catch (error) {
      const msg =
        error?.response?.data?.message ||
        error?.message ||
        "Payment initiation failed.";
      console.error("❌ Payment initiation error:", msg, error?.response?.data);
      res.status(500).json({ success: false, message: msg });
    }
  });

  // ─────────────────────────────────────────────────────
  // GET /api/payment/status/:invoice_id
  // Poll payment status (replaces IntaSend status check)
  // ─────────────────────────────────────────────────────
  router.get("/status/:invoice_id", verifyToken, async (req, res) => {
    if (!paystackClient) {
      return res.status(500).json({ success: false, message: "Payment service not configured" });
    }

    try {
      const response = await paystackClient.get(
        `/transaction/verify/${encodeURIComponent(req.params.invoice_id)}`
      );
      const txn = response.data.data;
      const rawStatus = txn.status; // "success" | "failed" | "pending" | "abandoned"

      // Upgrade user on success
      if (rawStatus === "success") {
        await db.query(
          "UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = $1 OR api_ref = $1",
          [req.params.invoice_id]
        );
        await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [req.user.id]);
        console.log(`✅ User ${req.user.id} upgraded to VIP via status poll`);
      }

      // Map to statuses your frontend already understands
      const statusMap = {
        success:   "COMPLETE",
        failed:    "FAILED",
        abandoned: "FAILED",
        pending:   "PENDING",
      };

      res.json({
        success: true,
        status: statusMap[rawStatus] || rawStatus.toUpperCase(),
        invoice: txn,
      });
    } catch (error) {
      console.error("❌ Status check error:", error?.response?.data || error.message);
      res.status(500).json({ success: false, message: "Failed to check payment status" });
    }
  });

  // ─────────────────────────────────────────────────────
  // POST /api/payment/webhook
  // Paystack sends events here — must be raw body for signature check
  // Register this URL in your Paystack dashboard:
  //   https://dashboard.paystack.com/#/settings/developer → Webhooks
  // ─────────────────────────────────────────────────────
  router.post(
    "/webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
      // 1. Verify signature
      const paystackSig = req.headers["x-paystack-signature"];
      const hash = crypto
        .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
        .update(req.body)
        .digest("hex");

      if (hash !== paystackSig) {
        console.warn("⚠️ Invalid Paystack webhook signature");
        return res.status(401).json({ error: "Invalid signature" });
      }

      // 2. Parse event
      let event;
      try {
        event = JSON.parse(req.body);
      } catch (parseErr) {
        return res.status(400).json({ error: "Invalid JSON payload" });
      }

      console.log(`📣 Paystack webhook: ${event.event}`);

      // 3. Handle charge.success
      if (event.event === "charge.success") {
        const { reference, metadata, amount, channel } = event.data;
        const userId = metadata?.user_id;

        try {
          // Update payment record
          await db.query(
            `UPDATE payments SET status = 'COMPLETE'
             WHERE invoice_id = $1 OR api_ref = $1`,
            [reference]
          );

          // Upgrade user if we have their ID from metadata
          if (userId) {
            await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [userId]);
            console.log(`✅ User ${userId} upgraded to VIP via webhook (ref: ${reference}, channel: ${channel})`);
          } else {
            // Fallback: look up user_id from payments table
            const result = await db.query(
              "SELECT user_id FROM payments WHERE invoice_id = $1 OR api_ref = $1",
              [reference]
            );
            if (result.rows.length > 0) {
              const foundUserId = result.rows[0].user_id;
              await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [foundUserId]);
              console.log(`✅ User ${foundUserId} upgraded to VIP via webhook fallback`);
            }
          }
        } catch (dbErr) {
          console.error("❌ Webhook DB error:", dbErr.message);
          // Still return 200 so Paystack doesn't retry
        }
      }

      // Always return 200 quickly
      res.status(200).json({ received: true });
    }
  );

  // ─────────────────────────────────────────────────────
  // POST /api/payment/verify-manual
  // User manually enters M-Pesa transaction code
  // ─────────────────────────────────────────────────────
  router.post("/verify-manual", verifyToken, async (req, res) => {
    const { transaction_code, reference_number, amount, plan_name } = req.body;

    if (!transaction_code) {
      return res.status(400).json({ success: false, message: "Transaction code is required" });
    }

    const code = transaction_code.toUpperCase().trim();

    try {
      // Option A: Verify via Paystack transaction search
      // (Paystack doesn't have a direct M-Pesa code lookup,
      //  so we search by reference or check our DB first)

      // 1. Check if this transaction code was already used (prevent double-use)
      const existingResult = await db.query(
        "SELECT * FROM payments WHERE api_ref = $1 AND status = 'COMPLETE'",
        [code]
      );

      if (existingResult.rows.length > 0) {
        return res.status(400).json({
          success: false,
          message: "This transaction code has already been used.",
        });
      }

      // 2. Try to verify the reference_number on Paystack
      //    (the reference_number was generated when user clicked Pay)
      let paystackVerified = false;
      if (reference_number && paystackClient) {
        try {
          const verifyRes = await paystackClient.get(
            `/transaction/verify/${encodeURIComponent(reference_number)}`
          );
          const txnStatus = verifyRes.data?.data?.status;

          if (txnStatus === "success") {
            paystackVerified = true;
          }
        } catch (verifyErr) {
          console.log("Paystack verify attempt:", verifyErr?.response?.data?.message || verifyErr.message);
        }
      }

      if (paystackVerified) {
        // Confirmed via Paystack — upgrade user
        await db.query(
          `INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (api_ref) DO UPDATE SET status = 'COMPLETE'`,
          [req.user.id, amount, "manual", plan_name, reference_number, code, "COMPLETE"]
        );
        await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [req.user.id]);
        console.log(`✅ Manual payment verified (Paystack) for user ${req.user.id}, code: ${code}`);

        return res.json({
          success: true,
          message: "Payment verified! VIP access activated.",
        });
      }

      // 3. If Paystack can't confirm, save for admin review
      //    (common for M-Pesa STK that timed out but user paid anyway)
      await db.query(
        `INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT DO NOTHING`,
        [req.user.id, amount || 0, "manual", plan_name || "Unknown", code, reference_number || code, "MANUAL_PENDING"]
      ).catch(() => {}); // ignore duplicate

      console.log(`📋 Manual payment pending admin review: user ${req.user.id}, code: ${code}`);

      return res.status(404).json({
        success: false,
        message:
          "Payment not automatically verified. Your transaction has been logged and will be reviewed within 5 minutes. Contact support with code: " + code,
      });
    } catch (error) {
      console.error("❌ Manual verification error:", error.message);
      res.status(500).json({ success: false, message: "Verification failed. Please contact support." });
    }
  });

  // ─────────────────────────────────────────────────────
  // GET /api/payment/history
  // ─────────────────────────────────────────────────────
  router.get("/history", verifyToken, async (req, res) => {
    try {
      const result = await db.query(
        "SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC",
        [req.user.id]
      );
      res.json(result.rows);
    } catch (err) {
      res.status(500).json({ message: "Failed to fetch payment history" });
    }
  });

  return router;
};
