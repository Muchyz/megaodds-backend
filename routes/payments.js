const express = require("express");
const crypto = require("crypto");
const { verifyToken } = require("../middleware/auth");

module.exports = (db, paystackClient) => {
  const router = express.Router();

  const detectProvider = (phone) => {
    const local = phone.startsWith("254") ? "0" + phone.substring(3) : phone;
    const prefix4 = local.substring(0, 4);
    const mpesaPrefixes = [
      "0700","0701","0702","0703","0704","0705","0706","0707","0708","0709",
      "0710","0711","0712","0713","0714","0715","0716","0717","0718","0719",
      "0720","0721","0722","0723","0724","0725","0726","0727","0728","0729",
      "0740","0741","0742","0743","0744","0745","0746","0747","0748","0749",
      "0757","0758","0759","0768","0769",
      "0790","0791","0792","0793","0794","0795","0796","0797","0798","0799",
      "0110","0111","0112","0113","0114","0115","0116","0117","0118","0119",
    ];
    return mpesaPrefixes.includes(prefix4) ? "mpesa" : "airtel";
  };

  // ── INITIATE PAYMENT ──────────────────────────────
  router.post("/initiate", verifyToken, async (req, res) => {
    const { amount, phone_number, plan_name, reference_number } = req.body;

    if (!amount || !phone_number || !plan_name)
      return res.status(400).json({ success: false, message: "Missing required fields" });

    let phone = phone_number.replace(/[\s\+\-]/g, "");
    if (phone.startsWith("0")) phone = "254" + phone.substring(1);
    if (!phone.startsWith("254")) phone = "254" + phone;

    if (!/^254[17]\d{8}$/.test(phone))
      return res.status(400).json({ success: false, message: "Invalid phone number. Use 07XXXXXXXX" });

    if (!paystackClient)
      return res.status(500).json({ success: false, message: "Payment service not configured" });

    try {
      const apiRef = reference_number || `MEGA-${Date.now()}-${req.user.id}`;
      const provider = detectProvider(phone);
      const localPhone = phone.replace(/^254/, "0"); // Paystack Kenya needs 07XX format

      const chargePayload = {
        email: req.user.email || "customer@megaodds.com",
        amount: Math.round(parseFloat(amount) * 100), // convert to cents
        currency: "KES",
        mobile_money: {
          phone: localPhone,
          provider: provider,
        },
        reference: apiRef,
        metadata: {
          plan_name,
          user_id: req.user.id,
        },
      };

      console.log("Paystack charge payload:", JSON.stringify(chargePayload));

      const response = await paystackClient.post("/charge", chargePayload);
      const data = response.data.data;

      console.log("Paystack response:", JSON.stringify(response.data));

      await db.query(
        "INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        [req.user.id, amount, phone, plan_name, data.reference, apiRef, "PENDING"]
      ).catch(err => console.error("DB save error:", err.message));

      const stkPushed = ["send_otp", "pay_offline", "pending", "success"].includes(data.status);

      if (stkPushed) {
        return res.json({
          success: true,
          message: provider === "mpesa"
            ? "STK Push sent! Check your phone and enter your M-Pesa PIN."
            : "Payment prompt sent! Approve on your Airtel Money.",
          invoice_id: data.reference,
          api_ref: apiRef,
          provider,
          status: data.status,
        });
      }

      return res.status(500).json({ success: false, message: `Unexpected payment status: ${data.status}` });
    } catch (error) {
      const msg = error?.response?.data?.message || error?.message || "Payment initiation failed.";
      console.error("Payment error:", msg, JSON.stringify(error?.response?.data));
      res.status(500).json({ success: false, message: msg });
    }
  });

  // ── CHECK PAYMENT STATUS ──────────────────────────
  router.get("/status/:invoice_id", verifyToken, async (req, res) => {
    if (!paystackClient)
      return res.status(500).json({ success: false, message: "Payment service not configured" });

    try {
      const response = await paystackClient.get(
        `/transaction/verify/${encodeURIComponent(req.params.invoice_id)}`
      );
      const txn = response.data.data;
      const rawStatus = txn.status;

      if (rawStatus === "success") {
        await db.query(
          "UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = $1 OR api_ref = $1",
          [req.params.invoice_id]
        );
        await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [req.user.id]);
        console.log(`✅ User ${req.user.id} upgraded to VIP`);
      }

      const statusMap = {
        success: "COMPLETE",
        failed: "FAILED",
        abandoned: "FAILED",
        pending: "PENDING",
      };

      res.json({
        success: true,
        status: statusMap[rawStatus] || rawStatus.toUpperCase(),
        invoice: txn,
      });
    } catch (error) {
      console.error("Status check error:", error?.response?.data || error.message);
      res.status(500).json({ success: false, message: "Failed to check payment status" });
    }
  });

  // ── WEBHOOK ───────────────────────────────────────
  router.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
    const paystackSig = req.headers["x-paystack-signature"];
    const hash = crypto
      .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
      .update(req.body)
      .digest("hex");

    if (hash !== paystackSig) {
      console.warn("Invalid Paystack webhook signature");
      return res.status(401).json({ error: "Invalid signature" });
    }

    let event;
    try {
      event = JSON.parse(req.body);
    } catch (e) {
      return res.status(400).json({ error: "Invalid JSON" });
    }

    console.log(`Paystack webhook: ${event.event}`);

    if (event.event === "charge.success") {
      const { reference, metadata } = event.data;
      const userId = metadata?.user_id;

      try {
        await db.query(
          "UPDATE payments SET status = 'COMPLETE' WHERE invoice_id = $1 OR api_ref = $1",
          [reference]
        );

        if (userId) {
          await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [userId]);
          console.log(`✅ User ${userId} upgraded via webhook`);
        } else {
          const result = await db.query(
            "SELECT user_id FROM payments WHERE invoice_id = $1 OR api_ref = $1",
            [reference]
          );
          if (result.rows.length > 0) {
            await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [result.rows[0].user_id]);
            console.log(`✅ User ${result.rows[0].user_id} upgraded via webhook fallback`);
          }
        }
      } catch (dbErr) {
        console.error("Webhook DB error:", dbErr.message);
      }
    }

    res.status(200).json({ received: true });
  });

  // ── MANUAL PAYMENT VERIFY ─────────────────────────
  router.post("/verify-manual", verifyToken, async (req, res) => {
    const { transaction_code, reference_number, amount, plan_name } = req.body;

    if (!transaction_code)
      return res.status(400).json({ success: false, message: "Transaction code is required" });

    const code = transaction_code.toUpperCase().trim();

    try {
      const existingResult = await db.query(
        "SELECT * FROM payments WHERE api_ref = $1 AND status = 'COMPLETE'",
        [code]
      );

      if (existingResult.rows.length > 0)
        return res.status(400).json({ success: false, message: "This transaction code has already been used." });

      let paystackVerified = false;
      if (reference_number && paystackClient) {
        try {
          const verifyRes = await paystackClient.get(
            `/transaction/verify/${encodeURIComponent(reference_number)}`
          );
          if (verifyRes.data?.data?.status === "success") {
            paystackVerified = true;
          }
        } catch (e) {
          console.log("Paystack verify attempt failed:", e?.response?.data?.message || e.message);
        }
      }

      if (paystackVerified) {
        await db.query(
          "INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (api_ref) DO UPDATE SET status = 'COMPLETE'",
          [req.user.id, amount, "manual", plan_name, reference_number, code, "COMPLETE"]
        );
        await db.query("UPDATE users SET is_vip = 1 WHERE id = $1", [req.user.id]);
        console.log(`✅ Manual payment verified for user ${req.user.id}`);
        return res.json({ success: true, message: "Payment verified! VIP access activated." });
      }

      await db.query(
        "INSERT INTO payments (user_id, amount, phone_number, plan_name, invoice_id, api_ref, status) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        [req.user.id, amount || 0, "manual", plan_name || "Unknown", code, reference_number || code, "MANUAL_PENDING"]
      ).catch(() => {});

      console.log(`Manual payment pending review: user ${req.user.id}, code: ${code}`);

      return res.status(404).json({
        success: false,
        message: "Payment not automatically verified. Your transaction has been logged and will be reviewed within 5 minutes. Contact support with code: " + code,
      });
    } catch (error) {
      console.error("Manual verification error:", error.message);
      res.status(500).json({ success: false, message: "Verification failed. Please contact support." });
    }
  });

  // ── PAYMENT HISTORY ───────────────────────────────
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
