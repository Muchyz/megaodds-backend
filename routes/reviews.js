// ==========================================
// REVIEWS ROUTE  —  /api/reviews
// Usage in index.js:
//   app.use("/api/reviews", require("./routes/reviews")(db));
// ==========================================

module.exports = (db) => {
  const express = require("express");
  const router  = express.Router();

  // ── Mask helpers (server-side, for public endpoint) ─────────────
  const maskEmail = (email) => {
    if (!email) return '';
    const [user, domain] = email.split('@');
    if (user.length <= 3) return `${user[0]}***@${domain}`;
    return `${user.substring(0, 2)}***${user.slice(-1)}@${domain}`;
  };

  const maskPhone = (phone) => {
    if (!phone || phone.length < 10) return phone;
    return `${phone.substring(0, 7)}***${phone.slice(-3)}`;
  };

  // ── GET all visible reviews (public) — email masked, phone masked ─
  router.get("/", async (req, res) => {
    try {
      const result = await db.query(
        `SELECT id, name, location, badge, rating, review_text,
                status, verified, member_since, likes, created_at,
                email, phone
         FROM reviews
         WHERE is_visible = TRUE
         ORDER BY created_at DESC`
      );
      // Mask sensitive fields before sending to public
      const rows = result.rows.map(r => ({
        ...r,
        email: maskEmail(r.email),
        phone: maskPhone(r.phone),
      }));
      res.json(rows);
    } catch (err) {
      console.error("GET /api/reviews:", err.message);
      res.status(500).json({ message: "Failed to fetch reviews" });
    }
  });

  // ── GET all reviews unmasked (admin only) ───────────────────────
  router.get("/admin", async (req, res) => {
    try {
      const result = await db.query(
        `SELECT * FROM reviews ORDER BY created_at DESC`
      );
      res.json(result.rows);
    } catch (err) {
      console.error("GET /api/reviews/admin:", err.message);
      res.status(500).json({ message: "Failed to fetch reviews" });
    }
  });

  // ── POST create review (admin) ──────────────────────────────────
  router.post("/", async (req, res) => {
    const {
      name, location, badge, rating, review_text,
      status, verified, member_since, email, phone, likes, is_visible,
    } = req.body;

    if (!name || !review_text) {
      return res.status(400).json({ message: "Name and review text are required" });
    }

    try {
      const result = await db.query(
        `INSERT INTO reviews
           (name, location, badge, rating, review_text, status,
            verified, member_since, email, phone, likes, is_visible)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         RETURNING id`,
        [
          name,
          location     ?? "Nairobi",
          badge        ?? "Starter",
          rating       ?? 5,
          review_text,
          status       ?? "offline",
          verified     ?? true,
          member_since ?? "",
          email        ?? "",
          phone        ?? "",
          likes        ?? 0,
          is_visible   ?? true,
        ]
      );
      res.status(201).json({ id: result.rows[0].id, message: "Review created" });
    } catch (err) {
      console.error("POST /api/reviews:", err.message);
      res.status(500).json({ message: "Failed to create review" });
    }
  });

  // ── PUT update review (admin) ───────────────────────────────────
  router.put("/:id", async (req, res) => {
    const { id } = req.params;
    const {
      name, location, badge, rating, review_text,
      status, verified, member_since, email, phone, likes, is_visible,
    } = req.body;

    try {
      await db.query(
        `UPDATE reviews
         SET name=$1, location=$2, badge=$3, rating=$4, review_text=$5,
             status=$6, verified=$7, member_since=$8, email=$9, phone=$10,
             likes=$11, is_visible=$12, updated_at=CURRENT_TIMESTAMP
         WHERE id=$13`,
        [name, location, badge, rating, review_text, status,
         verified, member_since, email, phone, likes, is_visible, id]
      );
      res.json({ message: "Review updated" });
    } catch (err) {
      console.error("PUT /api/reviews/:id:", err.message);
      res.status(500).json({ message: "Failed to update review" });
    }
  });

  // ── DELETE review (admin) ───────────────────────────────────────
  router.delete("/:id", async (req, res) => {
    const { id } = req.params;
    try {
      await db.query("DELETE FROM reviews WHERE id = $1", [id]);
      res.json({ message: "Review deleted" });
    } catch (err) {
      console.error("DELETE /api/reviews/:id:", err.message);
      res.status(500).json({ message: "Failed to delete review" });
    }
  });

  return router;
};
