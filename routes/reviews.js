// ==========================================
// REVIEWS ROUTE  —  /api/reviews
// Usage in index.js:
//   app.use("/api/reviews", require("./routes/reviews")(db));
// ==========================================

module.exports = (db) => {
  const express = require("express");
  const router  = express.Router();

  // ── GET all visible reviews (public) ───────────────────────────
  router.get("/", async (req, res) => {
    try {
      const result = await db.query(
        `SELECT id, name, location, badge, rating, review_text,
                status, verified, member_since, likes, created_at
         FROM reviews
         WHERE is_visible = TRUE
         ORDER BY created_at DESC`
      );
      res.json(result.rows);
    } catch (err) {
      console.error("GET /api/reviews:", err.message);
      res.status(500).json({ message: "Failed to fetch reviews" });
    }
  });

  // ── GET all reviews including hidden (admin) ────────────────────
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
      status, verified, member_since, likes, is_visible,
    } = req.body;

    if (!name || !review_text) {
      return res.status(400).json({ message: "Name and review text are required" });
    }

    try {
      const result = await db.query(
        `INSERT INTO reviews
           (name, location, badge, rating, review_text, status, verified, member_since, likes, is_visible)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
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
      status, verified, member_since, likes, is_visible,
    } = req.body;

    try {
      await db.query(
        `UPDATE reviews
         SET name=$1, location=$2, badge=$3, rating=$4, review_text=$5,
             status=$6, verified=$7, member_since=$8, likes=$9,
             is_visible=$10, updated_at=CURRENT_TIMESTAMP
         WHERE id=$11`,
        [name, location, badge, rating, review_text, status, verified, member_since, likes, is_visible, id]
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
