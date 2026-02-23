// routes/picks.js
const express = require("express");
const { verifyToken, isAdmin } = require("../middleware/auth");

module.exports = (db) => {
  const router = express.Router();

  // Public: yesterday's picks
  router.get("/yesterday", async (_req, res) => {
    try {
      const result = await db.query(
        "SELECT * FROM picks WHERE pick_type = 'yesterday' ORDER BY created_at DESC"
      );
      res.json(result.rows);
    } catch (err) {
      res.status(500).json({ message: "DB error" });
    }
  });

  // Public: today's picks
  router.get("/today", async (_req, res) => {
    try {
      const result = await db.query(
        "SELECT * FROM picks WHERE pick_type = 'today' ORDER BY created_at DESC"
      );
      res.json(result.rows);
    } catch (err) {
      res.status(500).json({ message: "DB error" });
    }
  });

  // Public: single pick
  router.get("/:id", async (req, res) => {
    try {
      const result = await db.query("SELECT * FROM picks WHERE id = $1", [req.params.id]);
      if (!result.rows.length) return res.status(404).json({ message: "Pick not found" });
      res.json(result.rows[0]);
    } catch (err) {
      res.status(500).json({ message: "DB error" });
    }
  });

  // Admin: create pick
  router.post("/", verifyToken, isAdmin, async (req, res) => {
    const { team1, team2, time, prediction, odds, status, isVIP, pickType } = req.body;

    if (!team1 || !team2 || !time || !pickType)
      return res.status(400).json({ message: "Missing required fields: team1, team2, time, pickType" });

    const finalPrediction = isVIP ? "Locked" : (prediction || "");
    const finalOdds       = isVIP ? "--"      : (odds       || "");

    try {
      const result = await db.query(
        "INSERT INTO picks (team1, team2, time, prediction, odds, status, is_vip, pick_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        [team1, team2, time, finalPrediction, finalOdds, status || "Pending", isVIP ? 1 : 0, pickType]
      );
      res.status(201).json({ message: "Pick created successfully", id: result.rows[0].id });
    } catch (err) {
      res.status(500).json({ message: "Failed to create pick" });
    }
  });

  // Admin: update pick
  router.put("/:id", verifyToken, isAdmin, async (req, res) => {
    const { team1, team2, time, prediction, odds, status, isVIP } = req.body;

    const finalPrediction = isVIP ? "Locked" : (prediction || "");
    const finalOdds       = isVIP ? "--"      : (odds       || "");

    try {
      const result = await db.query(
        "UPDATE picks SET team1=$1, team2=$2, time=$3, prediction=$4, odds=$5, status=$6, is_vip=$7 WHERE id=$8",
        [team1, team2, time, finalPrediction, finalOdds, status, isVIP ? 1 : 0, req.params.id]
      );
      if (result.rowCount === 0)
        return res.status(404).json({ message: "Pick not found" });
      res.json({ message: "Pick updated successfully" });
    } catch (err) {
      res.status(500).json({ message: "Failed to update pick" });
    }
  });

  // Admin: delete pick
  router.delete("/:id", verifyToken, isAdmin, async (req, res) => {
    try {
      const result = await db.query("DELETE FROM picks WHERE id = $1", [req.params.id]);
      if (result.rowCount === 0)
        return res.status(404).json({ message: "Pick not found" });
      res.json({ message: "Pick deleted successfully" });
    } catch (err) {
      res.status(500).json({ message: "Failed to delete pick" });
    }
  });

  return router;
};
