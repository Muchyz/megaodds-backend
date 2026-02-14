// routes/picks.js
const express = require("express");
const { verifyToken, isAdmin } = require("../middleware/auth");

module.exports = (db) => {
  const router = express.Router();

  // Public: yesterday's picks
  router.get("/yesterday", (_req, res) => {
    db.query(
      "SELECT * FROM picks WHERE pick_type = 'yesterday' ORDER BY created_at DESC",
      (err, rows) => {
        if (err) return res.status(500).json({ message: "DB error" });
        res.json(rows);
      }
    );
  });

  // Public: today's picks
  router.get("/today", (_req, res) => {
    db.query(
      "SELECT * FROM picks WHERE pick_type = 'today' ORDER BY created_at DESC",
      (err, rows) => {
        if (err) return res.status(500).json({ message: "DB error" });
        res.json(rows);
      }
    );
  });

  // Public: single pick
  router.get("/:id", (req, res) => {
    db.query("SELECT * FROM picks WHERE id = ?", [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ message: "DB error" });
      if (!rows.length) return res.status(404).json({ message: "Pick not found" });
      res.json(rows[0]);
    });
  });

  // Admin: create pick
  router.post("/", verifyToken, isAdmin, (req, res) => {
    const { team1, team2, time, prediction, odds, status, isVIP, pickType } = req.body;

    if (!team1 || !team2 || !time || !pickType)
      return res.status(400).json({ message: "Missing required fields: team1, team2, time, pickType" });

    const finalPrediction = isVIP ? "Locked" : (prediction || "");
    const finalOdds       = isVIP ? "--"      : (odds       || "");

    db.query(
      "INSERT INTO picks (team1, team2, time, prediction, odds, status, is_vip, pick_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [team1, team2, time, finalPrediction, finalOdds, status || "Pending", isVIP ? 1 : 0, pickType],
      (err, result) => {
        if (err) return res.status(500).json({ message: "Failed to create pick" });
        res.status(201).json({ message: "Pick created successfully", id: result.insertId });
      }
    );
  });

  // Admin: update pick
  router.put("/:id", verifyToken, isAdmin, (req, res) => {
    const { team1, team2, time, prediction, odds, status, isVIP } = req.body;

    const finalPrediction = isVIP ? "Locked" : (prediction || "");
    const finalOdds       = isVIP ? "--"      : (odds       || "");

    db.query(
      "UPDATE picks SET team1=?, team2=?, time=?, prediction=?, odds=?, status=?, is_vip=? WHERE id=?",
      [team1, team2, time, finalPrediction, finalOdds, status, isVIP ? 1 : 0, req.params.id],
      (err, result) => {
        if (err) return res.status(500).json({ message: "Failed to update pick" });
        if (result.affectedRows === 0)
          return res.status(404).json({ message: "Pick not found" });
        res.json({ message: "Pick updated successfully" });
      }
    );
  });

  // Admin: delete pick
  router.delete("/:id", verifyToken, isAdmin, (req, res) => {
    db.query("DELETE FROM picks WHERE id = ?", [req.params.id], (err, result) => {
      if (err) return res.status(500).json({ message: "Failed to delete pick" });
      if (result.affectedRows === 0)
        return res.status(404).json({ message: "Pick not found" });
      res.json({ message: "Pick deleted successfully" });
    });
  });

  return router;
};
