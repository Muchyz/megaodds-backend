// routes/features.js
const express = require("express");
const { verifyToken, isAdmin } = require("../middleware/auth");

module.exports = (db, upload) => {
  const router = express.Router();

  router.get("/", verifyToken, (req, res) => {
    if (Number(req.user.is_vip) !== 1)
      return res.status(403).json({ message: "VIP only" });
    db.query("SELECT * FROM features ORDER BY id DESC", (err, rows) => {
      if (err) return res.status(500).json({ message: "DB error" });
      res.json(rows);
    });
  });

  router.post("/", verifyToken, isAdmin, upload.single("image"), (req, res) => {
    const { title, description } = req.body;
    const image_url = req.file ? req.file.path : null;
    db.query(
      "INSERT INTO features (title, description, image_url) VALUES (?, ?, ?)",
      [title, description, image_url],
      (err) => {
        if (err) return res.status(500).json({ message: "Create failed" });
        res.json({ message: "Feature added" });
      }
    );
  });

  router.put("/:id", verifyToken, isAdmin, upload.single("image"), (req, res) => {
    const { title, description } = req.body;
    const image_url = req.file?.path;
    const sql = image_url
      ? "UPDATE features SET title=?, description=?, image_url=? WHERE id=?"
      : "UPDATE features SET title=?, description=? WHERE id=?";
    const values = image_url
      ? [title, description, image_url, req.params.id]
      : [title, description, req.params.id];
    db.query(sql, values, (err) => {
      if (err) return res.status(500).json({ message: "Update failed" });
      res.json({ message: "Feature updated" });
    });
  });

  router.delete("/:id", verifyToken, isAdmin, (req, res) => {
    db.query("DELETE FROM features WHERE id=?", [req.params.id], (err) => {
      if (err) return res.status(500).json({ message: "Delete failed" });
      res.json({ message: "Feature deleted" });
    });
  });

  return router;
};
