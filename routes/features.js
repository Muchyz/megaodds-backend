// routes/features.js
const express = require("express");
const { verifyToken, isAdmin } = require("../middleware/auth");

module.exports = (db, upload) => {
  const router = express.Router();

  router.get("/", verifyToken, async (req, res) => {
    if (Number(req.user.is_vip) !== 1)
      return res.status(403).json({ message: "VIP only" });
    try {
      const result = await db.query("SELECT * FROM features ORDER BY id DESC");
      res.json(result.rows);
    } catch (err) {
      res.status(500).json({ message: "DB error" });
    }
  });

  router.post("/", verifyToken, isAdmin, upload.single("image"), async (req, res) => {
    const { title, description } = req.body;
    const image_url = req.file ? req.file.path : null;
    try {
      await db.query(
        "INSERT INTO features (title, description, image_url) VALUES ($1, $2, $3)",
        [title, description, image_url]
      );
      res.json({ message: "Feature added" });
    } catch (err) {
      res.status(500).json({ message: "Create failed" });
    }
  });

  router.put("/:id", verifyToken, isAdmin, upload.single("image"), async (req, res) => {
    const { title, description } = req.body;
    const image_url = req.file?.path;
    try {
      if (image_url) {
        await db.query(
          "UPDATE features SET title=$1, description=$2, image_url=$3 WHERE id=$4",
          [title, description, image_url, req.params.id]
        );
      } else {
        await db.query(
          "UPDATE features SET title=$1, description=$2 WHERE id=$3",
          [title, description, req.params.id]
        );
      }
      res.json({ message: "Feature updated" });
    } catch (err) {
      res.status(500).json({ message: "Update failed" });
    }
  });

  router.delete("/:id", verifyToken, isAdmin, async (req, res) => {
    try {
      await db.query("DELETE FROM features WHERE id=$1", [req.params.id]);
      res.json({ message: "Feature deleted" });
    } catch (err) {
      res.status(500).json({ message: "Delete failed" });
    }
  });

  return router;
};
