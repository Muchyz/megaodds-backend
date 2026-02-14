// services/cloudinary.js
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");

let upload;

if (process.env.CLOUDINARY_CLOUD_NAME) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });

  const storage = new CloudinaryStorage({
    cloudinary,
    params: {
      folder: "vip-features",
      allowed_formats: ["jpg", "png", "jpeg", "webp"],
    },
  });

  upload = multer({ storage });
  console.log("✅ Cloudinary configured");
} else {
  console.log("⚠️  Cloudinary not configured");
  upload = multer({ dest: "uploads/" });
}

module.exports = { cloudinary, upload };
