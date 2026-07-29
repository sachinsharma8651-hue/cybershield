const express = require("express");
const router = express.Router();

const { analyzeScan } = require("../controllers/scanController");
const protect = require("../middleware/authMiddleware");
router.post("/analyze", protect, analyzeScan);

module.exports = router;