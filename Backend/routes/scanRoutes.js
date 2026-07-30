const express = require("express");
const router = express.Router();

const { analyzeScan } = require("../controllers/scanController");
const protect = require("../middleware/authMiddleware");
router.post("/analyze", analyzeScan);

module.exports = router;