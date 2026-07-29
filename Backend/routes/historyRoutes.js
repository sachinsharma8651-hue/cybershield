const express = require("express");

const {
  saveScan,
  getHistory,
  deleteScan,
} = require("../controllers/historyController");

const protect = require("../middleware/authMiddleware");
const router = express.Router();

// Save a scan
router.post("/", protect, saveScan);

// Get logged-in user's history
router.get("/", protect, getHistory);

// Delete a scan
router.delete("/:id", protect, deleteScan);

module.exports = router;