const express = require("express");
const router = express.Router();

const { analyzeScan } = require("../controllers/scanController");

router.post("/analyze", analyzeScan);

module.exports = router;