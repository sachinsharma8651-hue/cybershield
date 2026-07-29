const Scan = require("../models/Scan");

// Save Scan
const saveScan = async (req, res) => {
  try {
    const scan = new Scan({
      user: req.user.id,
      input: req.body.input,
      type: req.body.type,
      riskScore: req.body.riskScore,
      isSecure: req.body.isSecure,
      usesHTTPS: req.body.usesHTTPS,
      result: req.body.result,
    });

    await scan.save();

    res.status(201).json({
      success: true,
      message: "Scan saved successfully",
      scan,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Failed to save scan",
    });
  }
};

// Get User History
const getHistory = async (req, res) => {
  try {
    const scans = await Scan.find({ user: req.user.id }).sort({
      createdAt: -1,
    });

    res.json({
      success: true,
      total: scans.length,
      scans,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Failed to fetch history",
    });
  }
};

// Delete Scan
const deleteScan = async (req, res) => {
  try {
    const scan = await Scan.findOneAndDelete({
      _id: req.params.id,
      user: req.user.id,
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan not found",
      });
    }

    res.json({
      success: true,
      message: "Scan deleted successfully",
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Failed to delete scan",
    });
  }
};

module.exports = {
  saveScan,
  getHistory,
  deleteScan,
};