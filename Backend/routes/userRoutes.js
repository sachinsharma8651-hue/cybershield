const express = require("express");
const router = express.Router();

const {
    signup,
    login
} = require("../controllers/authController");

const protect = require("../middleware/authMiddleware");

// ======================
// Public Routes
// ======================
router.post("/signup", signup);
router.post("/login", login);

router.get("/test", (req, res) => {
    res.json({
        success: true,
        message: "User Route Working Successfully"
    });
});

// ======================
// Protected Route
// ======================
router.get("/profile", protect, (req, res) => {
    res.status(200).json({
        success: true,
        message: "Protected Route Access Granted",
        user: req.user
    });
});

module.exports = router;