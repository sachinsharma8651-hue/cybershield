const { analyzeInput } = require("../services/scanService");
const Scan = require("../models/Scan");
const analyzeScan = async (req, res) => {

    try {

        const { input } = req.body;

        if (!input) {
            return res.status(400).json({
                success: false,
                message: "Input is required"
            });
        }

        const result = await analyzeInput(input);

// Save scan history
if (req.user) {
    await Scan.create({
        user: req.user.id,
        input: result.input,
        type: result.type,
        riskScore: result.riskScore,
        isSecure: result.isSecure,
        usesHTTPS: result.usesHTTPS,
        result,
    });
}

return res.status(200).json({
    success: true,
    result,
});

    } catch (error) {

        console.error("Scan Error:", error);

        return res.status(500).json({
            success: false,
            message: error.message
        });

    }

};

module.exports = {
    analyzeScan
};