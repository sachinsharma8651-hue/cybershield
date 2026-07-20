const { analyzeInput } = require("../services/scanService");

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

        return res.status(200).json({
            success: true,
            result
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