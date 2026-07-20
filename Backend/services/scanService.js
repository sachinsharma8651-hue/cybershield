const { isValidUrl } = require("../utils/urlUtils");

const analyzeInput = async (input) => {

    let type = "text";

    if (isValidUrl(input)) {
        type = "url";
    }

   const result = {
    input,
    type,
    riskScore: 0,
    isSecure: false,
    usesHTTPS: false,
    message: "Analysis completed successfully."
};

    if (type === "url") {

    result.usesHTTPS = input.startsWith("https://");
    result.isSecure = result.usesHTTPS;

    if (result.usesHTTPS) {
        result.message = "Secure HTTPS URL detected.";
    } else {
        result.message = "Warning: URL is not using HTTPS.";
        result.riskScore = 30;
    }

} else {

    result.message = "Text detected.";

}

    return result;
};

module.exports = {
    analyzeInput
};