const { isValidUrl, extractDomain } = require("../utils/urlUtils");
const { getWhoisInfo } = require("./whoisService");
const { getSSLInfo } = require("./sslService");
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
        const domain = extractDomain(input);
        const whoisInfo = await getWhoisInfo(domain);
        const sslInfo = await getSSLInfo(domain);

    result.usesHTTPS = input.startsWith("https://");
    result.domain = domain;
    result.whois = whoisInfo;
    result.ssl = sslInfo;
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