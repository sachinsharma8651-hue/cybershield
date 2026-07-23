const {
    isValidUrl,
    extractDomain,
    isIPAddress,
    isPrivateIP
} = require("../utils/urlUtils");

const { getWhoisInfo } = require("./whoisService");
const { getSSLInfo } = require("./sslService");
const { getDomainAge } = require("./domainAgeService");
const { analyzePhishing } = require("./phishingService");
const { checkVirusTotal } = require("./virusTotalService");
const { analyzeScamText } = require("./geminiService");

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

        result.usesHTTPS = input.startsWith("https://");
        result.domain = domain;

        let whoisInfo = null;
        let sslInfo = null;
        let virusTotal = null;
        let aiAnalysis = null;
        let domainAge = {
            available: false,
            message: "Skipped for IP address"
        };

        // Public domains only
        if (!isIPAddress(domain) && !isPrivateIP(domain)) {

            whoisInfo = await getWhoisInfo(domain);

            // SSL check only if HTTPS
            if (result.usesHTTPS) {
                sslInfo = await getSSLInfo(domain);
            }

            domainAge = await getDomainAge(domain);
            virusTotal = await checkVirusTotal(input);
            aiAnalysis = await analyzeScamText(input);
        }

        const phishingAnalysis = analyzePhishing(
            input,
            domainAge,
            result.usesHTTPS
        );

        result.whois = whoisInfo;
        result.ssl = sslInfo;
        result.domainAge = domainAge;
        result.phishing = phishingAnalysis;
        result.virusTotal = virusTotal;
        result.aiAnalysis = aiAnalysis;

        result.isSecure = result.usesHTTPS;

        // Overall Risk Score
        result.riskScore = phishingAnalysis.phishingScore;

        if (result.usesHTTPS) {
            result.message = "Secure HTTPS URL detected.";
        } else {
            result.message = "Warning: URL is not using HTTPS.";
        }

    } else {

    result.message = "Text detected.";

    const aiAnalysis = await analyzeScamText(input);

    result.aiAnalysis = aiAnalysis;

}

    return result;
};

module.exports = {
    analyzeInput
};