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

        // ===============================
// Overall Risk Score Calculation
// ===============================

let riskScore = 0;

// Phishing Heuristic
riskScore += phishingAnalysis.phishingScore;

// HTTPS
if (!result.usesHTTPS) {
    riskScore += 15;
}

// SSL
if (sslInfo && sslInfo.valid === false) {
    riskScore += 15;
}

// Domain Age
if (
    domainAge &&
    domainAge.ageInDays !== null &&
    domainAge.ageInDays < 180
) {
    riskScore += 15;
}

// VirusTotal
if (virusTotal) {
    riskScore += virusTotal.malicious * 10;
    riskScore += virusTotal.suspicious * 5;
}

// Gemini AI
if (aiAnalysis && aiAnalysis.isScam) {
    riskScore += 30;
}

// Maximum 100
riskScore = Math.min(riskScore, 100);

result.riskScore = riskScore;

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