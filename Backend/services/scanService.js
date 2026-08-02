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

    console.log("******** NEW SCAN SERVICE VERSION ********");
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
// Overall Risk Score Calculation (Updated)
// ===============================

let riskScore = 0;

// 1. Phishing Heuristic Component (Max weight: ~25)
if (phishingAnalysis && phishingAnalysis.phishingScore) {
    riskScore += Math.min(25, Math.round(phishingAnalysis.phishingScore * 0.5));
}

// 2. HTTPS Check (Max weight: 15)
if (!result.usesHTTPS) {
    riskScore += 15;
}

// 3. SSL Certificate Component (Max weight: 15)
if (sslInfo && sslInfo.valid === false) {
    riskScore += 15;
} else if (sslInfo && sslInfo.isSelfSigned) {
    riskScore += 10;
}

// 4. Domain Age Component (Max weight: 15)
if (
    domainAge &&
    domainAge.ageInDays !== null
) {
    if (domainAge.ageInDays < 30) {
        riskScore += 15;
    } else if (domainAge.ageInDays < 90) {
        riskScore += 10;
    } else if (domainAge.ageInDays < 180) {
        riskScore += 5;
    }
}

// 5. VirusTotal Component (Max weight: 20)
if (virusTotal) {
    const malicious = virusTotal.malicious || 0;
    const suspicious = virusTotal.suspicious || 0;
    if (malicious > 0) {
        riskScore += Math.min(20, 10 + (malicious * 3));
    } else if (suspicious > 0) {
        riskScore += 8;
    }
}

// 6. Gemini AI Component (Max weight: 30)
if (aiAnalysis) {
    if (aiAnalysis.isScam || aiAnalysis.risk === 'High' || aiAnalysis.risk === 'danger') {
        riskScore += 30;
    } else if (aiAnalysis.risk === 'Medium' || aiAnalysis.risk === 'warning') {
        riskScore += 15;
    }
}

// Final Bounded Clamping (Strictly between 0 and 100)
riskScore = Math.max(0, Math.min(100, Math.round(riskScore)));

result.riskScore = riskScore;

// Set dynamic verdict/secure status based on final score
result.isSecure = riskScore < 30;

        if (result.usesHTTPS) {
            result.message = "Secure HTTPS URL detected.";
        } else {
            result.message = "Warning: URL is not using HTTPS.";
        }

   } else {

    result.message = "Text detected.";

    const aiAnalysis = await analyzeScamText(input);

    result.aiAnalysis = aiAnalysis;

    // --------------------------
    // OCR / Text Risk Calculation
    // --------------------------
    let riskScore = 0;

    if (aiAnalysis) {

        if (aiAnalysis.isScam) {

            switch ((aiAnalysis.risk || "").toLowerCase()) {

                case "high":
                    riskScore = 90;
                    break;

                case "medium":
                    riskScore = 60;
                    break;

                case "low":
                    riskScore = 30;
                    break;

                default:
                    riskScore = aiAnalysis.confidence || 70;
            }

            // confidence ke hisaab se adjust
            if (aiAnalysis.confidence) {
                riskScore = Math.max(
                    riskScore,
                    Math.min(aiAnalysis.confidence, 100)
                );
            }

        } else {

            riskScore = Math.max(
                5,
                aiAnalysis.confidence
                    ? Math.round((100 - aiAnalysis.confidence) / 8)
                    : 5
            );

        }

    }

    result.riskScore = Math.min(riskScore, 100);

    result.isSecure = !aiAnalysis?.isScam;
}

    return result;
};

module.exports = {
    analyzeInput
};