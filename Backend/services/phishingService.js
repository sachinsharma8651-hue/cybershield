const phishingKeywords = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "wallet",
    "free",
    "gift",
    "bonus",
    "win",
    "claim",
    "reward",
    "paypal",
    "amazon",
    "netflix"
];

const analyzePhishing = (url, domainAge, usesHTTPS) => {

    let score = 0;
    const reasons = [];

    // HTTPS Check
    if (!usesHTTPS) {
        score += 25;
        reasons.push("Website is not using HTTPS.");
    }

    // Domain Age
    if (domainAge.available) {

        if (domainAge.ageInDays < 30) {
            score += 35;
            reasons.push("Domain is less than 30 days old.");
        }

        else if (domainAge.ageInDays < 180) {
            score += 20;
            reasons.push("Domain is less than 6 months old.");
        }

    }

    // Long URL
    if (url.length > 75) {
        score += 10;
        reasons.push("Very long URL detected.");
    }

    // IP Address
    if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
        score += 30;
        reasons.push("IP address used instead of domain.");
    }

    // @ Symbol
    if (url.includes("@")) {
        score += 20;
        reasons.push("@ symbol found in URL.");
    }

    // Suspicious Keywords
    phishingKeywords.forEach(word => {

        if (url.toLowerCase().includes(word)) {

            score += 5;
            reasons.push(`Suspicious keyword: ${word}`);

        }

    });

    if (score > 100) score = 100;

    return {
        phishingScore: score,
        isPhishing: score >= 50,
        confidence: 100 - score,
        reasons
    };

};

module.exports = {
    analyzePhishing
};