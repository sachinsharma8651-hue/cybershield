const { getWhoisInfo } = require("./whoisService");

const getDomainAge = async (domain) => {
    try {
        const whois = await getWhoisInfo(domain);

        const created =
            whois.creationDate ||
            whois.createdDate ||
            whois.created ||
            whois.registered;

        if (!created) {
            return {
                available: false,
                message: "Creation date not found"
            };
        }

        const createdDate = new Date(created);
        const now = new Date();

        const ageInDays = Math.floor(
            (now - createdDate) / (1000 * 60 * 60 * 24)
        );

        const ageInYears = (ageInDays / 365).toFixed(1);

        let risk = "Low";

        if (ageInDays < 30) {
            risk = "Very High";
        } else if (ageInDays < 180) {
            risk = "High";
        } else if (ageInDays < 365) {
            risk = "Medium";
        }

        return {
            available: true,
            createdDate,
            ageInDays,
            ageInYears,
            risk
        };

    } catch (err) {
        return {
            available: false,
            message: err.message
        };
    }
};

module.exports = {
    getDomainAge
};