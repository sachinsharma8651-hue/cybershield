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
        
        // Check if date is valid
        if (isNaN(createdDate.getTime())) {
            return {
                available: false,
                message: "Invalid creation date format"
            };
        }

        const now = new Date();
        const diffTime = now - createdDate;
        
        // If date is in future or invalid difference
        if (diffTime < 0) {
            return {
                available: false,
                message: "Invalid date range"
            };
        }

        const ageInDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

        if (isNaN(ageInDays)) {
            return {
                available: false,
                message: "Could not calculate age"
            };
        }

        const ageInYears = (ageInDays / 365).toFixed(1);

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