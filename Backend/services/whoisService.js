const whois = require("whois-json");

const getWhoisInfo = async (domain) => {
    try {
        const result = await whois(domain);

        return {
            registrar: result.registrar || "Unknown",
            creationDate: result.creationDate || result.created || "Unknown",
            expirationDate: result.registryExpiryDate || result.expirationDate || "Unknown",
            country: result.country || "Unknown",
            organization: result.org || result.organization || "Unknown"
        };

    } catch (error) {

        return {
            registrar: "Unknown",
            creationDate: "Unknown",
            expirationDate: "Unknown",
            country: "Unknown",
            organization: "Unknown"
        };

    }
};

module.exports = {
    getWhoisInfo
};