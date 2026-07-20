function isValidUrl(input) {
    try {
        new URL(input);
        return true;
    } catch (error) {
        return false;
    }
}

function extractDomain(input) {
    try {
        const url = new URL(input);
        return url.hostname;
    } catch (error) {
        return null;
    }
}

module.exports = {
    isValidUrl,
    extractDomain
};