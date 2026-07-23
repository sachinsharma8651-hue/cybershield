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
function isIPAddress(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function isPrivateIP(ip) {

    if (!isIPAddress(ip)) return false;

    return (
        ip.startsWith("10.") ||
        ip.startsWith("192.168.") ||
        /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
        ip === "127.0.0.1"
    );
}

module.exports = {
    isValidUrl,
    extractDomain,
    isIPAddress,
    isPrivateIP
};