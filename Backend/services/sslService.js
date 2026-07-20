const tls = require("tls");

const getSSLInfo = async (domain) => {
    return new Promise((resolve) => {
        const socket = tls.connect(
            {
                host: domain,
                port: 443,
                servername: domain,
                rejectUnauthorized: false
            },
            () => {
                try {
                    const cert = socket.getPeerCertificate();

                    if (!cert || Object.keys(cert).length === 0) {
                        socket.end();
                        return resolve({
                            valid: false,
                            validFrom: "Unknown",
                            validTo: "Unknown",
                            daysRemaining: 0,
                            issuer: "Unknown"
                        });
                    }

                    const validTo = new Date(cert.valid_to);
                    const daysRemaining = Math.ceil(
                        (validTo - new Date()) / (1000 * 60 * 60 * 24)
                    );

                    socket.end();

                    resolve({
                        valid: true,
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to,
                        daysRemaining,
                        issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown"
                    });
                } catch (err) {
                    socket.end();

                    resolve({
                        valid: false,
                        validFrom: "Unknown",
                        validTo: "Unknown",
                        daysRemaining: 0,
                        issuer: "Unknown"
                    });
                }
            }
        );

        socket.on("error", () => {
            resolve({
                valid: false,
                validFrom: "Unknown",
                validTo: "Unknown",
                daysRemaining: 0,
                issuer: "Unknown"
            });
        });
    });
};

module.exports = {
    getSSLInfo
};