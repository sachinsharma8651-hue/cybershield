const axios = require("axios");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const checkVirusTotal = async (url) => {
    const API_KEY = process.env.VIRUSTOTAL_API_KEY;

    console.log("VirusTotal API Key:", API_KEY);

    if (!API_KEY) {
        return {
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            error: true,
            message: "VirusTotal API Key not found"
        };
    }

    try {
        // Step 1: Submit URL
        const submitResponse = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            new URLSearchParams({ url }),
            {
                headers: {
                    "x-apikey": API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            }
        );

        const analysisId = submitResponse.data.data.id;
        console.log("Analysis ID:", analysisId);

        let analysisResponse;

        // Step 2: Poll until completed
        for (let i = 1; i <= 10; i++) {
            console.log(`Checking VirusTotal... Attempt ${i}`);

            await sleep(2000);

            analysisResponse = await axios.get(
                `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
                {
                    headers: {
                        "x-apikey": API_KEY
                    }
                }
            );

            const status = analysisResponse.data.data.attributes.status;

            console.log("Status:", status);

            if (status === "completed") {
                break;
            }
        }

        const attributes = analysisResponse.data.data.attributes;
        const stats = attributes.stats;

        console.log("Final VirusTotal Stats:", stats);

        return {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0
        };

    } catch (error) {
        console.log("========== VirusTotal ERROR ==========");
        console.log(error.response?.data || error.message);
        console.log("======================================");

        return {
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            error: true,
            message: error.response?.data || error.message
        };
    }
};

module.exports = {
    checkVirusTotal
};