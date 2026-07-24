const { GoogleGenAI } = require("@google/genai");

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

async function analyzeScamText(text) {
  try {
    const prompt = `
Analyze this URL/Text for potential safety threats or scams:

"${text}"

Return ONLY valid JSON matching this structure:
{
  "isScam": false,
  "risk": "Low",
  "confidence": 95,
  "reason": "Short explanation"
}
`;

    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
      config: {
        temperature: 0.2,
        maxOutputTokens: 1000, // 👈 1000 Tokens ताकि रिस्पॉन्स अधूरा न कटे
        responseMimeType: "application/json", // 👈 Gemini को Strict JSON लौटाने के लिए मजबूर करता है
      },
    });

    let output = response.text || "";

    console.log("========== GEMINI RAW RESPONSE ==========");
    console.log(output);
    console.log("=========================================");

    // Clean potential markdown tags or leftover quotes
    output = output
      .replace(/```json/gi, "")
      .replace(/```/g, "")
      .trim();

    return JSON.parse(output);

  } catch (error) {
    console.error("Gemini Error:", error);

    let message = error.message;

    try {
      const parsed = JSON.parse(error.message);
      message = parsed.error?.message || error.message;
    } catch {
      // Keep original message if it's not JSON
    }

    return {
      isScam: false,
      risk: "Unknown",
      confidence: 0,
      reason: message,
    };
  }
}

module.exports = {
  analyzeScamText,
};