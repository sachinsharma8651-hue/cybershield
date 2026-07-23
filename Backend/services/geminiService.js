const { GoogleGenAI } = require("@google/genai");

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

async function analyzeScamText(text) {
  try {
    const prompt = `
Analyze this URL:

${text}

Return ONLY JSON:

{
  "isScam": false,
  "risk": "Low",
  "confidence": 95,
  "reason": "Short reason"
}
`;
   const response = await ai.models.generateContent({
  model: "gemini-3-flash-preview",
  contents: prompt,
  config: {
    temperature: 0.2,
    maxOutputTokens: 300,
  },
});

    let output = response.text || "";

    // Remove markdown code fences if present
    output = output
      .replace(/```json/gi, "")
      .replace(/```/g, "")
      .trim();
      console.log("========== GEMINI RAW RESPONSE ==========");
console.log(output);
console.log("=========================================");

    return JSON.parse(output);

  } catch (error) {
  console.error("Gemini Error:", error);

  let message = error.message;

  try {
    const parsed = JSON.parse(error.message);
    message = parsed.error?.message || error.message;
  } catch {
    // अगर error.message JSON नहीं है,
    // तो original message ही use होगा
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