# Cybershield 🛡️

Cybershield is an intelligent, multi-layered threat detection web application designed to analyze URLs and text for potential phishing, scams, and malicious activities. It utilizes a combination of local heuristics, external APIs, and artificial intelligence to provide a comprehensive risk assessment.

## 🚀 Features

- **Multi-Modal Analysis**: Analyze raw text, suspicious URLs, and (simulated) screenshot uploads for malicious intent.
- **AI-Powered Heuristics**: Leverages Google's Gemini AI (`gemini-3-flash-preview`) to understand the context and urgency of text-based scams.
- **Deep URL Inspection**:
  - **VirusTotal Integration**: Scans URLs against dozens of industry-standard anti-virus engines.
  - **Domain Age & WHOIS**: Detects newly registered domains commonly used in hit-and-run phishing campaigns.
  - **SSL Certificate Verification**: Validates the security and issuer of the website's TLS/SSL certificate.
  - **Local Heuristics**: Fast, mathematical checks for IP-based domains, missing HTTPS, suspicious keywords, and risky TLDs.
- **User Authentication**: Secure sign-up and login functionality with JWT and MongoDB.
- **Interactive UI**: A modern, responsive frontend with a detailed breakdown of the risk score, verdict, and the specific reasons behind the assessment.

## 🏗️ Project Structure

The project is divided into a decoupled Frontend and Backend architecture.

```text
cybershield/
│
├── Backend/                 # Node.js / Express API
│   ├── config/              # Database (MongoDB) configuration
│   ├── controllers/         # Route controllers (Auth, Analysis)
│   ├── middleware/          # JWT Auth Middleware
│   ├── models/              # Mongoose Data Models (User, etc.)
│   ├── routes/              # Express API Routes
│   ├── services/            # Core analysis engines (Gemini, VirusTotal, WHOIS, etc.)
│   ├── server.js            # Main backend entry point
│   └── .env                 # Backend environment variables
│
└── Frontend/                # Vanilla HTML/CSS/JS Application
    ├── index.html           # Main UI layout
    ├── style.css            # Custom styling
    └── app.js               # Frontend logic and API integration
```

## 💻 Technology Stack

- **Frontend**: Vanilla HTML5, CSS3, Vanilla JavaScript.
- **Backend**: Node.js, Express.js
- **Database**: MongoDB (Mongoose)
- **External APIs**: 
  - Google Gemini API (`@google/genai`)
  - VirusTotal API (v3)
  - `whois-json` for Domain data
  - Native Node.js `tls` for SSL checks

## ⚙️ Installation & Setup

### Prerequisites
- Node.js (v18+ recommended)
- MongoDB (Local or Atlas URI)
- API Keys for Google Gemini and VirusTotal

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd cybershield
```

### 2. Backend Setup
Navigate to the backend directory and install dependencies:
```bash
cd Backend
npm install
```

Create a `.env` file in the `Backend/` directory with the following variables:
```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_super_secret_jwt_key
GEMINI_API_KEY=your_google_gemini_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Start the backend server:
```bash
npm run dev
# The server will start on http://localhost:5000
```

### 3. Frontend Setup
The frontend is a static web application and does not require building. You can serve it using any static file server.

If you have Node installed, you can use `serve`:
```bash
cd ../Frontend
npx serve -l 3000
```
Open your browser and navigate to `http://localhost:3000`.

*(Note: The frontend expects the backend API to be running on `http://localhost:5000`. If you change the backend port, update the `API_BASE` variable in `Frontend/app.js`)*

## 🛡️ How the Analysis Works (The Pipeline)

When a user submits a URL for analysis, the **Scan Service Orchestrator** kicks in and runs the following checks in parallel:
1. **Phishing Service**: Runs local regex rules on the URL string.
2. **WHOIS & Domain Age**: Checks who registered the domain and flags it if it's less than 30-180 days old.
3. **SSL Service**: Connects to Port 443 to verify encryption standards.
4. **VirusTotal Service**: Submits the URL to external security vendors for a known-malware check.
5. **Gemini Service**: Passes the URL/Text to AI to evaluate semantic intent (e.g., "Does this text sound like a scam?").

All results are compiled into a final `riskScore` (0-100%) and sent to the frontend UI.
