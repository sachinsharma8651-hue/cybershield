# Cybershield Data Flow & Architecture

This diagram illustrates how data flows through the Cybershield application, from the user's input on the frontend to the orchestration of multiple micro-services on the backend.

```mermaid
graph TD
    %% Entities
    User((User))
    Frontend[Frontend UI \n (HTML/JS/CSS)]
    BackendAPI[Backend API \n (Node.js/Express)]
    DB[(MongoDB)]
    
    %% External Services
    Gemini[Google Gemini API]
    VT[VirusTotal API]
    WHOIS[WHOIS Database]
    TargetSite[Target Website \n (Port 443)]

    %% User Interaction
    User -- "Enters URL/Text\nor Uploads Image" --> Frontend
    User -- "Login/Signup" --> Frontend

    %% Auth Flow
    Frontend -- "/api/users/login \n /api/users/signup" --> BackendAPI
    BackendAPI -- "Verify/Store User" --> DB

    %% Analysis Flow (Intended Pipeline)
    Frontend -- "Submit Input \n POST /api/scan" --> BackendAPI
    
    subgraph Backend Architecture
        BackendAPI -- "Route: analyzeInput" --> ScanService{Scan Service \n (Orchestrator)}
        
        ScanService -- "If Type == Text" --> GeminiService[Gemini Service]
        
        ScanService -- "If Type == URL" --> Extract[Extract Domain]
        Extract --> ParallelExecution((Parallel Execution))
        
        ParallelExecution --> WhoisService[WHOIS Service]
        ParallelExecution --> SSLService[SSL Service]
        ParallelExecution --> VTService[VirusTotal Service]
        ParallelExecution --> GeminiService
        
        WhoisService --> DomainAge[Domain Age Service]
        DomainAge --> PhishingService[Phishing Service \n (Local Heuristics)]
    end

    %% External Calls
    WhoisService -- "Query Domain" --> WHOIS
    SSLService -- "TLS Handshake" --> TargetSite
    VTService -- "Submit URL" --> VT
    GeminiService -- "Prompt (Context/Semantics)" --> Gemini

    %% Aggregation & Response
    PhishingService --> Aggregation[Result Aggregation \n & Risk Score Calculation]
    SSLService --> Aggregation
    VTService --> Aggregation
    GeminiService --> Aggregation
    
    Aggregation -- "Compile JSON Result" --> BackendAPI
    BackendAPI -- "Return Verdict \n & Reasons" --> Frontend
    Frontend -- "Render Score & Details" --> User

    %% Styling
    classDef frontend fill:#3b82f6,stroke:#2563eb,stroke-width:2px,color:#fff;
    classDef backend fill:#10b981,stroke:#059669,stroke-width:2px,color:#fff;
    classDef database fill:#f59e0b,stroke:#d97706,stroke-width:2px,color:#fff;
    classDef external fill:#6366f1,stroke:#4f46e5,stroke-width:2px,color:#fff;
    classDef orchestrator fill:#ef4444,stroke:#dc2626,stroke-width:2px,color:#fff;

    class Frontend frontend;
    class BackendAPI,WhoisService,SSLService,VTService,GeminiService,DomainAge,PhishingService,Extract,Aggregation backend;
    class DB database;
    class Gemini,VT,WHOIS,TargetSite external;
    class ScanService orchestrator;
```

### 📝 Flow Explanation

1. **User Interaction**: The user logs in and submits a URL or Text via the Frontend UI.
2. **Authentication**: The frontend sends credentials to the backend `/api/users/login`, which verifies against **MongoDB** and returns a JWT token.
3. **Submission**: The frontend submits the target URL or text to the backend analysis endpoint. *(Note: In the current demo state, the frontend is running simulated heuristics locally, but the backend architecture is fully built to handle this).*
4. **Orchestration (`scanService.js`)**: The Backend receives the input. If it's plain text, it bypasses the URL checks and sends it directly to Gemini. If it's a URL, it extracts the domain and fires multiple micro-services in parallel.
5. **Parallel Processing**:
   - **WHOIS & Domain Age**: Queries external WHOIS registries to find the domain creation date.
   - **SSL Check**: Connects directly to the target website to verify encryption.
   - **VirusTotal**: Submits the URL to the VT API for malware checks.
   - **Gemini AI**: Sends the URL structure to Google's LLM for semantic evaluation.
6. **Heuristics**: The `phishingService` runs a mathematical point-system calculation based on the URL structure (IPs, long URLs, suspicious keywords) and the Domain Age.
7. **Aggregation**: The orchestrator waits for all services to finish, merges their individual reports, sets a final `riskScore` (0-100%), and responds to the frontend.
8. **UI Rendering**: The frontend parses the JSON response and updates the visual score bar, verdict, and the list of reasons.
