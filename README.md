# CatchThePhish Browser Extension
Protecting Singaporeans from rising digital threats like scams, phishing, and impersonation.  
This browser extension provides real-time scam detection, AI-powered phishing text analysis, and one-click scam reporting, designed especially for busy working adults (30–49 years old), the demographic most frequently targeted by phishing attacks.

## Features

* **URL Reputation Detection**
  * Scans links on hover, copy, or paste.
  * Detects typosquatting, suspicious domains, and newly registered sites.
  * Cross-checks with VirusTotal API for authoritative verdicts.

* **AI-Powered Phishing Text Detection**
  * Flags scammy content with impersonation cues and urgency signals.
  * Identifies AI-generated or suspiciously persuasive text using HuggingFace models.

* **Crowd Reporting**
  * One-click export of suspicious site details into JSON format.
  * Designed for future integration with ScamShield / SPF reporting pipelines.

* **Educational Tips**
  * Each pop-up includes bite-sized anti-scam tips.
  * Rotates tips to prevent fatigue, reinforcing digital literacy.


## Folder Structure

```
catch-the-phish/
├── demo/
│   ├── test-phishing-page.html   # Sample phishing webpage for testing
│   ├── demo-launcher.html
│   ├── singapore-phishing-demo.html
│   ├── banking-phishing-demo.html
│   └── demo-test-urls.txt        # List of test URLs
├── extension/                    # Browser extension frontend
│   ├── icons/
│   ├── popup/
│   ├── styles/
│   ├── utils/
│   ├── background.js
│   ├── content.js
│   └── manifest.json
├── backend/                      # FastAPI backend
│   ├── src/
│   │   ├── router/
│   │   ├── services/
│   │   ├── models/
│   │   ├── config/
│   │   └── main.py
│   ├── Dockerfile
│   └── requirements.txt
├── docker-compose.yml
├── .env.example
└── README.md
````

## Setup & Installation

### 1. Backend (FastAPI)

#### Clone the repository:
```bash
git clone https://github.com/yourusername/catch-the-phish.git
cd catch-the-phish
````

#### Environment Setup:
Copy .env.example into .env and configure API keys:
```bash
cp .env.example .env
```

#### Build and run with Docker Compose:

```bash
docker compose build
docker compose up
```

The backend will start at:
[http://127.0.0.1:8000](http://127.0.0.1:8000)

### 2. Browser Extension

1. Open **Google Chrome**.
2. Go to `chrome://extensions/`.
3. Enable **Developer Mode**.
4. Click **Load Unpacked** and select the `extension/` folder.
5. The extension icon will appear in your browser toolbar.

### 3. Testing

#### Open Demo Page

* Open [http://localhost:3000/demo-launcher.html](http://localhost:3000/demo-launcher.html) in Chrome.
* Open Demo Sites: Click the demo links below to open different phishing scenarios
* Test Features:
  * Click "Scan This Website" button to test comprehensive page analysis
  * Select suspicious text and right-click to test text analysis
  * Hover over suspicious links to test URL detection
* Observe Results: Check if the extension correctly identifies threats and provides warnings
* Compare: Test on legitimate sites to ensure no false positives

#### Expected Behaviours

* **Suspicious URL** → Warning pop-up (e.g., “⚠️ Suspicious URL Detected”).
* **Phishing text** → Select suspicious text and right-click to test text analysis
* **Report button** → JSON payload of scam details displayed/exported.
* **Educational tip** → Short advice included in warning pop-up.

## Tech Stack

* **Frontend**: Chrome Extension (HTML, CSS, JavaScript)
* **Backend**: FastAPI (Python), VirusTotal API integration, Docker
* **AI / Detection**: Rule-based heuristics + Hugging Face models for AI-powered phishing text classification
* **Demo Tools**: Test phishing page, curated phishing URLs

## API Endpoints

### 1. Analyze URL

**Endpoint:** `POST /url-analysis/analyze-url`

Analyzes type of suspicious URL.

Request:

```json
{
  "url": "http://phishy-example.com",
  "confidence": 0.7,
  "reason": "typo_detected"
}
```

Response:

```json
{
  "suspicious": true,
  "confidence": 0.9,
  "reason": "Server Confirmed: Domain appears to impersonate a legitimate website through typosquatting",
  "type": "typo"
}
```

### 2. Scan Page

**Endpoint:** `POST /url-analysis/scan-page`

Scans page for suspicious URLs.

Request:

```json
{
  "page_url": "http://fakebank-login.com",
  "extracted_links": ["http://fakebank-login.com/reset", "http://example.com"]
}
```

Response:

```json
{
  "success": true,
  "is_suspicious": true,
  "confidence": 0.8,
  "reason": "High risk detected - found 1 suspicious links",
  "links_scanned": 2,
  "suspicious_links_found": 1,
  "suspicious_links": [
    {
      "url": "http://fakebank-login.com/reset",
      "reason": "Domain mimics known bank"
    }
  ],
  "scan_summary": "Scanned 2 links, found 1 suspicious"
}
```

### 3. Analyze Text

**Endpoint:** `POST /text-analysis/analyze-text`

Analyze a single text snippet for phishing risks.

Request:

```json
{
  "text": "Dear user, your bank account has been locked. Click here to reset."
}
```

Response:

```json
{
  "suspicious": true,
  "confidence": 0.85,
  "reason": "Detected impersonation and urgency in the message"
}
```

### 4. Analyze Page Text (Chunks)

**Endpoint:** `POST /text-analysis/analyze-page-text`

Analyze multiple text chunks from a webpage.

Request:

```json
{
  "chunks": [
    "Welcome to DBS login portal.",
    "Your account is locked. Reset now to avoid suspension."
  ]
}
```

Response:

```json
{
  "overall_suspicious": true,
  "confidence": 0.9,
  "reasons": [
    "Chunk 2 contains urgency and impersonation"
  ]
}
```

## Demo Video

[YouTube Link – insert here after recording](https://youtube.com)

## Future Development

* Multilingual support (Mandarin, Malay, Tamil).
* Self-improving AI pipeline with crowdsourced scam reports.
* Expansion to detect AI-generated images, voice, and video scams.
* Integration with ScamShield & SPF reporting systems.

## Team

* Sean Elisha Koh Tze Li (Leader)
* Loo Zhi Yi
* Eiffel Chong Shiang Yih
* Ryan Soh Jing Zhi
* Yong Yuan Qi
* Lim Yixuan
