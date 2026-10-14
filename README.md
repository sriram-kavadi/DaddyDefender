# Threat Check — AI-Powered Digital Threat Detection & Digital Trust Platform

A full-stack cybersecurity application that inspects URLs, messages, and suspicious online activities for phishing, scam, and social engineering indicators. Threat Check evaluates structural and linguistic threat patterns, correlates them with live threat intelligence feeds, assigns evidence-based risk scores, and provides plain-language safety recommendations.

---

## Architecture Overview

Threat Check features a dual-mode hybrid architecture:

1. **Backend Engine (FastAPI + SQLite + Threat Intelligence):**
   - **FastAPI REST API**: Endpoints for URL and message analysis, persistent scan history, aggregate statistics, and system health.
   - **Analysis Engine**: Heuristic detection rules, PSL-aware domain decomposition (`tldextract`), brand impersonation detection (Levenshtein distance & look-alikes), and social engineering linguistic analysis.
   - **Threat Intelligence Abstraction**: Live correlation against **URLhaus** (abuse.ch malware URL database) and **VirusTotal** API with in-memory caching and graceful degradation.
   - **Centralized Scoring & Classification**: Evidence-based risk scoring (0–100), severity levels (`Low`, `Moderate`, `High`, `Critical`), threat classifications (`Phishing`, `Scam`, `Suspicious`, `No Significant Threat`), confidence explanations, and actionable precautions.
   - **Async SQLite Persistence**: Persists scan history, metrics, and aggregate stats via `aiosqlite`.
   - **Security**: Rate limiting via SlowAPI, strict input validation via Pydantic v2 schemas, CORS protection, and secure server-side API key handling.

2. **Frontend Client (HTML5 / Vanilla CSS / Vanilla JS):**
   - Zero-dependency, lightweight, accessible UI.
   - Dual-mode operation: Automatically connects to the FastAPI backend with live threat intel and persistent history; seamlessly falls back to local client-side `analyzer.js` heuristics if offline.
   - Real-time engine health indicator, loading feedback, interactive metric cards, severity chips, threat intelligence provider status, and persistent SQLite scan history viewer.

---

## Project Structure

```
threat-check/
├── index.html                   # Main Analyzer UI
├── privacy.html                 # Privacy policy (documents local & API modes)
├── terms.html                   # Terms & conditions
├── styles.css                   # Responsive typography-focused stylesheet
├── app.js                       # UI controller, API client, & fallback logic
├── analyzer.js                  # Client-side heuristic detection engine
├── tests/
│   └── analyzer.test.js         # Node.js test suite for client heuristics
└── backend/
    ├── requirements.txt         # Python dependencies
    ├── .env.example             # Configuration template
    ├── main.py                  # FastAPI application entry point
    ├── models.py                # Pydantic v2 schemas & domain models
    ├── database.py              # Async SQLite persistence layer (aiosqlite)
    ├── analysis/
    │   ├── __init__.py
    │   ├── url_analyzer.py      # Lexical, structural & brand impersonation engine
    │   ├── message_analyzer.py  # Social engineering & embedded link extraction
    │   ├── scoring.py           # Unified risk assessment, classification & recommendations
    │   └── threat_intel.py      # VirusTotal & URLhaus integration with caching
    ├── routes/
    │   ├── __init__.py
    │   ├── analyze.py           # POST /api/analyze/url, POST /api/analyze/message
    │   ├── scans.py             # GET /api/scans, GET /api/scans/{id}, DELETE, /stats
    │   └── health.py            # GET /api/health
    └── tests/
        ├── __init__.py
        ├── test_url_analyzer.py     # Python URL analyzer unit tests
        ├── test_message_analyzer.py # Python message analyzer unit tests
        ├── test_scoring.py          # Unified scoring engine tests
        ├── test_threat_intel.py     # Threat intel provider abstraction tests
        ├── test_database.py         # SQLite CRUD & aggregation tests
        └── test_api.py              # FastAPI integration & route tests
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check & threat intel provider availability |
| `POST` | `/api/analyze/url` | Submit a URL for passive heuristic & threat intel analysis |
| `POST` | `/api/analyze/message` | Submit message text for social engineering & link analysis |
| `GET` | `/api/scans` | Retrieve recent scans (supports `limit` and `offset`) |
| `GET` | `/api/scans/{scan_id}` | Retrieve full details of a specific scan |
| `DELETE` | `/api/scans/{scan_id}` | Delete a scan record from the database |
| `GET` | `/api/scans/stats` | Aggregate metrics (total scans, average score, risk levels) |
| `GET` | `/api/docs` | Interactive Swagger / OpenAPI documentation |

---

## Getting Started

### Prerequisites

- Python 3.10+ (for the backend)
- Node.js (optional, for client unit tests)

### Backend Setup

1. Navigate to the backend directory and set up a virtual environment:
   ```bash
   cd backend
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   *(Optional)* Add your `VIRUSTOTAL_API_KEY` in `.env` to enable VirusTotal lookups. URLhaus works automatically without an API key.

4. Start the backend server:
   ```bash
   uvicorn main:app --reload --port 8000
   ```
   The API will be available at `http://localhost:8000` with Swagger docs at `http://localhost:8000/api/docs`.

### Running the Frontend

Open `index.html` in your browser or serve it using any HTTP server:
```bash
# Example using Python:
python -m http.server 5500
```
Then visit `http://localhost:5500`. The frontend will automatically detect the backend on `http://localhost:8000`. If the backend is stopped, it gracefully continues in client-side mode.

---

## Running Tests

### Backend Test Suite (Pytest)
From the repository root or `backend/`:
```bash
pytest backend/tests/ -v
```
Covers:
- `test_url_analyzer.py`: URL parsing, homoglyphs, brand imitations, and risky TLDs.
- `test_message_analyzer.py`: Linguistic rules, negation context, embedded link isolation.
- `test_scoring.py`: Scoring thresholds, threat classifications, and recommendations.
- `test_threat_intel.py`: In-memory TTL caching, disabled provider fallbacks.
- `test_database.py`: Async SQLite schema creation, CRUD operations, and aggregate queries.
- `test_api.py`: FastAPI endpoints, validation rules, 400/404/422 responses.

### Frontend Test Suite (Node.js)
```bash
node tests/analyzer.test.js
```

---

## Threat Detection Capabilities

### In URLs:
- **Protocol**: Missing HTTPS / plain HTTP warnings.
- **Host**: Raw IP address hosts (IPv4 & IPv6), username embedding (`@` trick).
- **Domain**: Homoglyph look-alike substitution, brand imitation via Levenshtein distance, excessive subdomains/hyphens, risky TLDs (`.xyz`, `.top`, `.zip`, etc.).
- **Path & Query**: Phishing keywords, embedded redirect parameters, heavy percent-encoding, executable file downloads (`.exe`, `.scr`, `.bat`).

### In Messages:
- **Urgency & Pressure**: Deadlines, immediate action warnings, final notices.
- **Account Threats**: Account suspension, legal actions, unauthorized activity alerts.
- **Credential Harvesting**: Passwords, OTPs, PINs, card numbers, identity requests (with negation handling to avoid flagging security awareness tips).
- **Fraud & Scams**: Unsolicited lottery/crypto prizes, wire transfers, upfront fees, gift card demands.
- **Brand Mismatch**: Messages claiming to represent a brand while containing links pointing to unauthorized domains.
- **Per-Link Deep Inspection**: Every URL in a message is independently extracted and analyzed.
"# DaddyDefender" 
