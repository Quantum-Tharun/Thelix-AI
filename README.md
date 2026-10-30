# Thelix AI — Digital Trust & Security Intelligence

A premium, enterprise-grade AI-powered cybersecurity assistant that detects scams, phishing, fake websites, malicious content, and suspicious messages using a deterministic multi-vector Risk Engine with optional LLM explanation.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite |
| Backend | Python 3.12, FastAPI, Uvicorn |
| Database | SQLite (dev) / PostgreSQL (production) |
| Auth | Supabase JWT (dev bypass in development mode) |
| AI/ML | Deterministic Risk Engine, optional Gemini LLM |
| Risk Engine | Heuristic scoring, URL static analysis, canonical normalization |
| Optional Providers | Google Safe Browsing, VirusTotal, Gemini API |

---

## Project Structure

```
Thelix-AI/
├── app/                     # FastAPI backend application
│   ├── api/v1/              # API routes: analyze, scans, health
│   ├── auth/                # Supabase JWT authentication
│   ├── ai/                  # AI service adapters (Gemini, OCR)
│   ├── services/            # Orchestrator, input detection, policy
│   ├── repositories/        # Database access layer
│   ├── schemas/             # Pydantic request/response schemas
│   ├── models/              # SQLAlchemy ORM models
│   ├── database/            # Session management
│   └── middleware/          # Rate limiting, CORS
├── risk_engine/             # Deterministic scoring engine
├── llm/                     # LLM provider abstraction (Gemini, mock)
├── ai_engineering/          # Multimodal analysis pipeline
├── frontend/                # React + TypeScript + Vite dashboard
│   └── src/
│       ├── components/      # Sidebar, TopNav, ScannerPanel, TrustScoreCard, ScanHistory, SecurityPosture
│       ├── services/api.ts  # API client (all backend calls)
│       └── types/api.ts     # TypeScript types matching backend schemas
├── tests/                   # Backend test suite (400+ tests)
├── docs/                    # Architecture documents
├── .env.example             # Environment variable template
└── thelix.db                # SQLite database (development)
```

---

## Prerequisites

- Python 3.12
- Node.js 18+ and npm
- (Optional) Gemini API key for LLM explanations
- (Optional) VirusTotal API key for threat intelligence
- (Optional) Google Safe Browsing API key

---

## Setup

### 1. Python Virtual Environment

```bash
cd "/Users/sujithss/Thelix AI 1K/Thelix-AI"

# Create virtual environment (skip if .venv already exists)
python3.12 -m venv .venv

# Activate
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and set the following (minimum required for development):

```env
ENVIRONMENT=development
DATABASE_URL=sqlite:///./thelix.db
```

Optional (for extended capabilities):

```env
GEMINI_API_KEY=your-gemini-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
SAFE_BROWSING_API_KEY=your-safe-browsing-api-key
```

> **Note**: Never commit your `.env` file. It is already in `.gitignore`.

### 3. Frontend Dependencies

```bash
cd frontend
npm install
```

---

## Starting the Application

### Start the Backend

```bash
# From the project root
.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify it is running:
```bash
curl http://127.0.0.1:8000/health
# Returns: {"status": "ok", ...}

curl http://127.0.0.1:8000/health/ready
# Returns: {"status": "ready", ...}
```

### Start the Frontend

```bash
cd frontend
npm run dev
```

Open the application: **http://localhost:5173**

---

## API Health Checks

| Endpoint | Description |
|---|---|
| `GET /health` | Liveness check |
| `GET /health/ready` | Readiness with engine versions, provider status |
| `POST /v1/analyze` | Submit URL, text, or file for trust analysis |
| `GET /v1/scans` | List recent scan history |
| `GET /v1/scans/{id}/report` | Get full report for a specific scan |

---

## Running Tests

```bash
# Run all backend tests
.venv/bin/python -m pytest tests/ -q

# Run frontend TypeScript type check
cd frontend && npx tsc --noEmit

# Run frontend production build
cd frontend && npm run build
```

**Latest test results:**
- Backend: **419 passed, 6 skipped** (includes deepfake hardening & threat-intel integration tests)
- Frontend TypeScript: **0 errors**
- Frontend build: **✓ successful**

---

## Production Build

```bash
cd frontend
npm run build
# Output in frontend/dist/
```

Serve `frontend/dist` with any static file server or integrate with the FastAPI backend.

---

## Features

### Threat Scanner
- URL and text/message analysis
- File, screenshot, and QR code upload (PNG, JPEG, WEBP, BMP, PDF)
- In-memory QR code detection and payload extraction (via OpenCV & `qrcode`)
- Contextual threat details input
- Real-time Trust Score and Risk Index display
- Verdict label, policy action, confidence, and coverage
- Analytical rationale with signal mismatch detection
- Security check breakdown
- Threat indicators and recommended safeguards

### Deepfake Detector (AI Vision)
- Dedicated synthetic media inspection console
- Image and video frame evaluation drop zone
- Format and size validation (max 10MB, 16MP decompression bomb defense)
- PyTorch architecture integration with honest prototype disclosure (`PROTOTYPE_UNAVAILABLE`) when uncalibrated model weights are unloaded
- Transparent probabilistic disclaimer (AI vision is never definitive legal proof)

### AI Architecture & Fallback Router
- **Multi-Vector Routing Policy:** Gemini API (Cloud) -> Ollama Gemma (Local Private) -> Deterministic Mock
- **Offline / Local First:** Zero cloud data exfiltration when local inference or deterministic analysis is requested
- **Isolation:** AI explanation errors or unconfigured keys never interrupt or degrade deterministic scoring verdicts

### Scan History
- Live scan records from persistent database
- Search by URL, keyword, or scan ID
- Filter by input type and status
- Full report inspection from history
- Timestamps and status badges

### Security Posture
- Real backend health and readiness data
- Engine version integrity display (Risk Engine, URL Analyzer, Normalizer, QR Decoder, Deepfake Detector)
- Active subsystem list with truthful operational status
- Multi-provider telemetry (Gemini, Ollama Gemma, VirusTotal, Safe Browsing)
- Rate limiting guard status
- Sandbox availability status
- Vector coverage breakdown from session scans

---

## Known Limitations

1. **LLM Explanations & Fallback**: The backend uses a multi-tier fallback router (Gemini Cloud → Ollama Gemma Local → Verdict-Aware Mock). The mock fallback dynamically generates explanations consistent with the deterministic Trust Score to prevent false warnings. If an external LLM contradicts deterministic scores, the frontend detects and flags the signal mismatch. The numeric Trust Score and Risk Index from the deterministic engine are always authoritative.

2. **Sandbox disabled**: `SAFE_LOCAL_SANDBOX_ENABLED=false` by default. File uploads are analyzed using static heuristics only — no live browser execution.

3. **Optional providers unconfigured**: Without `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, and `SAFE_BROWSING_API_KEY`, analysis falls back to the local deterministic engine. Set these in `.env` for enhanced coverage.

4. **OCR unavailable**: Tesseract OCR is not installed by default. Image text extraction requires `tesseract-ocr` system package.

5. **QR code analysis**: Requires the `qrcode` Python package (installed via `pip install "qrcode[pil]"`).

6. **Development auth bypass**: In `ENVIRONMENT=development`, all requests use `dev_default_user` when no Authorization header is provided. Configure `SUPABASE_JWT_SECRET` for production authentication.

7. **Rate limiting**: In-memory rate limiting does not persist across backend restarts. Use `RATE_LIMIT_STORE=redis` for production multi-worker deployments.

---

## Deployment Guide

### 1. Frontend Deployment (Vercel)
The frontend is a single-page React + TypeScript application located under `/frontend`.

- **Framework Preset**: Vite
- **Root Directory**: `frontend`
- **Build Command**: `npm run build` (or `tsc -b && vite build`)
- **Output Directory**: `dist`
- **Install Command**: `npm install`
- **Environment Variables**:
  - `VITE_API_BASE_URL`: The public HTTPS URL of your deployed backend service (e.g., `https://api.thelix.ai`). If left empty, requests default to relative paths for same-domain proxy setups.
- **Routing**: Handled via `frontend/vercel.json` SPA catch-all rewrites (`/(.*) -> /index.html`).

### 2. Backend Deployment (Docker / VPS / Cloud Run / Railway / Render)
The backend is an asynchronous FastAPI service requiring Python 3.11+, OpenCV, and optional Tesseract OCR libraries.

- **Dockerfile**: Provided at project root (`./Dockerfile`) with hardened non-root user execution (`useradd -m -u 1000 thelix`).
- **Production Startup**: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- **Environment Variables for Production**:
  - `ENVIRONMENT=production`
  - `DATABASE_URL=postgresql://user:password@host:5432/thelix_db`
  - `ALLOWED_ORIGINS=https://your-frontend-deployment.vercel.app` (Wildcard `*` is strictly blocked in production)
  - `SECRET_KEY=<generate-secure-32-char-random-key>`
  - `INTERNAL_SERVICE_TOKEN=<generate-secure-16-char-random-token>`
  - `SUPABASE_JWT_SECRET=<supabase-jwt-secret>`
  - `RATE_LIMIT_STORE=redis` & `REDIS_URL=redis://...` (for distributed deployments)
  - Optional Threat Feeds: `VIRUSTOTAL_API_KEY`, `SAFE_BROWSING_API_KEY`, `GEMINI_API_KEY`

---

## Safe Deployment Guidance

- Set `ENVIRONMENT=production` or `ENVIRONMENT=pilot`
- Configure `SUPABASE_JWT_SECRET` (required for real authentication)
- Use PostgreSQL: `DATABASE_URL=postgresql://...`
- Set `ALLOWED_ORIGINS` to only your frontend domain
- Configure `RATE_LIMIT_STORE=redis` with a real Redis URL
- Do not expose `/health/ready` publicly without authentication
- Never set `PILOT_MODE_ENABLED=false` in production without auth configured
- Keep all API keys in environment variables, never in source code

---

## Environment Variables Reference

See [`.env.example`](.env.example) for the complete reference with descriptions.

Critical variables:

| Variable | Required | Description |
|---|---|---|
| `ENVIRONMENT` | Yes | `development` \| `pilot` \| `production` |
| `DATABASE_URL` | Yes | SQLite or PostgreSQL connection string |
| `SUPABASE_JWT_SECRET` | Production | JWT signing secret for user auth |
| `GEMINI_API_KEY` | Optional | Enables Gemini LLM threat explanations |
| `OLLAMA_BASE_URL` | Optional | Local Ollama endpoint (default: `http://localhost:11434`) |
| `OLLAMA_MODEL` | Optional | Local Gemma model tag (default: `gemma:2b`) |
| `VIRUSTOTAL_API_KEY` | Optional | Enables real-time URL reputation checks |
| `SAFE_BROWSING_API_KEY` | Optional | Enables Google Safe Browsing integration |
