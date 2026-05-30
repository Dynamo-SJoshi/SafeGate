# SafeGate Backend

This folder contains the SafeGate API backend.

## Current status

Minimal FastAPI skeleton with:

- a health check endpoint
- a file upload endpoint that saves files to a temporary folder and returns metadata
- a basic file fingerprinting step that compares the claimed type against the detected type
- PostgreSQL persistence for upload metadata
- a safe URL analysis endpoint with SSRF protection
- landing-page detection with candidate download-link extraction

## Run locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Set the database URL before starting the server:

```bash
set DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/postgres
```

Set the Gemini key if you want AI explanations and chat:

```bash
set GEMINI_API_KEY=YOUR_GEMINI_API_KEY
```

Optional model override:

```bash
set GEMINI_MODEL=gemini-2.5-flash
```

Start the server:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check:

```text
GET http://127.0.0.1:8000/health
```

Upload test:

```text
POST http://127.0.0.1:8000/upload
```

URL analysis test:

```text
POST http://127.0.0.1:8000/analyze-url
```

The backend will create the `uploads` table automatically on startup.

When a URL points to HTML instead of a direct file, the backend now marks it as a landing page and returns candidate download links when it can find them.

The backend can also call Gemini server-side to generate:

- a very short plain-English explanation of the technical analysis
- a short chat answer for questions related to the current analysis

Your Gemini key is read from `backend/.env` or the terminal environment. Do not put the real key in GitHub.
