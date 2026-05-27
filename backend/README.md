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
