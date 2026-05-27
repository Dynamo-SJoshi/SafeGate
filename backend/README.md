# SafeGate Backend

This folder contains the SafeGate API backend.

## Current status

Minimal FastAPI skeleton with:

- a health check endpoint
- a file upload endpoint that saves files to a temporary folder and returns metadata
- a basic file fingerprinting step that compares the claimed type against the detected type

## Run locally

Install dependencies:

```bash
pip install -r requirements.txt
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
