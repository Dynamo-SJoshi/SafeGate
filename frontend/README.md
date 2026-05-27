# SafeGate Frontend

This folder contains the SafeGate web app.

## Current status

Minimal Next.js frontend with:

- a landing page
- a backend health bridge
- a link analysis form that proxies to the backend URL analysis endpoint
- a file upload fallback that proxies to the backend upload endpoint

## Run locally

Install dependencies:

```bash
npm install
```

Start the dev server:

```bash
npm run dev
```

Open:

```text
http://127.0.0.1:3000
```

## Upload flow

The frontend sends links to `/api/analyze-url`, which forwards them to the backend at `http://127.0.0.1:8000/analyze-url`.

## File upload fallback

The frontend can still send files to `/api/upload`, which forwards them to the backend at `http://127.0.0.1:8000/upload`.

## Notes

- The frontend expects the backend to be available at `http://127.0.0.1:8000`
- The health check is proxied through `/api/health`
