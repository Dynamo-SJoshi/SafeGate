# SafeGate Frontend

This folder contains the SafeGate web app.

## Current status

Minimal Next.js frontend with a landing page and backend health bridge.

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

## Notes

- The frontend expects the backend to be available at `http://127.0.0.1:8000`
- The health check is proxied through `/api/health`

