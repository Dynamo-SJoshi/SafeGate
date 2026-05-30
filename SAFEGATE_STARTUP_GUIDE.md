# SafeGate Startup Guide

This file explains how to start SafeGate from a fresh terminal session and how the current project pieces fit together.

I will keep this guide updated as the project workflow changes.

---

## 1. What SafeGate currently has

- Next.js frontend
- FastAPI backend
- PostgreSQL for upload metadata
- file upload fallback
- URL analysis flow
- SSRF protection for URL fetching
- landing-page detection and candidate download links
- file fingerprinting

---

## 2. Prerequisites

Make sure these are installed on the laptop:

- Git
- Node.js and npm
- Python
- PostgreSQL
- ExifTool
- FFmpeg / ffprobe
- ClamAV
- YARA
- Docker Desktop if you want Redis later

If you are using the tools from the current setup, they already exist on this machine.

---

## 3. Project folder

Open Command Prompt and go to:

```cmd
cd C:\Users\DELL\Downloads\SafeGate
```

---

## 4. Start the backend

The backend needs the Python virtual environment and the PostgreSQL connection string.

### Step 4.1: Activate the virtual environment

```cmd
.venv\Scripts\activate
```

### Step 4.2: Set PostgreSQL connection string

```cmd
set DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/postgres
```

Replace `YOUR_PASSWORD` with your real PostgreSQL password.

### Step 4.3: Install backend dependencies if needed

```cmd
python -m pip install -r backend\requirements.txt
```

### Step 4.4: Run the backend

```cmd
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

### Step 4.5: Check backend health

Open:

```text
http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok","service":"safegate-api"}
```

---

## 5. Start the frontend

Open a second Command Prompt window and go to the frontend folder:

```cmd
cd C:\Users\DELL\Downloads\SafeGate\frontend
```

Then run:

```cmd
npm run dev
```

Open the app in the browser:

```text
http://127.0.0.1:3000
```

The frontend will show:

- backend health
- link analysis form
- file upload fallback
- fingerprint summary
- candidate download links when a landing page is detected

---

## 6. How the frontend and backend connect

### Frontend health check

The frontend calls:

```text
/api/health
```

That route proxies to the backend:

```text
http://127.0.0.1:8000/health
```

### Link analysis

The frontend sends a pasted link to:

```text
/api/analyze-url
```

That proxies to the backend:

```text
http://127.0.0.1:8000/analyze-url
```

### File upload fallback

The frontend can still upload a file through:

```text
/api/upload
```

That proxies to the backend:

```text
http://127.0.0.1:8000/upload
```

---

## 7. How the URL flow works

Current URL analysis logic:

1. The user pastes a suspicious link.
2. SafeGate validates the URL for SSRF safety.
3. SafeGate fetches the page or file.
4. If the response is HTML, SafeGate marks it as a landing page.
5. SafeGate extracts candidate download links from the page.
6. If the response is a direct file, SafeGate fingerprints it.
7. SafeGate stores metadata in PostgreSQL.
8. The frontend shows the result.

Useful result states:

- `direct_file`
- `landing_page`
- `blocked_url`
- `failed_fetch`

---

## 8. How the file upload flow works

Current upload logic:

1. The user chooses a file.
2. The frontend sends it to the backend upload endpoint.
3. The backend stores the file temporarily.
4. The backend fingerprints the file.
5. The backend writes metadata to PostgreSQL.
6. The frontend displays the response.

---

## 9. PostgreSQL commands

### Open PostgreSQL shell

```cmd
psql -U postgres -d postgres
```

The password input is hidden while you type. That is normal.

### Useful commands inside `psql`

List tables:

```sql
\dt
```

Show recent SafeGate upload records:

```sql
SELECT upload_id, original_filename, size_bytes, match_status, created_at
FROM uploads
ORDER BY created_at DESC
LIMIT 5;
```

Quit PostgreSQL:

```sql
\q
```

---

## 10. GitHub workflow

When you make changes:

```cmd
git status
git add .
git commit -m "your message"
git push origin main
```

For documentation-only changes, use a commit message like:

```cmd
git commit -m "docs: update startup guide"
```

---

## 11. Common startup checklist

Before testing SafeGate:

- backend terminal is in `C:\Users\DELL\Downloads\SafeGate`
- `.venv` is activated
- `DATABASE_URL` is set in the same terminal
- `GEMINI_API_KEY` is set in the same terminal or in `backend\.env`
- backend is running on port `8000`
- frontend is running on port `3000`
- PostgreSQL service is running

---

## 12. Common errors and what they mean

### `DATABASE_URL is not set`

Set it in the backend terminal before starting `uvicorn`.

### `GEMINI_API_KEY is not set`

Set it in the backend terminal, or copy `backend\.env.example` to `backend\.env` and replace the placeholder key.

### `python-multipart` missing

Install backend dependencies again:

```cmd
python -m pip install -r backend\requirements.txt
```

### `psycopg` missing

Install backend dependencies again in the active `.venv`.

### Backend says `503` during URL analysis

Usually means PostgreSQL was not reachable or `DATABASE_URL` was missing in the backend terminal.

### Gemini explanation or chat fails

Usually means the backend cannot find `GEMINI_API_KEY`, or the Gemini API returned an error. Make sure the key is set only on your local machine.

### `Remote file exceeds the SafeGate fetch limit`

The remote file is larger than the current safe fetch limit.

---

## 13. Current development direction

SafeGate is moving toward:

- link-first analysis
- landing-page detection
- candidate download-link extraction
- automatic best-candidate following for landing pages
- safer file type validation
- better report generation
- browser extension support later

---

## 14. What to do next after the current setup

Recommended next steps:

1. Make landing-page extraction smarter for JavaScript-heavy sites.
2. Improve the candidate-link ranking logic.
3. Add automatic selection of the best candidate link when safe.
4. Add clearer verdict labels in the UI.
5. Add static analysis rules for PDFs, archives, and Office docs.

---

## 15. Latest URL flow behavior

When a pasted URL points to a landing page, SafeGate will:

1. Detect the page as a landing page.
2. Extract likely download candidates from the HTML.
3. Try the best-ranked candidate automatically.
4. If the candidate is a real file, analyze that file instead of the page.

Useful source states you may see:

- `direct_file`
- `landing_page`
- `landing_page_followed`

When `landing_page_followed` appears, the response also includes `selected_candidate_url` so you can see exactly which link SafeGate chose.

If the page exposes multiple candidates, SafeGate now also returns candidate scores and reasons so you can compare alternatives in the UI.

The preview flow is now available too:

- click `Load Safe Preview` after an upload or URL analysis
- renderable files open inline in a temporary viewer
- archives, Office packages, and binaries fall back to a safe structured summary

If a public site resolves through NAT64, SafeGate now checks the embedded IPv4 target and allows it when the real target is public.

Gemini is integrated on the backend as a private helper:

- set `GEMINI_API_KEY` in `backend\.env` or the backend terminal
- optionally set `GEMINI_MODEL=gemini-2.5-flash`
- the frontend only calls local SafeGate routes, not Gemini directly
- Gemini responses are trimmed to at most 2 lines for simple explanations
- the chat box is for related doubts about the current analysis only

This makes SafeGate better suited for download sites that do not expose the actual file directly in the first URL.
