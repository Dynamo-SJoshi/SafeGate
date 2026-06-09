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
- Asynchronous background worker queue for scans
- YARA scanning with rules for PDFs, macros, webshells, and PowerShell
- Dynamic sandboxing inside isolated read-only Python containers

---

## 2. Quick Start with Docker (Recommended)

Now that SafeGate has been dockerized, you can start both the backend and frontend services with a single command. **Running under Docker is highly recommended** since the dynamic sandbox requires mounting the host's `/var/run/docker.sock` to execute isolated script containers.

### Steps
1. Make sure **Docker Desktop** is open and running on your machine.
2. Open a terminal/Command Prompt and go to the project root:
   ```cmd
   cd C:\Users\DELL\Downloads\SafeGate
   ```
3. Start the containers using:
   ```cmd
   docker compose up --build
   ```
   *(Note: You can omit `--build` on subsequent runs unless you have changed dependencies or configuration files. If you prefer to run in the background/detached mode, run `docker compose up -d`)*

### Accessing the Applications
* **Frontend**: Open `http://localhost:3000` in your browser.
* **Backend Health**: Open `http://localhost:8000/health` (should return `{"status":"ok","service":"safegate-api"}`).

### Stopping the Services
To stop the services and remove the containers, run:
```cmd
docker compose down
```

---

## 3. Prerequisites (For running locally without Docker)

Make sure these are installed on the laptop if you choose to run outside of containers:

- Git
- Node.js and npm
- Python
- PostgreSQL
- ExifTool
- FFmpeg / ffprobe
- ClamAV
- YARA

If you are using the tools from the current setup, they already exist on this machine.

---

## 4. Running Locally without Docker

If you prefer to run the services individually on your host machine instead of using Docker, follow these steps:

### Step 4.1: Open the Project folder
Open Command Prompt and go to:
```cmd
cd C:\Users\DELL\Downloads\SafeGate
```

### Step 4.2: Start the Backend
1. **Activate the virtual environment**:
   ```cmd
   .venv\Scripts\activate
   ```
2. **Set PostgreSQL connection string**:
   ```cmd
   set DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/postgres
   ```
   *(Replace `YOUR_PASSWORD` with your real PostgreSQL password)*
3. **Install backend dependencies if needed**:
   ```cmd
   python -m pip install -r backend\requirements.txt
   ```
4. **Run the backend**:
   ```cmd
   uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```

### Step 4.3: Start the Frontend
Open a second Command Prompt window and run:
```cmd
cd C:\Users\DELL\Downloads\SafeGate\frontend
npm run dev
```

The frontend will show:
- backend health
- link analysis form
- file upload fallback
- fingerprint summary
- candidate download links when a landing page is detected

---

## 5. How the frontend and backend connect

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

## 6. How the URL flow works

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

## 7. How the file upload flow works

Current upload logic:

1. The user chooses a file.
2. The frontend sends it to the backend upload endpoint.
3. The backend stores the file temporarily.
4. The backend fingerprints the file.
5. The backend writes metadata to PostgreSQL.
6. The frontend displays the response.

---

## 8. PostgreSQL commands

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

## 9. GitHub workflow

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

## 10. Common startup checklist

Before testing SafeGate:

- backend terminal is in `C:\Users\DELL\Downloads\SafeGate`
- `.venv` is activated
- `DATABASE_URL` is set in the same terminal
- `GEMINI_API_KEY` is set in the same terminal or in `backend\.env`
- backend is running on port `8000`
- frontend is running on port `3000`
- PostgreSQL service is running

---

## 11. Common errors and what they mean

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

## 12. Current development direction

SafeGate is moving toward:

- link-first analysis
- landing-page detection
- candidate download-link extraction
- automatic best-candidate following for landing pages
- safer file type validation
- better report generation
- browser extension support later

---

## 13. What to do next after the current setup

Recommended next steps:

1. Make landing-page extraction smarter for JavaScript-heavy sites.
2. Improve the candidate-link ranking logic.
3. Add automatic selection of the best candidate link when safe.
4. Add clearer verdict labels in the UI.
5. Add static analysis rules for PDFs, archives, and Office docs.

---

## 14. Latest URL flow behavior

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
- Gemini responses are formatted as two clear lines using `Summary:` and `Advice:`
- the chat box is for related doubts about the current analysis only
- if Gemini reports high demand or a transient failure, SafeGate retries briefly and then falls back to a local SafeGate summary so the panel still works
- **Persistent chat on failure**: If a scan or fetching fails, the chatbot stays visible and Gemini parses the error details to explain why it failed.

Asynchronous scanning and sandboxing details:
- **Async Queue**: Uploads and link analyses return a `PENDING` state instantly. A resident FastAPI task processes scans (ClamAV, YARA, ExifTool, Sandbox) in the background. The Next.js frontend automatically polls the backend every 2 seconds to refresh details.
- **Dynamic Sandbox**: Python (`.py`) scripts are copied to a host-shared directory and executed inside a read-only `python:3.10-slim` container with no network access and strict resources limits. It flags file system write attempts or connection attempts and reports them back.
- **ClamAV Timeout**: If ClamAV times out or is offline, it displays `TIMEOUT` or `UNAVAILABLE` gracefully in the UI.

This makes SafeGate a full-featured asynchronous scan analysis platform.
