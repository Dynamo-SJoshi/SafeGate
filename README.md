# SafeGate

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14%2B-blue.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-Active-red.svg)](https://redis.io/)
[![Gemini](https://img.shields.io/badge/Gemini%20AI-Integrated-orange.svg)](https://deepmind.google/technologies/gemini/)

SafeGate is a browser-assisted, cloud-based safe download and file inspection platform. It allows users to intercept, inspect, and safely preview suspicious files and remote download links inside disposable, resource-constrained, and network-isolated cloud environments before saving them locally.

**Philosophy:** *Inspect first, preview safely, and decide with confidence.*

---

## Protected Threat Vectors & Malware Safeguards

SafeGate provides active protection against modern malware delivery mechanisms:

1. **Extension Spoofing & Double Extension Masquerading:** Blocks renaming execution threats (e.g. `invoice.pdf.exe` or `backup.txt.bat`) by validating real magic bytes, MIME types, and header structures.
2. **Directory Traversal (Zip Slip):** Statically inspects zip and compressed archive file listing trees for relative segments (`..` or leading `/`) designed to overwrite system files upon extraction.
3. **Denial of Service (Zip Bombs):** Inspects zip headers in-memory prior to extraction, instantly rejecting decompression ratios exceeding `100:1` or file size thresholds to prevent server storage depletion.
4. **Phishing & Credential-Harvesting Sites:** Playwright-based dynamic scans headlessly inspect HTML documents for phishing inputs, auto-redirections, suspicious external form post actions, and code obfuscations.
5. **Fileless Malware & Memory Injection:** Analyzes script payloads and binaries statically using custom YARA rules to detect Win32 API calls (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`) commonly used in memory injection and code detonation techniques.
6. **Trojan Horses & Signature Exploits:** Standard signatures are scanned instantly via a local ClamAV antivirus engine.
7. **Sandbox Escape Hazards:** The dynamic execution sandbox applies memory limits (128 MB RAM), strict CPU cap limits (0.5 CPUs), read-only root filesystems, and cuts off all outbound network sockets (`none`).

---

## Core System Features

* **Multi-Layer Static Analysis Pipeline:** Evaluates files through ClamAV, a custom compiled YARA rules engine (configured in `analyzers/rules.yar`), and ExifTool metadata parsing.
* **Disposable Sandbox Detonation:** Supports multi-language script execution inside clean Docker containers:
  * **Python (`.py`):** Runs inside `python:3.10-slim`.
  * **PowerShell (`.ps1`):** Runs inside `powershell:lts-alpine` with 256 MB RAM to prevent dotnet CoreCLR crashes.
  * **JavaScript/Node (`.js`):** Runs inside `node:18-alpine`.
  * **Shell Script (`.sh`):** Runs inside `alpine:latest`.
  * **Web Pages (`.html`):** Detonated inside Playwright browser containers to extract script links and warn of credential theft layouts.
* **Interactive Archive Explorer:** Traverses, structures, and browses nested folders inside `.zip`, `.tar`, `.gz`, `.war`, `.jar`, and `.7z` files on-demand. Scan results of inner files propagate automatically to update the parent archive status.
* **Timezone-Aware PDF Reports:** Compiles deterministic reports featuring executive layman-friendly summaries, static scanners checkmarks, and 5-axis Radar Risk Vector charts generated via QuickChart and printed using WeasyPrint. Reports adapt to the user's browser timezone dynamically.
* **Gemini AI Explanation Assistant:** Powered by Gemini, generating short, contextual 2-line layperson explanations for analysis logs and active chat windows for uploaded files and nested archive items.
* **Service Portability & Toggles:** Supports running in lightweight environments using `ENABLE_CLAMAV=false` and `ENABLE_SANDBOX=false` toggles, falling back natively to static checks.

---

## Complete Workflow Architecture

The diagram below maps the complete lifecycle of a file upload or remote URL inspection:

```mermaid
flowchart TD
    subgraph Client ["Next.js Frontend Client"]
        A[User Input] -->|Direct File Upload| B(Upload Form)
        A -->|Remote link| C(URL input)
        B -->|POST /upload| API
        C -->|POST /analyze-url| API
        
        Dashboard[Interactive Dashboard]
        Dashboard -->|Load Safe Preview| PreviewAPI[Next.js API /api/preview]
        Dashboard -->|AI Explanations| GeminiAPI[Next.js API /api/ai/explain]
        Dashboard -->|Download PDF Report| ReportAPI[Next.js API /api/report/:id/pdf]
    end

    subgraph ServiceLayer ["FastAPI Service Layer"]
        API[FastAPI Backend Gateway] -->|Log Request IP & Metadata| DB[(PostgreSQL Database)]
        API -->|Enqueue upload_id| Queue[Redis RQ Task Queue]
        
        API -->|GET /report/:id/pdf| Weasy[WeasyPrint PDF Generator]
        Weasy -->|Calculate 5-vector Risk Score| Radar[QuickChart Radar API]
    end

    subgraph WorkerLayer ["Redis Background Worker"]
        Queue -->|Fetch Job| Worker[workers/worker.py]
        Worker -->|Remote URL Fetching| Fetcher[url_fetching.py]
        Fetcher -->|Landing Page Extractor| Candidate[Candidate Scorer & Follower]
        
        Worker -->|Run Verification Checks| Fingerprint[fingerprinting.py]
        Fingerprint -->|Checks| BOM[BOM Signatures Check]
        Fingerprint -->|Checks| DblExt[Double Extension Spoofing Check]
        Fingerprint -->|Checks| ZipBomb[Zip Bomb In-Memory Ratio Check]
        
        Worker -->|Static Inspections| StaticScanners
        subgraph StaticScanners ["Static Analysis Engines"]
            ClamAV[ClamAV daemon scan TCP]
            YARA[YARA Compiler & Rules Engine]
            ExifTool[ExifTool Process Extractor]
        end
        
        YARA -->|Rule Matches| MemInjRules[Memory Injection Heuristics]
        Fingerprint -->|Archives .zip, .7z, .tar, .gz, .war, .jar| ZipSlip[Zip Slip Directory Traversal Check]
        
        Worker -->|Dynamic Sandboxing| Sandbox[sandbox_runner.py]
        subgraph SandboxSection ["Dynamic Sandbox Detonation"]
            DockerSocket[Docker UNIX Socket /var/run/docker.sock] -->|Create Container| Container[Ephemeral Container]
            Container -->|Python .py| Python[python:3.10-slim]
            Container -->|PowerShell .ps1| PS[powershell:lts-alpine]
            Container -->|NodeJS .js| Node[node:18-alpine]
            Container -->|Bash .sh| Bash[alpine:latest]
            Container -->|Phishing HTML| Playwright[Playwright Browser Container]
            
            ContainerConfig[Strict Caps: 128MB RAM, 0.5 CPU, read-only rootfs, Network None, tmpfs mount] --> Container
        end
        
        Worker -->|Propagate Inner Threat Verdicts| DB
        Worker -->|Sanitize Log Null Bytes & Update Record| DB
    end
    
    subgraph AILayer ["Gemini AI Explanation"]
        GeminiAPI -->|POST /gemini/explain| GeminiBackend[FastAPI Gemini Helper]
        GeminiBackend -->|Explain / Chat| GeminiAPIKey[Gemini API Key]
    end

    PreviewAPI -->|Request file stream| API
    ReportAPI -->|Forward query with local timezone| API
```

---

## Local Setup & Installation

### Docker Compose (Recommended Setup)

To spin up all services—including ClamAV, Redis, PostgreSQL, the background worker, Next.js frontend, and dynamic sandbox container controllers—use the bundled Docker Compose:

1. Clone the repository and navigate to the project directory:
   ```bash
   cd SafeGate
   ```
2. Set your Gemini API key in `backend/.env` (use `backend/.env.example` as a template):
   ```bash
   GEMINI_API_KEY=your_gemini_api_key_here
   ```
3. Boot the environment:
   ```bash
   docker compose up --build
   ```
4. Access the web dashboard at:
   ```text
   http://localhost:3000
   ```

### Manual Development Setup

If running components natively for development (requires a local Docker socket `/var/run/docker.sock` for sandbox containers, and installed `exiftool` and `clamd` binaries):

#### 1. Setup Backend (FastAPI)
1. Create a Python virtual environment and activate it:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # macOS/Linux
   ```
2. Install python dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. Set your PostgreSQL database connection and API keys:
   ```bash
   set DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/postgres
   set GEMINI_API_KEY=YOUR_API_KEY
   ```
4. Run the FastAPI development server:
   ```bash
   uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```

#### 2. Start Background Workers
Launch a background worker process to listen to the Redis job queue:
```bash
python workers/worker.py
```

#### 3. Setup Frontend (Next.js)
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install npm modules:
   ```bash
   npm install
   ```
3. Start the Next.js dev server:
   ```bash
   npm run dev
   ```
4. Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Production Deployment on Render

SafeGate supports cloud deployment via Render using the configured `render.yaml` Blueprint:

1. Connect your GitHub repository to Render.
2. Render will spin up:
   * **Database:** Managed PostgreSQL instance.
   * **Cache:** Managed Redis instance.
   * **Web API Service:** FastAPI backend using a Docker environment (executes `run_services.py` which runs both FastAPI and the RQ worker concurrently).
   * **Frontend Service:** Static Next.js web application.
3. Configure environment variables in the Render console:
   * `GEMINI_API_KEY`: Google Gemini API key.
   * `PUBLIC_BACKEND_URL`: Public HTTPS link of the FastAPI service.
   * `ENABLE_CLAMAV`: Set to `false` if deploying on low-resource free instances.
   * `ENABLE_SANDBOX`: Set to `false` if host Docker access is restricted.

---

## Safety Constraints

SafeGate is built around zero-trust design rules:
* Files are uploaded to temporary paths and automatically pruned.
* Outbound networking is disabled inside sandbox execution contexts to prevent C2 (command and control) telemetry.
* Local file size scans are capped at **50 MB** in cloud environments. For larger files, the system prompts instructions to clone and run the verification layers locally.
* Verdicts are framed conservatively (**Low Risk**, **Suspicious**, or **Threat Detected**) to avoid misleading users into absolute guarantees.
