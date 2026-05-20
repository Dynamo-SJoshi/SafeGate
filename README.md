# SafeGate

SafeGate is a browser-assisted, cloud-based safe download and file inspection platform.
It helps users inspect suspicious downloads in an isolated environment before they save or open them locally.

The core idea is simple:

`Inspect first` -> `Preview safely` -> `Decide with confidence`

---

## Why SafeGate Exists

Many malicious files hide behind trusted-looking names and extensions.

Examples:

- `movie.mp4.exe`
- fake PDFs
- malicious ZIP archives
- weaponized Office documents
- unsafe installers
- phishing attachments

SafeGate is designed to reduce that risk by combining:

- file fingerprinting
- static analysis
- optional sandbox execution
- temporary previews
- human-readable risk reports

It is **not** a replacement for antivirus software.
It is a safe inspection gateway that helps users avoid blindly trusting downloads.

---

## Core Goals

- Detect fake or disguised downloads
- Validate file type using real file structure, not just extensions
- Analyze files without running them whenever possible
- Use disposable sandboxes for high-risk files
- Generate temporary previews for safe inspection
- Explain findings in plain language
- Auto-delete temporary analysis data

---

## How It Works

```text
User clicks file or link
  |
  v
Browser extension or web upload
  |
  v
Upload to SafeGate
  |
  v
File fingerprinting
  |
  v
Static analysis
  |
  v
Risk scoring
  |
  v
High risk?
  |\
  | \-- No  -> Generate preview -> Final report
  |
  \---- Yes -> Run in disposable sandbox -> Behavior monitoring
                                   |
                                   v
                              Final risk report
                                   |
                                   v
                           Temporary dashboard
```

### What each step means

- **Browser extension or web upload**: the user sends a file or suspicious link to SafeGate
- **File fingerprinting**: SafeGate checks what the file really is
- **Static analysis**: SafeGate inspects the file without executing it
- **Risk scoring**: findings are combined into a verdict
- **Sandbox**: dangerous files can be executed in a disposable isolated environment
- **Preview**: SafeGate renders a safe temporary preview if possible
- **Report**: the user sees a readable explanation of the risk

---

## File Inspection Pipeline

```text
Upload
  |
  v
Magic bytes
  |
  v
MIME detection
  |
  v
Binary structure check
  |
  v
Format-specific checks
  |
  v
Static indicators
  |
  v
Risk score
```

### Why this matters

Never trust file extensions alone.

SafeGate checks:

- magic bytes
- MIME type
- actual binary structure
- media container / codec validity

This helps catch files like:

- `photo.jpg.exe`
- malformed PDFs
- disguised executables
- broken archives

---

## Analysis Modes

### 1. Low Risk Files

Examples:

- images
- videos
- audio files

Processing:

- fingerprint the file
- run static checks
- generate preview only

### 2. Medium Risk Files

Examples:

- PDFs
- Office documents
- archives

Processing:

- fingerprint the file
- inspect embedded content
- detect scripts, macros, and nested files
- render preview only if safe

### 3. High Risk Files

Examples:

- EXE
- MSI
- BAT
- JS
- VBS
- PowerShell scripts
- APK

Processing:

- fingerprint the file
- run static checks
- send to disposable sandbox if needed
- monitor execution behavior

```text
Incoming file
  |
  v
File type
  |
  +-- Image / Media --------> Static inspection + preview
  |
  +-- PDF / Office / Archive -> Deep static analysis + safe rendering
  |
  +-- Executable / Script / APK -> Sandbox execution
                                   |
                                   v
                                 Report
```

---

## Key Features

### File Type Validation

SafeGate validates files using real content, not just the extension.

It can inspect:

- magic bytes
- MIME type
- container structure
- codec validity
- metadata

Tools commonly used for this:

- `libmagic`
- `file`
- `ffprobe`
- `trid`
- `exiftool`

### Static Analysis

SafeGate analyzes files without executing them.

It can detect:

- PDF JavaScript
- embedded files
- suspicious objects
- Office macros
- auto-run behavior
- nested executables
- archive bombs
- path traversal
- suspicious imports
- entropy anomalies
- hidden payloads

Common tools:

- `ClamAV`
- `YARA`
- `pdfid`
- `peepdf`
- `oletools`

### Dynamic Sandbox Execution

Only high-risk files should be executed, and only inside a disposable isolated environment.

The sandbox should:

- auto-delete after use
- isolate networking
- restrict persistence
- monitor filesystem activity
- monitor process spawning
- monitor registry edits
- monitor suspicious system calls

Preferred sandbox option:

- **Firecracker microVMs**

Fallback option:

- **hardened Docker containers**

### Temporary Cloud Preview

SafeGate lets users preview files before downloading them locally.

Examples:

- stream video
- render PDFs
- display images
- inspect Office documents
- list ZIP contents safely

Preview links should:

- expire automatically
- use temporary object storage
- avoid permanent retention

### AI Safety Explanation

AI does **not** make the safety decision.

AI should:

- summarize findings
- translate technical details into plain English
- explain why the file looks suspicious

AI should **not**:

- replace malware detection
- claim a file is guaranteed safe
- override the analysis engines

### Browser Extension

The browser extension is the easiest way for users to send suspicious downloads to SafeGate.

It can:

- intercept suspicious download links
- upload a file or send metadata/hash
- open the preview/report page
- show the verdict to the user

---

## Recommended Architecture

```text
Browser Extension / Website
  |
  v
API Backend
  |
  v
Fingerprinting Layer
  |
  v
Static Analysis Engine
  |
  v
Risk Scoring Engine
  |
  v
Needs sandbox?
  |\
  | \-- No  -> Preview Renderer -> AI Explanation Layer -> Temporary Dashboard
  |
  \---- Yes -> Disposable Sandbox -> Behavior Logs -> AI Explanation Layer
                                                     |
                                                     v
                                            Temporary Dashboard
```

### Suggested Technology Stack

#### Frontend

- **Next.js**
- **React**
- **Tailwind CSS**

Why:

- great for dashboards and report pages
- fast UI development
- good routing and server-side rendering support

#### Backend

- **FastAPI**

Why:

- excellent for APIs
- strong Python ecosystem for file analysis tools
- easy to build and maintain

#### Queue System

- **Redis**

Why:

- simple MVP-friendly job queue
- easy to deploy
- good enough for scan workers

#### Database

- **PostgreSQL**

Why:

- reliable
- structured data fits this project well
- good for reports, sessions, logs, and audit trails

#### Storage

- **S3-compatible temporary object storage**

Why:

- supports expiring uploads and previews
- easy cleanup
- good scaling path

#### Sandbox

- **Firecracker microVMs** for stronger isolation
- **Docker** as a temporary fallback during early development

---

## MVP Scope

The first version should focus on the following:

- file fingerprinting
- media validation
- PDF and document inspection
- ZIP extraction safety
- temporary preview generation
- simple risk scoring
- human-readable reports
- auto-deletion of analysis sessions

The MVP does **not** need:

- enterprise SIEM integration
- perfect malware detection
- advanced reverse engineering
- distributed sandbox orchestration
- large-scale threat intelligence sharing

---

## Supported File Types

### Phase 1

- `mp4`
- `mkv`
- `mp3`
- `pdf`
- `jpg`
- `png`
- `webp`
- `zip`
- `rar`
- `docx`
- `xlsx`
- `pptx`

### Phase 2

- `exe`
- `msi`
- `apk`
- scripts
- `iso`
- `img`

### Phase 3

- advanced malware detonation
- behavioral scoring
- AI-assisted classification

---

## Security Philosophy

SafeGate is built around the assumption that every upload is hostile.

### Rules

- Never execute unknown files on the host
- Prefer static analysis before dynamic execution
- Minimize attack surface
- Use disposable analysis environments
- Avoid permanent storage unless explicitly requested
- Use rate limits and abuse protection

### Verdict Labels

SafeGate should never say "100% safe".

Use labels like:

- Low Risk
- Suspicious
- High Risk
- Failed Analysis
- Unknown Format

---

## Suggested Folder Structure

```text
/safegate
  /frontend
  /backend
  /sandbox
  /workers
  /analyzers
  /ai
  /storage
  /extension
  /docs
```

### What these folders mean

- `frontend`: user dashboard and preview UI
- `backend`: API, auth, scan orchestration
- `sandbox`: disposable execution environment
- `workers`: background jobs for scans and previews
- `analyzers`: file-type-specific inspection logic
- `ai`: natural-language report generation
- `storage`: temporary object storage integration
- `extension`: browser extension code
- `docs`: design notes, architecture, and onboarding materials

---

## Development Roadmap

### Priority 1

- file fingerprinting
- media validation
- PDF/document inspection
- ZIP extraction safety
- browser extension

### Priority 2

- dynamic sandbox execution
- VM orchestration
- AI summaries
- streaming previews

### Priority 3

- scalable microVM infrastructure
- malware behavior graphs
- advanced threat intelligence

```text
Priority 1
   |
   v
Priority 2
   |
   v
Priority 3

Priority 1 -> Core MVP -> Usable product -> Safer scale
```

---

## Important Safety Constraints

- Treat all uploads as hostile
- Never run unknown files directly on the host
- Do not persist files by default
- Auto-delete sandbox sessions
- Restrict sandbox networking
- Limit file size and archive depth
- Rate-limit uploads and analysis requests

---

## Inspiration

SafeGate is inspired by:

- VirusTotal
- ANY.RUN
- CAPE Sandbox
- Cuckoo Sandbox
- Firecracker microVMs

---

## Final Goal

Build a lightweight, modern, AI-assisted safe download gateway that allows users to inspect suspicious downloads in temporary isolated cloud environments before downloading them locally.

---

## Status

This repository is currently in the planning stage.

The recommended first milestone is to build the MVP pipeline:

1. upload
2. fingerprint
3. static analysis
4. risk scoring
5. safe preview
6. temporary report
7. auto cleanup
