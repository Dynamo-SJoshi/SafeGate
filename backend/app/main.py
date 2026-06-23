from __future__ import annotations

import asyncio
import hashlib
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .environment import load_local_env_files
from .database import get_upload_record, save_upload_record, db_connection
from .fingerprinting import fingerprint_file
from .report_generator import generate_pdf_report, get_report_data
from .gemini import (
    ask_gemini_about_analysis,
    build_fallback_chat_answer,
    build_fallback_explanation,
    explain_analysis_with_gemini,
    is_transient_gemini_error,
    explain_zip_item_with_gemini,
    build_fallback_zip_item_explanation,
)
from .previewing import build_preview
from .url_fetching import fetch_remote_source
from .cleanup import cleanup_loop
from .clamav_scanner import scan_file_with_clamav
from .yara_scanner import scan_file_with_yara
from .exif_scanner import extract_metadata_with_exiftool
from .security import validate_and_normalize_url
from .geolocation import get_location_from_ip

load_local_env_files()

# Global scan queue (Redis backed)
from redis import Redis
from rq import Queue
import os

redis_conn = Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
scan_queue = Queue("scans", connection=redis_conn)



@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    from .database import initialize_database
    try:
        initialize_database()
        print("Database schema checked/initialized successfully.")
    except Exception as exc:
        print(f"Error initializing database on startup: {exc}")

    # Start the background cleanup task on startup (runs every 5 minutes by default)
    cleanup_task = asyncio.create_task(cleanup_loop())
    
    yield
    # Cancel tasks on shutdown
    cleanup_task.cancel()
    try:
        await asyncio.gather(cleanup_task, return_exceptions=True)
    except Exception:
        pass


app = FastAPI(title="SafeGate API", version="0.1.0", lifespan=lifespan)

if os.path.exists("/app/storage"):
    _storage_base = Path("/app/storage")
elif os.path.exists("./storage"):
    _storage_base = Path("./storage")
else:
    _storage_base = Path(tempfile.gettempdir()) / "safegate"

UPLOAD_ROOT = _storage_base / "uploads"
REMOTE_ROOT = _storage_base / "remote"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024

ENABLE_CLAMAV = os.getenv("ENABLE_CLAMAV", "true").lower() == "true"
ENABLE_SANDBOX = os.getenv("ENABLE_SANDBOX", "true").lower() == "true"

UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
REMOTE_ROOT.mkdir(parents=True, exist_ok=True)


class UrlAnalyzeRequest(BaseModel):
    url: str


class PreviewRequest(BaseModel):
    upload_id: str


class GeminiExplainRequest(BaseModel):
    analysis: dict[str, object]


class GeminiExplainZipItemRequest(BaseModel):
    file_path: str
    content: str | None = None
    scan_results: dict[str, object] | None = None


class GeminiChatMessage(BaseModel):
    role: str
    content: str


class GeminiChatRequest(BaseModel):
    analysis: dict[str, object]
    question: str
    history: list[GeminiChatMessage] = Field(default_factory=list)


@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "safegate-api",
        "docs": "/docs"
    }


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "safegate-api"}


@app.post("/gemini/explain")
def gemini_explain(payload: GeminiExplainRequest):
    try:
        answer = explain_analysis_with_gemini(payload.analysis)
        return {"answer": answer, "mode": "gemini"}
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        if is_transient_gemini_error(exc):
            return {
                "answer": build_fallback_explanation(payload.analysis),
                "mode": "fallback",
                "detail": str(exc),
            }
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/gemini/explain-zip-item")
def gemini_explain_zip_item(payload: GeminiExplainZipItemRequest):
    try:
        answer = explain_zip_item_with_gemini(
            file_path=payload.file_path,
            content=payload.content,
            scan_results=payload.scan_results,
        )
        return {"answer": answer, "mode": "gemini"}
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        if is_transient_gemini_error(exc):
            return {
                "answer": build_fallback_zip_item_explanation(
                    file_path=payload.file_path,
                    scan_results=payload.scan_results,
                ),
                "mode": "fallback",
                "detail": str(exc),
            }
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/gemini/chat")
def gemini_chat(payload: GeminiChatRequest):
    try:
        answer = ask_gemini_about_analysis(
            analysis=payload.analysis,
            question=payload.question,
            history=[message.model_dump() for message in payload.history],
        )
        return {"answer": answer, "mode": "gemini"}
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        if is_transient_gemini_error(exc):
            return {
                "answer": build_fallback_chat_answer(payload.analysis, payload.question),
                "mode": "fallback",
                "detail": str(exc),
            }
        raise HTTPException(status_code=502, detail=str(exc)) from exc


def get_client_ip(request: Request) -> str:
    """
    Extract the client IP address from proxy headers (if present) or fallback to request.client.host.
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
        
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
        
    return request.client.host if request.client else "unknown"


@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...)):
    upload_id = str(uuid4())
    client_ip = get_client_ip(request)
    client_location = get_location_from_ip(client_ip)
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="Missing filename.")

        stored_path = UPLOAD_ROOT / f"{upload_id}-{Path(file.filename).name}"
        await _save_uploaded_file(file=file, destination=stored_path)
        return _analyze_and_store_file(
            upload_id=upload_id,
            stored_path=stored_path,
            original_filename=file.filename,
            content_type=file.content_type or "application/octet-stream",
            source_kind="upload",
            client_ip=client_ip,
            client_location=client_location,
        )
    finally:
        await file.close()


@app.post("/analyze-url")
def analyze_url(payload: UrlAnalyzeRequest, request: Request):
    upload_id = str(uuid4())
    client_ip = get_client_ip(request)
    client_location = get_location_from_ip(client_ip)

    try:
        normalized_url = validate_and_normalize_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    placeholder_fingerprint = {
        "claimed_content_type": "unknown",
        "detected_content_type": "unknown",
        "claimed_extension": "",
        "detected_type": "unknown",
        "match_status": "unknown",
        "confidence": "unknown"
    }

    try:
        save_upload_record(
            upload_id=upload_id,
            original_filename="pending-download",
            stored_filename="pending-download",
            content_type="application/octet-stream",
            size_bytes=0,
            sha256="pending",
            fingerprint=placeholder_fingerprint,
            analysis_state="pending",
            source_url=normalized_url,
            source_kind="url",
            source_state="pending_fetch",
            client_ip=client_ip,
            client_location=client_location,
        )
        scan_queue.enqueue("workers.worker.process_scan_job", upload_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to initialize upload record in database: {exc}",
        ) from exc

    return {
        "status": "received",
        "upload_id": upload_id,
        "filename": "pending-download",
        "content_type": "application/octet-stream",
        "size_bytes": 0,
        "sha256": "pending",
        "fingerprint": placeholder_fingerprint,
        "analysis_state": "pending",
        "database_state": "saved",
        "source_kind": "url",
        "source_state": "pending_fetch",
        "source_url": normalized_url,
        "candidate_urls": [],
        "candidate_details": [],
        "notes": [],
    }


@app.post("/preview")
def preview_upload(payload: PreviewRequest, request: Request):
    record = get_upload_record(payload.upload_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Upload record not found.")

    stored_path = _resolve_stored_path(record)
    if not stored_path.exists():
        raise HTTPException(status_code=404, detail="Stored file not found.")

    # Check if a dynamic sandbox screenshot preview exists
    screenshot_path = _storage_base / "previews" / f"{payload.upload_id}.png"
    if screenshot_path.exists():
        import os
        public_url = os.environ.get("PUBLIC_BACKEND_URL") or os.environ.get("RENDER_EXTERNAL_URL")
        if public_url:
            screenshot_url = f"{public_url.rstrip('/')}/preview/{payload.upload_id}/screenshot"
        else:
            screenshot_url = str(request.url_for("preview_screenshot", upload_id=payload.upload_id))
            
        return {
            "preview_kind": "html-screenshot",
            "preview_url": screenshot_url,
            "has_screenshot": True
        }

    preview = build_preview(
        upload_id=str(record["upload_id"]),
        stored_path=stored_path,
        original_filename=str(record["original_filename"]),
        detected_content_type=str(record["detected_content_type"]),
        fingerprint=dict(record["fingerprint"]),
    )
    if preview.preview_kind == "renderable-file":
        import os
        public_url = os.environ.get("PUBLIC_BACKEND_URL") or os.environ.get("RENDER_EXTERNAL_URL")
        if public_url:
            preview.preview_url = f"{public_url.rstrip('/')}/preview/{record['upload_id']}/file"
        else:
            preview.preview_url = str(request.url_for("preview_file", upload_id=str(record["upload_id"])))
    return preview.to_dict()


@app.get("/preview/{upload_id}/screenshot", name="preview_screenshot")
def preview_screenshot(upload_id: str):
    screenshot_path = _storage_base / "previews" / f"{upload_id}.png"
    if not screenshot_path.exists():
        raise HTTPException(status_code=404, detail="Screenshot preview not found.")
        
    return FileResponse(
        path=screenshot_path,
        media_type="image/png",
        filename=f"SafeGate_Screenshot_{upload_id}.png"
    )


@app.get("/preview/{upload_id}/file", name="preview_file")
def preview_file(upload_id: str):
    record = get_upload_record(upload_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Upload record not found.")

    stored_path = _resolve_stored_path(record)
    if not stored_path.exists():
        raise HTTPException(status_code=404, detail="Stored file not found.")

    detected_content_type = str(record["detected_content_type"])
    if detected_content_type not in {
        "application/pdf",
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "audio/mpeg",
        "video/mp4",
        "video/x-matroska",
    }:
        raise HTTPException(status_code=400, detail="This file type does not have an inline preview.")

    filename = str(record["original_filename"])
    return FileResponse(
        path=stored_path,
        media_type=detected_content_type,
        filename=filename,
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )


@app.get("/preview/{upload_id}/zip-file")
def preview_zip_file(upload_id: str, file_path: str):
    record = get_upload_record(upload_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Upload record not found.")

    stored_path = _resolve_stored_path(record)
    if not stored_path.exists():
        raise HTTPException(status_code=404, detail="Stored file not found.")

    detected_content_type = str(record["detected_content_type"])
    original_filename = str(record["original_filename"])

    is_archive = (
        detected_content_type in {"application/zip", "application/x-tar", "application/gzip"}
        or original_filename.lower().endswith(
            (".zip", ".docx", ".xlsx", ".pptx", ".tar", ".gz", ".tar.gz", ".tgz", ".war", ".jar", ".ear")
        )
        or detected_content_type.startswith("application/vnd.openxmlformats-officedocument.")
    )

    if not is_archive:
        raise HTTPException(status_code=400, detail="This file type is not a supported archive.")

    fingerprint = dict(record.get("fingerprint") or {})
    if detected_content_type == "application/zip-bomb" or "zip-bomb-detected" in fingerprint.get("indicators", []):
        raise HTTPException(status_code=400, detail="Decompression is disabled: this archive is flagged as a ZIP bomb.")

    from app.archive_utils import ArchiveReader
    import html
    import shutil

    try:
        with ArchiveReader(stored_path, detected_content_type, original_filename) as archive:
            norm_path = file_path.replace("\\", "/").lstrip("/")
            try:
                info = archive.getinfo(norm_path)
            except KeyError:
                raise HTTPException(status_code=404, detail=f"File {file_path} not found in the archive.")

            if info.is_dir():
                return {
                    "file_path": file_path,
                    "content": "This is a directory.",
                    "is_binary": False,
                    "size_bytes": 0,
                    "scan_results": None
                }

            # Check for Zip Slip / path traversal threat
            is_zip_slip = False
            normalized_path = norm_path.replace("\\", "/")
            if "../" in normalized_path or normalized_path.startswith("../") or normalized_path.startswith("/") or (len(normalized_path) >= 2 and normalized_path[0].isalpha() and normalized_path[1] == ":"):
                is_zip_slip = True

            if is_zip_slip:
                scan_results = {
                    "verdict": "malicious",
                    "clamav": {"verdict": "infected", "details": "Flagged by SafeGate Path Analyzer: Potential Zip Slip / Directory Traversal attempt detected in archive file path."},
                    "yara": {"verdict": "clean", "details": "YARA scan skipped: Path analyzer already flagged threat."},
                    "exiftool": {"status": "skipped", "details": "ExifTool skipped: Path analyzer already flagged threat."},
                    "sandbox": {
                        "executed": False,
                        "verdict": "malicious",
                        "behavior_alerts": ["Zip Slip / Path Traversal Attempt: File path targets parent directories (../)."],
                        "reason": "Dynamic execution skipped because path contains directory traversal sequences.",
                        "logs": "No logs: Dynamic sandboxing refused to run path-traversal payload."
                    }
                }
                
                # Update parent DB record to malicious if not already
                current_state = record.get("analysis_state", "unverified")
                if current_state != "malicious":
                    parent_static = dict(record.get("static_analysis") or {})
                    if "zip_findings" not in parent_static:
                        parent_static["zip_findings"] = []
                    
                    existing_paths = [f.get("file_path") for f in parent_static["zip_findings"]]
                    if norm_path not in existing_paths:
                        parent_static["zip_findings"].append({
                            "file_path": norm_path,
                            "verdict": "malicious",
                            "alerts": ["Zip Slip / Directory Traversal Pattern Detected in path."]
                        })
                    
                    save_upload_record(
                        upload_id=upload_id,
                        original_filename=str(record["original_filename"]),
                        stored_filename=str(record["stored_filename"]),
                        content_type=str(record["content_type"]),
                        size_bytes=int(record["size_bytes"]),
                        sha256=str(record["sha256"]),
                        fingerprint=dict(record["fingerprint"]),
                        analysis_state="malicious",
                        source_url=record.get("source_url"),
                        source_kind=str(record["source_kind"]),
                        source_state=str(record["source_state"]),
                        selected_candidate_url=record.get("selected_candidate_url"),
                        candidate_urls=record.get("candidate_urls"),
                        client_ip=record.get("client_ip"),
                        static_analysis=parent_static,
                        candidate_details=record.get("candidate_details"),
                        client_location=record.get("client_location"),
                    )

                return {
                    "file_path": file_path,
                    "content": "Directory traversal payload detected inside path names.",
                    "is_binary": True,
                    "size_bytes": info.file_size,
                    "scan_results": scan_results
                }

            # 1. Extract file temporarily for security scans
            suffix = Path(norm_path).suffix
            temp_scan_file = UPLOAD_ROOT / f"zip_temp_{upload_id}_{uuid4().hex}{suffix}"
            
            clamav_res = {"verdict": "skipped", "details": "ClamAV not run."}
            yara_res = {"verdict": "skipped", "details": "YARA not run."}
            exif_res = {"status": "skipped", "details": "ExifTool not run."}
            sandbox_res = {"verdict": "skipped", "reason": "Sandbox not run.", "executed": False}
            
            try:
                with archive.open(norm_path) as source_f:
                    with open(temp_scan_file, "wb") as dest_f:
                        shutil.copyfileobj(source_f, dest_f)
                
                # Run security scans
                if ENABLE_CLAMAV:
                    clamav_res = scan_file_with_clamav(temp_scan_file)
                else:
                    clamav_res = {"verdict": "skipped", "details": "ClamAV is disabled in this environment."}
                
                if ENABLE_SANDBOX:
                    from sandbox.sandbox_runner import run_isolated_scans, run_in_sandbox
                    scan_id = f"zip_{upload_id}_{uuid4().hex[:8]}"
                    
                    isolated_res = run_isolated_scans(scan_id, temp_scan_file)
                    yara_res = isolated_res.get("yara", {"verdict": "error", "details": f"Isolated scan failed: {isolated_res.get('error', 'Unknown error')}"})
                    exif_res = isolated_res.get("exiftool", {"status": "error", "details": f"Isolated scan failed: {isolated_res.get('error', 'Unknown error')}"})
                    
                    sandbox_res = run_in_sandbox(scan_id, temp_scan_file, Path(norm_path).name)
                else:
                    yara_res = scan_file_with_yara(temp_scan_file)
                    exif_res = extract_metadata_with_exiftool(temp_scan_file)
                    sandbox_res = {"verdict": "skipped", "reason": "Dynamic sandboxing is disabled in this environment.", "executed": False}
            finally:
                if temp_scan_file.exists():
                    temp_scan_file.unlink()

            # Calculate overall verdict for this zip item
            item_verdict = "clean"
            if clamav_res.get("verdict") == "infected" or sandbox_res.get("verdict") == "malicious":
                item_verdict = "malicious"
            elif yara_res.get("verdict") == "suspicious" or sandbox_res.get("verdict") == "suspicious":
                item_verdict = "suspicious"

            # If the item verdict is worse than the current analysis_state, update the database record!
            if item_verdict in ("malicious", "suspicious"):
                current_state = record.get("analysis_state", "unverified")
                if current_state != "malicious":  # If it's already malicious, we don't need to change anything
                    new_state = "malicious" if item_verdict == "malicious" else "suspicious"
                    if current_state != new_state:
                        parent_static = dict(record.get("static_analysis") or {})
                        
                        # Add a zip_findings log so the report lists the threat
                        if "zip_findings" not in parent_static:
                            parent_static["zip_findings"] = []
                        
                        # Avoid duplicates
                        existing_paths = [f.get("file_path") for f in parent_static["zip_findings"]]
                        if norm_path not in existing_paths:
                            parent_static["zip_findings"].append({
                                "file_path": norm_path,
                                "verdict": item_verdict,
                                "alerts": clamav_res.get("details") or yara_res.get("details") or sandbox_res.get("behavior_alerts") or []
                            })
                        
                        # Update the database
                        save_upload_record(
                            upload_id=upload_id,
                            original_filename=str(record["original_filename"]),
                            stored_filename=str(record["stored_filename"]),
                            content_type=str(record["content_type"]),
                            size_bytes=int(record["size_bytes"]),
                            sha256=str(record["sha256"]),
                            fingerprint=dict(record["fingerprint"]),
                            analysis_state=new_state,
                            source_url=record.get("source_url"),
                            source_kind=str(record["source_kind"]),
                            source_state=str(record["source_state"]),
                            selected_candidate_url=record.get("selected_candidate_url"),
                            candidate_urls=record.get("candidate_urls"),
                            client_ip=record.get("client_ip"),
                            static_analysis=parent_static,
                            candidate_details=record.get("candidate_details"),
                            client_location=record.get("client_location"),
                        )

            scan_results = {
                "verdict": item_verdict,
                "clamav": clamav_res,
                "yara": yara_res,
                "exiftool": exif_res,
                "sandbox": sandbox_res
            }

            ext = Path(norm_path).suffix.lower()
            previewable_exts = {".txt", ".py", ".js", ".json", ".sh", ".ini", ".md", ".csv", ".yaml", ".yml", ".xml", ".html", ".css", ".sql", ".conf", ".cfg", ".ps1"}

            if ext not in previewable_exts:
                return {
                    "file_path": file_path,
                    "content": "Binary file: inline preview disabled for safety.",
                    "is_binary": True,
                    "size_bytes": info.file_size,
                    "scan_results": scan_results
                }

            with archive.open(norm_path) as f:
                lines = []
                for _ in range(100):
                    line_bytes = f.readline()
                    if not line_bytes:
                        break
                    try:
                        line_text = line_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        return {
                            "file_path": file_path,
                            "content": "Binary file: inline preview disabled for safety.",
                            "is_binary": True,
                            "size_bytes": info.file_size,
                            "scan_results": scan_results
                        }
                    lines.append(line_text)

                content = "".join(lines)
                sanitized_content = html.escape(content)

                if f.readline():
                    sanitized_content += "\n\n... [truncated: showing only the first 100 lines for length/safety]"

                return {
                    "file_path": file_path,
                    "content": sanitized_content,
                    "is_binary": False,
                    "size_bytes": info.file_size,
                    "scan_results": scan_results
                }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid archive structure or extraction failure: {str(e)}")




@app.get("/upload/{upload_id}")
def get_upload_status(upload_id: str):
    record = get_upload_record(upload_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Upload record not found.")

    from .progress import progress_store
    record["download_progress"] = progress_store.get(upload_id, None)
    return record


async def _save_uploaded_file(*, file: UploadFile, destination: Path) -> None:
    size_bytes = 0

    try:
        with destination.open("wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break

                size_bytes += len(chunk)
                if size_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 50 MB MVP upload limit.",
                    )

                buffer.write(chunk)
    except HTTPException:
        if destination.exists():
            destination.unlink(missing_ok=True)
        raise


def _resolve_stored_path(record: dict[str, object]) -> Path:
    stored_filename = str(record["stored_filename"])
    source_kind = str(record["source_kind"])
    base_root = UPLOAD_ROOT if source_kind == "upload" else REMOTE_ROOT
    return base_root / stored_filename


def _analyze_and_store_file(
    *,
    upload_id: str,
    stored_path: Path,
    original_filename: str,
    content_type: str,
    source_kind: str,
    source_url: str | None = None,
    source_state: str = "direct_file",
    selected_candidate_url: str | None = None,
    candidate_urls: list[str] | None = None,
    candidate_details: list[dict[str, object]] | None = None,
    notes: list[str] | None = None,
    client_ip: str | None = None,
    client_location: str | None = None,
) -> dict[str, object]:
    size_bytes = stored_path.stat().st_size
    
    sha256_hash = hashlib.sha256()
    with stored_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    sha256 = sha256_hash.hexdigest()

    fingerprint = fingerprint_file(
        file_path=stored_path,
        claimed_filename=original_filename,
        claimed_content_type=content_type,
    )

    # Run Static Anti-Malware Analyzers
    clamav_res = {"verdict": "pending", "details": "Scan is pending."} if ENABLE_CLAMAV else {"verdict": "skipped", "details": "ClamAV is disabled in this environment."}
    yara_res = {"verdict": "pending", "details": "Scan is pending."}
    exif_res = {"status": "pending", "details": "Scan is pending."}

    static_analysis = {
        "clamav": clamav_res,
        "yara": yara_res,
        "exiftool": exif_res
    }

    # Compute analysis_state
    fingerprint_dict = fingerprint.to_dict()
    if fingerprint.detected_type == "application/zip-bomb":
        analysis_state = "malicious"
        static_analysis = {
            "zip_bomb_detection": {
                "verdict": "malicious",
                "details": "ZIP bomb signature detected via in-memory header inspection (extremely high compression ratio or single-file size anomaly)."
            },
            "clamav": {"verdict": "skipped", "details": "Scan skipped for safety: ZIP bomb detected."},
            "yara": {"verdict": "skipped", "details": "Scan skipped for safety: ZIP bomb detected."},
            "exiftool": {"status": "skipped", "metadata": {}},
            "sandbox": {"verdict": "skipped", "reason": "Scan skipped for safety: ZIP bomb detected.", "executed": False}
        }
    elif "zip-slip-detected" in fingerprint_dict.get("indicators", []):
        analysis_state = "malicious"
        static_analysis = {
            "zip_slip_detection": {
                "verdict": "malicious",
                "details": "ZIP Slip / Directory Traversal threat detected: One or more files inside the archive contain directory traversal path sequences (e.g. '../'). Extraction on a vulnerable system could lead to arbitrary file overwrite and RCE."
            },
            "clamav": {"verdict": "skipped", "details": "Scan skipped for safety: ZIP Slip threat detected."},
            "yara": {"verdict": "skipped", "details": "Scan skipped for safety: ZIP Slip threat detected."},
            "exiftool": {"status": "skipped", "metadata": {}},
            "sandbox": {"verdict": "skipped", "reason": "Scan skipped for safety: ZIP Slip threat detected.", "executed": False}
        }
    else:
        analysis_state = "pending"

    try:
        save_upload_record(
            upload_id=upload_id,
            original_filename=original_filename,
            stored_filename=stored_path.name,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256=sha256,
            fingerprint=fingerprint_dict,
            analysis_state=analysis_state,
            source_url=source_url,
            source_kind=source_kind,
            source_state=source_state,
            selected_candidate_url=selected_candidate_url,
            candidate_urls=candidate_urls,
            client_ip=client_ip,
            static_analysis=static_analysis,
            candidate_details=candidate_details,
            client_location=client_location,
        )
        # Enqueue the background scanning task if pending
        if analysis_state == "pending":
            scan_queue.enqueue("workers.worker.process_scan_job", upload_id)
    except Exception as exc:
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=503,
            detail=f"Failed to save upload metadata to PostgreSQL: {exc}",
        ) from exc

    return {
        "status": "received",
        "upload_id": upload_id,
        "filename": original_filename,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "fingerprint": fingerprint_dict,
        "analysis_state": analysis_state,
        "static_analysis": static_analysis,
        "database_state": "saved",
        "source_kind": source_kind,
        "source_state": source_state,
        "source_url": source_url,
        "selected_candidate_url": selected_candidate_url,
        "candidate_urls": candidate_urls or [],
        "candidate_details": candidate_details or [],
        "notes": notes or [],
    }


@app.get("/report/{upload_id}")
def get_report_json(upload_id: str):
    record = get_upload_record(upload_id)
    if not record:
        raise HTTPException(status_code=404, detail="Upload record not found.")
    
    if record.get("analysis_state") == "pending":
        raise HTTPException(status_code=400, detail="Scan analysis is still pending.")
        
    try:
        data = get_report_data(record)
        return data
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate report JSON: {str(exc)}")


@app.get("/report/{upload_id}/pdf")
def get_report_pdf(upload_id: str, tz: str = "UTC"):
    record = get_upload_record(upload_id)
    if not record:
        raise HTTPException(status_code=404, detail="Upload record not found.")
    
    if record.get("analysis_state") == "pending":
        raise HTTPException(status_code=400, detail="Scan analysis is still pending.")
        
    try:
        pdf_bytes = generate_pdf_report(record, tz=tz)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"inline; filename=SafeGate_Report_{upload_id}.pdf"
            }
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to compile PDF report: {str(exc)}")

