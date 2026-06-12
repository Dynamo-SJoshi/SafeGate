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
)
from .previewing import build_preview
from .url_fetching import fetch_remote_source
from .cleanup import cleanup_loop
from .clamav_scanner import scan_file_with_clamav
from .yara_scanner import scan_file_with_yara
from .exif_scanner import extract_metadata_with_exiftool
from .security import validate_and_normalize_url

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

UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
REMOTE_ROOT.mkdir(parents=True, exist_ok=True)


class UrlAnalyzeRequest(BaseModel):
    url: str


class PreviewRequest(BaseModel):
    upload_id: str


class GeminiExplainRequest(BaseModel):
    analysis: dict[str, object]


class GeminiChatMessage(BaseModel):
    role: str
    content: str


class GeminiChatRequest(BaseModel):
    analysis: dict[str, object]
    question: str
    history: list[GeminiChatMessage] = Field(default_factory=list)


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
        )
    finally:
        await file.close()


@app.post("/analyze-url")
def analyze_url(payload: UrlAnalyzeRequest, request: Request):
    upload_id = str(uuid4())
    client_ip = get_client_ip(request)

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

    preview = build_preview(
        upload_id=str(record["upload_id"]),
        stored_path=stored_path,
        original_filename=str(record["original_filename"]),
        detected_content_type=str(record["detected_content_type"]),
        fingerprint=dict(record["fingerprint"]),
    )
    if preview.preview_kind == "renderable-file":
        import os
        public_url = os.environ.get("PUBLIC_BACKEND_URL")
        if public_url:
            preview.preview_url = f"{public_url.rstrip('/')}/preview/{record['upload_id']}/file"
        else:
            preview.preview_url = str(request.url_for("preview_file", upload_id=str(record["upload_id"])))
    return preview.to_dict()


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

    is_zip = detected_content_type == "application/zip" or original_filename.lower().endswith(
        (".zip", ".docx", ".xlsx", ".pptx")
    ) or detected_content_type.startswith("application/vnd.openxmlformats-officedocument.")

    if not is_zip:
        raise HTTPException(status_code=400, detail="This file type is not a ZIP archive.")

    fingerprint = dict(record.get("fingerprint") or {})
    if detected_content_type == "application/zip-bomb" or "zip-bomb-detected" in fingerprint.get("indicators", []):
        raise HTTPException(status_code=400, detail="Decompression is disabled: this archive is flagged as a ZIP bomb.")

    import zipfile
    import html

    try:
        with zipfile.ZipFile(stored_path) as archive:
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
                }

            ext = Path(norm_path).suffix.lower()
            previewable_exts = {".txt", ".py", ".js", ".json", ".sh", ".ini", ".md", ".csv", ".yaml", ".yml", ".xml", ".html", ".css", ".sql", ".conf", ".cfg"}

            if ext not in previewable_exts:
                return {
                    "file_path": file_path,
                    "content": "Binary file: inline preview disabled for safety.",
                    "is_binary": True,
                    "size_bytes": info.file_size,
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
                }
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive structure.")




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
    clamav_res = {"verdict": "pending", "details": "Scan is pending."}
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
def get_report_pdf(upload_id: str):
    record = get_upload_record(upload_id)
    if not record:
        raise HTTPException(status_code=404, detail="Upload record not found.")
    
    if record.get("analysis_state") == "pending":
        raise HTTPException(status_code=400, detail="Scan analysis is still pending.")
        
    try:
        pdf_bytes = generate_pdf_report(record)
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

