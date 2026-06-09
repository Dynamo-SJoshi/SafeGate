from __future__ import annotations

import asyncio
import hashlib
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .environment import load_local_env_files
from .database import get_upload_record, save_upload_record, db_connection
from .fingerprinting import fingerprint_file
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

load_local_env_files()

# Global scan queue
scan_queue: asyncio.Queue[str] = asyncio.Queue()

def get_pending_upload_ids() -> list[str]:
    try:
        with db_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT upload_id FROM uploads WHERE analysis_state = 'pending'")
                records = cursor.fetchall()
                return [str(r["upload_id"]) for r in records]
    except Exception as exc:
        print(f"Error querying pending upload IDs on startup: {exc}")
        return []

async def resident_worker_loop():
    """Loops indefinitely, processing scan jobs from the queue."""
    from workers.worker import process_scan_job
    print("Resident scan worker loop started.")
    while True:
        try:
            upload_id = await scan_queue.get()
            print(f"Worker picked up upload_id: {upload_id}")
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, process_scan_job, upload_id)
            scan_queue.task_done()
        except asyncio.CancelledError:
            print("Resident scan worker loop cancelled.")
            break
        except Exception as exc:
            print(f"Error in resident scan worker: {exc}")
            await asyncio.sleep(1)



@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start the background cleanup task on startup (runs every 5 minutes by default)
    cleanup_task = asyncio.create_task(cleanup_loop())
    # Start resident scan worker task
    worker_task = asyncio.create_task(resident_worker_loop())
    
    # Enqueue existing pending tasks from database
    pending_ids = get_pending_upload_ids()
    print(f"Startup: Found {len(pending_ids)} pending scans to queue.")
    for uid in pending_ids:
        await scan_queue.put(uid)
        
    yield
    # Cancel tasks on shutdown
    cleanup_task.cancel()
    worker_task.cancel()
    try:
        await asyncio.gather(cleanup_task, worker_task, return_exceptions=True)
    except Exception:
        pass


app = FastAPI(title="SafeGate API", version="0.1.0", lifespan=lifespan)

UPLOAD_ROOT = Path(tempfile.gettempdir()) / "safegate" / "uploads"
REMOTE_ROOT = Path(tempfile.gettempdir()) / "safegate" / "remote"
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
        remote_fetch = fetch_remote_source(
            source_url=payload.url,
            upload_id=upload_id,
        )
        parsed_final_url = urlparse(remote_fetch.final_url)
        return _analyze_and_store_file(
            upload_id=upload_id,
            stored_path=remote_fetch.stored_path,
            original_filename=Path(parsed_final_url.path).name or "downloaded-file",
            content_type=remote_fetch.content_type or "application/octet-stream",
            source_kind="url",
            source_url=remote_fetch.final_url,
            source_state=remote_fetch.fetch_kind,
            selected_candidate_url=remote_fetch.selected_candidate_url,
            candidate_urls=remote_fetch.candidate_urls,
            candidate_details=[
                {"url": candidate.url, "score": candidate.score, "reasons": candidate.reasons}
                for candidate in remote_fetch.candidate_details
            ],
            notes=remote_fetch.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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


@app.get("/upload/{upload_id}")
def get_upload_status(upload_id: str):
    record = get_upload_record(upload_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Upload record not found.")
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
        # Enqueue the background scanning task
        scan_queue.put_nowait(upload_id)
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
