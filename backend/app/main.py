from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

from .database import save_upload_record
from .fingerprinting import fingerprint_file
from .url_fetching import fetch_remote_source

app = FastAPI(title="SafeGate API", version="0.1.0")

UPLOAD_ROOT = Path(tempfile.gettempdir()) / "safegate" / "uploads"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024

UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)


class UrlAnalyzeRequest(BaseModel):
    url: str


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "safegate-api"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    upload_id = str(uuid4())
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
        )
    finally:
        await file.close()


@app.post("/analyze-url")
def analyze_url(payload: UrlAnalyzeRequest):
    upload_id = str(uuid4())

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
) -> dict[str, object]:
    size_bytes = stored_path.stat().st_size
    sha256 = hashlib.sha256(stored_path.read_bytes()).hexdigest()

    fingerprint = fingerprint_file(
        file_path=stored_path,
        claimed_filename=original_filename,
        claimed_content_type=content_type,
    )

    try:
        save_upload_record(
            upload_id=upload_id,
            original_filename=original_filename,
            stored_filename=stored_path.name,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256=sha256,
            fingerprint=fingerprint.to_dict(),
            analysis_state="pending",
            source_url=source_url,
            source_kind=source_kind,
            source_state=source_state,
            selected_candidate_url=selected_candidate_url,
            candidate_urls=candidate_urls,
        )
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
        "fingerprint": fingerprint.to_dict(),
        "analysis_state": "pending",
        "database_state": "saved",
        "source_kind": source_kind,
        "source_state": source_state,
        "source_url": source_url,
        "selected_candidate_url": selected_candidate_url,
        "candidate_urls": candidate_urls or [],
        "candidate_details": candidate_details or [],
        "notes": notes or [],
    }
