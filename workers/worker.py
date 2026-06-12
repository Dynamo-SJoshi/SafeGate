from __future__ import annotations

import tempfile
import logging
import os
from pathlib import Path
from typing import Any

from app.database import get_upload_record, save_upload_record
from app.clamav_scanner import scan_file_with_clamav
from app.yara_scanner import scan_file_with_yara
from app.exif_scanner import extract_metadata_with_exiftool

logger = logging.getLogger("safegate-worker")
logger.setLevel(logging.INFO)

if os.path.exists("/app/storage"):
    _storage_base = Path("/app/storage")
elif os.path.exists("./storage"):
    _storage_base = Path("./storage")
else:
    _storage_base = Path(tempfile.gettempdir()) / "safegate"

UPLOAD_ROOT = _storage_base / "uploads"
REMOTE_ROOT = _storage_base / "remote"


def resolve_stored_path(record: dict[str, Any]) -> Path:
    stored_filename = str(record["stored_filename"])
    source_kind = str(record["source_kind"])
    base_root = UPLOAD_ROOT if source_kind == "upload" else REMOTE_ROOT
    return base_root / stored_filename


def process_scan_job(upload_id: str) -> dict[str, Any] | None:
    """Fetches the upload record, runs security scans, and updates the db."""
    logger.info(f"Worker processing scan job: {upload_id}")
    record = get_upload_record(upload_id)
    if not record:
        logger.error(f"Upload record not found: {upload_id}")
        return None

    if record.get("source_kind") == "url" and record.get("source_state") == "pending_fetch":
        logger.info(f"Worker downloading remote file for URL: {record.get('source_url')}")
        from app.url_fetching import fetch_remote_source
        from app.progress import progress_store
        from urllib.parse import urlparse
        import hashlib
        from app.fingerprinting import fingerprint_file

        def on_progress(bytes_written: int, total_bytes: int):
            if total_bytes > 0:
                percent = int((bytes_written / total_bytes) * 100)
                percent = max(0, min(100, percent))
                progress_store[upload_id] = percent
            else:
                progress_store[upload_id] = -1

        try:
            remote_fetch = fetch_remote_source(
                source_url=str(record["source_url"]),
                upload_id=upload_id,
                on_progress=on_progress,
            )
            
            parsed_final_url = urlparse(remote_fetch.final_url)
            original_filename = Path(parsed_final_url.path).name or "downloaded-file"
            stored_path = remote_fetch.stored_path
            content_type = remote_fetch.content_type or "application/octet-stream"
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

            # Update the database record with metadata
            save_upload_record(
                upload_id=upload_id,
                original_filename=original_filename,
                stored_filename=stored_path.name,
                content_type=content_type,
                size_bytes=size_bytes,
                sha256=sha256,
                fingerprint=fingerprint.to_dict(),
                analysis_state="pending",
                source_url=remote_fetch.final_url,
                source_kind="url",
                source_state=remote_fetch.fetch_kind,
                selected_candidate_url=remote_fetch.selected_candidate_url,
                candidate_urls=remote_fetch.candidate_urls,
                client_ip=record.get("client_ip"),
                static_analysis=record.get("static_analysis") or {},
                candidate_details=[
                    {"url": candidate.url, "score": candidate.score, "reasons": candidate.reasons}
                    for candidate in remote_fetch.candidate_details
                ],
            )
            
            # Reload record and stored_path for analysis
            record = get_upload_record(upload_id)
            
            # Clean up progress store
            if upload_id in progress_store:
                del progress_store[upload_id]

        except Exception as exc:
            logger.error(f"Failed to fetch remote source for {upload_id}: {exc}")
            if upload_id in progress_store:
                del progress_store[upload_id]
            
            placeholder_fingerprint = {
                "claimed_content_type": "unknown",
                "detected_content_type": "unknown",
                "claimed_extension": "",
                "detected_type": "unknown",
                "match_status": "unknown",
                "confidence": "unknown"
            }
            save_upload_record(
                upload_id=upload_id,
                original_filename="download-failed",
                stored_filename="none",
                content_type="application/octet-stream",
                size_bytes=0,
                sha256="none",
                fingerprint=record.get("fingerprint") or placeholder_fingerprint,
                analysis_state="error",
                source_url=record.get("source_url"),
                source_kind="url",
                source_state="error",
                client_ip=record.get("client_ip"),
                static_analysis={"error": f"Failed to download remote file: {exc}"},
            )
            return get_upload_record(upload_id)

    stored_path = resolve_stored_path(record)
    if not stored_path.exists():
        logger.error(f"Stored file not found for scanning: {stored_path}")
        save_upload_record(
            upload_id=upload_id,
            original_filename=str(record["original_filename"]),
            stored_filename=stored_path.name,
            content_type=str(record["content_type"]),
            size_bytes=int(record["size_bytes"]),
            sha256=str(record["sha256"]),
            fingerprint=dict(record["fingerprint"]),
            analysis_state="error",
            source_url=record.get("source_url"),
            source_kind=str(record["source_kind"]),
            source_state=str(record["source_state"]),
            selected_candidate_url=record.get("selected_candidate_url"),
            candidate_urls=record.get("candidate_urls"),
            client_ip=record.get("client_ip"),
            static_analysis={
                "error": "Stored file was not found on disk. It may have been cleaned up or expired."
            },
            candidate_details=record.get("candidate_details"),
        )
        return get_upload_record(upload_id)

    # Run the actual analyzers
    # 1. Skip all scans if the file is a ZIP bomb
    fingerprint = record.get("fingerprint") or {}
    detected_type = fingerprint.get("detected_type")
    
    if detected_type == "application/zip-bomb":
        logger.info(f"Worker skipping scan: ZIP bomb detected for {upload_id}")
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
        save_upload_record(
            upload_id=upload_id,
            original_filename=str(record["original_filename"]),
            stored_filename=stored_path.name,
            content_type=str(record["content_type"]),
            size_bytes=int(record["size_bytes"]),
            sha256=str(record["sha256"]),
            fingerprint=fingerprint,
            analysis_state="malicious",
            source_url=record.get("source_url"),
            source_kind=str(record["source_kind"]),
            source_state=str(record["source_state"]),
            selected_candidate_url=record.get("selected_candidate_url"),
            candidate_urls=record.get("candidate_urls"),
            client_ip=record.get("client_ip"),
            static_analysis=static_analysis,
            candidate_details=record.get("candidate_details"),
        )
        return get_upload_record(upload_id)

    # 2. Run the actual analyzers (isolated where possible)
    logger.info(f"Running ClamAV scan on: {stored_path.name}")
    clamav_res = scan_file_with_clamav(stored_path)
    
    logger.info(f"Running YARA and ExifTool in isolated container for: {stored_path.name}")
    from sandbox.sandbox_runner import run_isolated_scans
    isolated_res = run_isolated_scans(upload_id, stored_path)
    
    yara_res = isolated_res.get("yara", {"verdict": "error", "details": f"Isolated scan failed: {isolated_res.get('error', 'Unknown error')}"})
    exif_res = isolated_res.get("exiftool", {"status": "error", "details": f"Isolated scan failed: {isolated_res.get('error', 'Unknown error')}"})

    logger.info(f"Running isolated Dynamic Sandbox on: {stored_path.name}")
    from sandbox.sandbox_runner import run_in_sandbox
    sandbox_res = run_in_sandbox(upload_id, stored_path, str(record["original_filename"]))

    static_analysis = {
        "clamav": clamav_res,
        "yara": yara_res,
        "exiftool": exif_res,
        "sandbox": sandbox_res
    }

    # Compute final analysis state
    fingerprint = dict(record["fingerprint"])
    match_status = fingerprint.get("match_status", "unknown")

    if clamav_res.get("verdict") == "infected" or sandbox_res.get("verdict") == "malicious":
        analysis_state = "malicious"
    elif yara_res.get("verdict") == "suspicious" or match_status == "mismatch" or sandbox_res.get("verdict") == "suspicious":
        analysis_state = "suspicious"
    else:
        analysis_state = "clean"

    # Save / Update the database record
    logger.info(f"Updating database for upload_id {upload_id} with state {analysis_state}")
    save_upload_record(
        upload_id=upload_id,
        original_filename=str(record["original_filename"]),
        stored_filename=stored_path.name,
        content_type=str(record["content_type"]),
        size_bytes=int(record["size_bytes"]),
        sha256=str(record["sha256"]),
        fingerprint=fingerprint,
        analysis_state=analysis_state,
        source_url=record.get("source_url"),
        source_kind=str(record["source_kind"]),
        source_state=str(record["source_state"]),
        selected_candidate_url=record.get("selected_candidate_url"),
        candidate_urls=record.get("candidate_urls"),
        client_ip=record.get("client_ip"),
        static_analysis=static_analysis,
        candidate_details=record.get("candidate_details"),
    )
    
    logger.info(f"Successfully processed scan job: {upload_id}")
    return get_upload_record(upload_id)
