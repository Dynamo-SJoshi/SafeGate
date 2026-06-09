from __future__ import annotations

import tempfile
import logging
from pathlib import Path
from typing import Any

from app.database import get_upload_record, save_upload_record
from app.clamav_scanner import scan_file_with_clamav
from app.yara_scanner import scan_file_with_yara
from app.exif_scanner import extract_metadata_with_exiftool

logger = logging.getLogger("safegate-worker")
logger.setLevel(logging.INFO)

UPLOAD_ROOT = Path(tempfile.gettempdir()) / "safegate" / "uploads"
REMOTE_ROOT = Path(tempfile.gettempdir()) / "safegate" / "remote"


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
    logger.info(f"Running ClamAV scan on: {stored_path.name}")
    clamav_res = scan_file_with_clamav(stored_path)
    
    logger.info(f"Running YARA scan on: {stored_path.name}")
    yara_res = scan_file_with_yara(stored_path)
    
    logger.info(f"Extracting ExifTool metadata from: {stored_path.name}")
    exif_res = extract_metadata_with_exiftool(stored_path)

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
