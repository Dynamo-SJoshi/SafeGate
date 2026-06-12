from __future__ import annotations

import mimetypes
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class FingerprintResult:
    claimed_filename: str
    claimed_extension: str
    claimed_content_type: str
    detected_type: str
    detected_content_type: str
    match_status: str
    confidence: str
    indicators: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "claimed_filename": self.claimed_filename,
            "claimed_extension": self.claimed_extension,
            "claimed_content_type": self.claimed_content_type,
            "detected_type": self.detected_type,
            "detected_content_type": self.detected_content_type,
            "match_status": self.match_status,
            "confidence": self.confidence,
            "indicators": self.indicators,
        }


def fingerprint_file(file_path: Path, claimed_filename: str, claimed_content_type: str) -> FingerprintResult:
    file_bytes = file_path.read_bytes()
    header = file_bytes[:4096]
    extension = Path(claimed_filename).suffix.lower().lstrip(".")
    detected_type, detected_content_type, indicators, confidence = detect_file_type(
        file_path=file_path,
        file_bytes=file_bytes,
        header=header,
    )

    claimed_normalized = normalize_claimed_type(claimed_filename, claimed_content_type)
    match_status = "match" if claimed_normalized == detected_type else "mismatch"

    return FingerprintResult(
        claimed_filename=claimed_filename,
        claimed_extension=extension or "unknown",
        claimed_content_type=claimed_content_type or "application/octet-stream",
        detected_type=detected_type,
        detected_content_type=detected_content_type,
        match_status=match_status,
        confidence=confidence,
        indicators=indicators,
    )


def normalize_claimed_type(filename: str, content_type: str) -> str:
    ext = Path(filename).suffix.lower()
    extension_map = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".pdf": "application/pdf",
        ".zip": "application/zip",
        ".rar": "application/vnd.rar",
        ".7z": "application/x-7z-compressed",
        ".mp3": "audio/mpeg",
        ".mp4": "video/mp4",
        ".mkv": "video/x-matroska",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".exe": "application/x-msdownload",
        ".msi": "application/x-msi",
    }

    claimed_from_extension = extension_map.get(ext)
    if claimed_from_extension:
        return claimed_from_extension

    if content_type:
        return content_type.split(";")[0].strip().lower()

    guessed, _ = mimetypes.guess_type(filename)
    return (guessed or "application/octet-stream").lower()


def detect_file_type(
    file_path: Path,
    file_bytes: bytes,
    header: bytes,
) -> tuple[str, str, list[str], str]:
    indicators: list[str] = []

    if header.startswith(b"%PDF-"):
        indicators.append("pdf-header")
        return "application/pdf", "application/pdf", indicators, "high"

    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        indicators.append("png-signature")
        return "image/png", "image/png", indicators, "high"

    if header.startswith(b"\xff\xd8\xff"):
        indicators.append("jpeg-signature")
        return "image/jpeg", "image/jpeg", indicators, "high"

    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        indicators.append("gif-signature")
        return "image/gif", "image/gif", indicators, "high"

    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        indicators.append("webp-container")
        return "image/webp", "image/webp", indicators, "high"

    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06") or header.startswith(b"PK\x07\x08"):
        indicators.append("zip-container")
        return detect_zip_based_type(file_path, indicators)

    if header.startswith(b"Rar!\x1a\x07\x00") or header.startswith(b"Rar!\x1a\x07\x01\x00"):
        indicators.append("rar-signature")
        return "application/vnd.rar", "application/vnd.rar", indicators, "high"

    if header.startswith(b"\x1f\x8b"):
        indicators.append("gzip-signature")
        return "application/gzip", "application/gzip", indicators, "high"

    if header.startswith(b"MZ"):
        indicators.append("dos-mz-header")
        return "application/x-msdownload", "application/x-msdownload", indicators, "high"

    if header.startswith(b"ID3") or looks_like_mp3_frame(file_bytes):
        indicators.append("mp3-marker")
        return "audio/mpeg", "audio/mpeg", indicators, "medium"

    if looks_like_mp4(header):
        indicators.append("mp4-ftyp-box")
        return "video/mp4", "video/mp4", indicators, "medium"

    if header.startswith(b"\x1aE\xdf\xa3"):
        indicators.append("mkv-ebml-header")
        return "video/x-matroska", "video/x-matroska", indicators, "high"

    return "unknown", "application/octet-stream", indicators, "low"


def detect_zip_based_type(file_path: Path, indicators: list[str]) -> tuple[str, str, list[str], str]:
    try:
        with zipfile.ZipFile(file_path) as archive:
            # 1. In-Memory Header Inspection for Zip Bombs
            total_uncompressed_size = 0
            has_huge_file = False
            for info in archive.infolist():
                total_uncompressed_size += info.file_size
                if info.file_size > 500 * 1024 * 1024:
                    has_huge_file = True

            compressed_size = file_path.stat().st_size
            ratio = total_uncompressed_size / max(compressed_size, 1)

            if (ratio > 100.0 and total_uncompressed_size > 20 * 1024 * 1024) or has_huge_file:
                indicators.append("zip-bomb-detected")
                indicators.append(f"zip-bomb-ratio:{ratio:.1f}")
                indicators.append(f"zip-bomb-uncompressed-bytes:{total_uncompressed_size}")
                return "application/zip-bomb", "application/zip", indicators, "high"

            names = set(archive.namelist())

            if "[Content_Types].xml" in names:
                if any(name.startswith("word/") for name in names):
                    indicators.append("docx-structure")
                    return (
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        indicators,
                        "high",
                    )
                if any(name.startswith("xl/") for name in names):
                    indicators.append("xlsx-structure")
                    return (
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        indicators,
                        "high",
                    )
                if any(name.startswith("ppt/") for name in names):
                    indicators.append("pptx-structure")
                    return (
                        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                        indicators,
                        "high",
                    )

            indicators.append("generic-zip")
            return "application/zip", "application/zip", indicators, "high"
    except zipfile.BadZipFile:
        indicators.append("zip-header-but-invalid-structure")
        return "unknown", "application/octet-stream", indicators, "low"


def looks_like_mp3_frame(file_bytes: bytes) -> bool:
    if len(file_bytes) < 2:
        return False

    for index in range(min(len(file_bytes) - 1, 64)):
        if file_bytes[index] == 0xFF and (file_bytes[index + 1] & 0xE0) == 0xE0:
            return True
    return False


def looks_like_mp4(header: bytes) -> bool:
    if len(header) < 12:
        return False
    return header[4:8] == b"ftyp"
