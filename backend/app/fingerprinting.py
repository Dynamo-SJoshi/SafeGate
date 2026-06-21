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
    
    text_extensions = {
        "txt", "md", "py", "js", "json", "sh", "ps1", "html", "css", 
        "xml", "yaml", "yml", "ini", "conf", "cfg", "sql", "csv"
    }
    
    is_claimed_text = claimed_normalized.startswith("text/") or extension in text_extensions
    is_detected_text = detected_type.startswith("text/")
    
    if is_claimed_text and is_detected_text:
        match_status = "match"
    else:
        match_status = "match" if claimed_normalized == detected_type else "mismatch"

    if check_double_extension(claimed_filename):
        indicators.append("double-extension-detected")

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


def check_double_extension(filename: str) -> bool:
    parts = filename.split(".")
    if len(parts) < 3:
        return False
    
    decoy_ext = "." + parts[-2].lower()
    actual_ext = "." + parts[-1].lower()
    
    decoy_extensions = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", 
        ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", 
        ".zip", ".tar", ".gz", ".7z", ".rar"
    }
    
    executable_extensions = {
        ".exe", ".msi", ".bat", ".cmd", ".vbs", ".ps1", ".js", 
        ".scr", ".pif", ".lnk", ".wsf", ".hta", ".vbe", ".jse", ".reg"
    }
    
    if decoy_ext in decoy_extensions and actual_ext in executable_extensions:
        return True
        
    return False


def normalize_claimed_type(filename: str, content_type: str) -> str:
    ext = Path(filename).suffix.lower()
    if filename.lower().endswith(".tar.gz"):
        ext = ".tar.gz"

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
        ".tar": "application/x-tar",
        ".gz": "application/gzip",
        ".tar.gz": "application/gzip",
        ".tgz": "application/gzip",
        ".war": "application/zip",
        ".jar": "application/zip",
        ".ear": "application/zip",
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

    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        indicators.append("7z-signature")
        return "application/x-7z-compressed", "application/x-7z-compressed", indicators, "high"

    if header.startswith(b"Rar!\x1a\x07\x00") or header.startswith(b"Rar!\x1a\x07\x01\x00"):
        indicators.append("rar-signature")
        return "application/vnd.rar", "application/vnd.rar", indicators, "high"

    if header.startswith(b"\x1f\x8b"):
        indicators.append("gzip-signature")
        return "application/gzip", "application/gzip", indicators, "high"

    if len(header) >= 262 and (header[257:262] == b"ustar" or header[257:262] == b"ustar\x00"):
        indicators.append("tar-ustar-magic")
        try:
            import tarfile
            with tarfile.open(file_path, "r") as archive:
                for name in archive.getnames():
                    if is_zip_slip_path(name):
                        indicators.append("zip-slip-detected")
                        break
        except Exception:
            pass
        return "application/x-tar", "application/x-tar", indicators, "high"

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

    # Check if the file looks like text
    if not header:
        return "text/plain", "text/plain", indicators, "low"

    if b"\x00" not in header:
        # Try to decode to check for HTML specifically
        try:
            header_text = header.decode("utf-8-sig", errors="ignore").strip().lower()
            if header_text.startswith("<!doctype html") or "<html" in header_text:
                indicators.append("html-elements")
                return "text/html", "text/html", indicators, "high"
        except Exception:
            pass

        # Check printable character density
        printable_chars = set(b"\n\r\t") | set(range(32, 127))
        non_printable = sum(1 for byte in header if byte not in printable_chars)
        if len(header) > 0 and (non_printable / len(header)) < 0.10:
            indicators.append("printable-text-heuristics")
            return "text/plain", "text/plain", indicators, "medium"

    return "unknown", "application/octet-stream", indicators, "low"


def is_zip_slip_path(path_str: str) -> bool:
    normalized = path_str.replace("\\", "/")
    if "../" in normalized or normalized.startswith("../"):
        return True
    if normalized.startswith("/"):
        return True
    if len(normalized) >= 2 and normalized[0].isalpha() and normalized[1] == ":":
        return True
    return False


def detect_zip_based_type(file_path: Path, indicators: list[str]) -> tuple[str, str, list[str], str]:
    try:
        with zipfile.ZipFile(file_path) as archive:
            # Check for Zip Slip threat
            has_zip_slip = False
            for name in archive.namelist():
                if is_zip_slip_path(name):
                    has_zip_slip = True
                    break
            if has_zip_slip:
                indicators.append("zip-slip-detected")
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
