from __future__ import annotations

import base64
import binascii
import html
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET


RENDERABLE_CONTENT_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "audio/mpeg",
    "video/mp4",
    "video/x-matroska",
}


@dataclass(slots=True)
class PreviewResult:
    upload_id: str
    preview_kind: str
    preview_title: str
    summary: str
    content_type: str
    preview_url: str | None = None
    text: str | None = None
    items: list[dict[str, object]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "upload_id": self.upload_id,
            "preview_kind": self.preview_kind,
            "preview_title": self.preview_title,
            "summary": self.summary,
            "content_type": self.content_type,
            "preview_url": self.preview_url,
            "text": self.text,
            "items": self.items,
            "notes": self.notes,
        }


def build_preview(
    *,
    upload_id: str,
    stored_path: Path,
    original_filename: str,
    detected_content_type: str,
    fingerprint: dict[str, object],
) -> PreviewResult:
    if detected_content_type in RENDERABLE_CONTENT_TYPES:
        return PreviewResult(
            upload_id=upload_id,
            preview_kind="renderable-file",
            preview_title=f"Inline preview for {original_filename}",
            summary="SafeGate can render this file inline in a temporary preview viewer.",
            content_type=detected_content_type,
            preview_url=f"/preview/{upload_id}/file",
            notes=["temporary-inline-preview"],
        )

    is_archive = (
        detected_content_type in {"application/zip", "application/x-tar", "application/gzip"}
        or original_filename.lower().endswith(
            (".zip", ".docx", ".xlsx", ".pptx", ".tar", ".gz", ".tar.gz", ".tgz", ".war", ".jar", ".ear")
        )
        or detected_content_type.startswith("application/vnd.openxmlformats-officedocument.")
    )
    if is_archive:
        return _build_zip_like_preview(
            upload_id=upload_id,
            stored_path=stored_path,
            original_filename=original_filename,
            detected_content_type=detected_content_type,
        )

    if detected_content_type.startswith("application/vnd.openxmlformats-officedocument."):
        return _build_zip_like_preview(
            upload_id=upload_id,
            stored_path=stored_path,
            original_filename=original_filename,
            detected_content_type=detected_content_type,
        )

    if detected_content_type == "application/vnd.rar" or original_filename.lower().endswith(".rar"):
        return PreviewResult(
            upload_id=upload_id,
            preview_kind="archive-unavailable",
            preview_title=f"Archive preview for {original_filename}",
            summary="RAR archives are not expanded in the MVP preview path. SafeGate shows a safe metadata summary instead.",
            content_type=detected_content_type,
            text=_binary_summary(stored_path),
            notes=["rar-preview-limited"],
        )

    if detected_content_type.startswith("text/"):
        return PreviewResult(
            upload_id=upload_id,
            preview_kind="text-snippet",
            preview_title=f"Text preview for {original_filename}",
            summary="SafeGate extracted a safe text snippet from the file.",
            content_type=detected_content_type,
            text=_read_text_excerpt(stored_path),
            notes=["text-preview"],
        )

    if detected_content_type in {"application/x-msdownload", "application/x-msi"} or original_filename.lower().endswith(
        (".exe", ".msi", ".apk", ".iso", ".img")
    ):
        return PreviewResult(
            upload_id=upload_id,
            preview_kind="binary-summary",
            preview_title=f"Binary preview for {original_filename}",
            summary="SafeGate cannot render this file type inline, so it shows a safe binary summary instead.",
            content_type=detected_content_type,
            text=_binary_summary(stored_path),
            notes=["binary-preview"],
        )

    return PreviewResult(
        upload_id=upload_id,
        preview_kind="binary-summary",
        preview_title=f"Preview for {original_filename}",
        summary="SafeGate does not have a custom renderer for this type yet, so it shows a safe summary instead.",
        content_type=detected_content_type,
        text=_binary_summary(stored_path),
        notes=["fallback-preview"],
    )


def _build_zip_like_preview(
    *,
    upload_id: str,
    stored_path: Path,
    original_filename: str,
    detected_content_type: str,
) -> PreviewResult:
    try:
        from app.archive_utils import ArchiveReader
        with ArchiveReader(stored_path, detected_content_type, original_filename) as archive:
            names = archive.namelist()
            items = []
            for name in names[:120]:
                info = archive.getinfo(name)
                items.append(
                    {
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "is_directory": info.is_dir(),
                    }
                )

            notes = ["zip-preview"]
            preview_kind = "archive-listing"
            summary = "SafeGate shows the archive contents and treats nested executables as suspicious."

            if archive._archive_type == "zip" and _looks_like_office_package(names):
                preview_kind = "office-package"
                office_text = _extract_office_text(archive._zip_archive)
                if office_text:
                    notes.append("office-text-extracted")
                    return PreviewResult(
                        upload_id=upload_id,
                        preview_kind=preview_kind,
                        preview_title=f"Office preview for {original_filename}",
                        summary="SafeGate extracted a safe text snippet and the package structure for inspection.",
                        content_type=detected_content_type,
                        text=office_text,
                        items=items,
                        notes=notes,
                    )

            return PreviewResult(
                upload_id=upload_id,
                preview_kind=preview_kind,
                preview_title=f"Archive preview for {original_filename}",
                summary=summary,
                content_type=detected_content_type,
                items=items,
                notes=notes,
            )
    except Exception as e:
        import logging
        logger = logging.getLogger("safegate-preview")
        logger.error(f"Failed to generate archive preview: {e}")
        return PreviewResult(
            upload_id=upload_id,
            preview_kind="binary-summary",
            preview_title=f"Preview for {original_filename}",
            summary="SafeGate expected a valid archive but the structure was invalid, so it shows a safe binary summary.",
            content_type=detected_content_type,
            text=_binary_summary(stored_path),
            notes=["archive-structure-invalid"],
        )


def _looks_like_office_package(names: list[str]) -> bool:
    lower_names = [name.lower() for name in names]
    if "[content_types].xml" not in lower_names:
        return False
    return any(name.startswith(("word/", "xl/", "ppt/")) for name in lower_names)


def _extract_office_text(archive: zipfile.ZipFile) -> str | None:
    candidates = []
    for name in (
        "word/document.xml",
        "ppt/slides/slide1.xml",
        "ppt/slides/slide2.xml",
        "xl/sharedStrings.xml",
    ):
        try:
            data = archive.read(name)
        except KeyError:
            continue
        text = _xml_text_snippet(data)
        if text:
            candidates.append(f"[{name}]\n{text}")

    if not candidates:
        return None
    return "\n\n".join(candidates[:3])


def _xml_text_snippet(xml_bytes: bytes) -> str | None:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None

    parts: list[str] = []
    for element in root.iter():
        if element.text and element.text.strip():
            parts.append(element.text.strip())

    if not parts:
        return None

    snippet = " ".join(parts)
    return _truncate_text(snippet, 4000)


def _read_text_excerpt(stored_path: Path) -> str:
    raw = stored_path.read_bytes()
    text = raw.decode("utf-8", errors="ignore")
    return _truncate_text(text, 4000)


def _binary_summary(stored_path: Path) -> str:
    raw = stored_path.read_bytes()
    header = raw[:64]
    hex_header = binascii.hexlify(header).decode("ascii")
    ascii_preview = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in header)
    base64_preview = base64.b64encode(header).decode("ascii")
    summary = (
        f"Size: {stored_path.stat().st_size} bytes\n"
        f"Header hex: {hex_header}\n"
        f"ASCII preview: {ascii_preview}\n"
        f"Header base64: {base64_preview}"
    )
    return _truncate_text(summary, 4000)


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"
