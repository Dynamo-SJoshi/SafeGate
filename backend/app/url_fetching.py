from __future__ import annotations

import re
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .security import validate_and_normalize_url

MAX_REMOTE_BYTES = 50 * 1024 * 1024
MAX_LANDING_PAGE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
REMOTE_TIMEOUT_SECONDS = 15


@dataclass(slots=True)
class CandidateLinkInfo:
    url: str
    score: int
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RemoteFetchResult:
    stored_path: Path
    size_bytes: int
    final_url: str
    content_type: str
    fetch_kind: str
    selected_candidate_url: str | None = None
    candidate_urls: list[str] = field(default_factory=list)
    candidate_details: list[CandidateLinkInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DownloadLinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.candidates: list[str] = []
        self._tag_stack: list[str] = []

    def handle_starttag(self, tag, attrs):
        self._tag_stack.append(tag.lower())
        attribute_map = {key.lower(): value for key, value in attrs}
        for attribute_name in ("href", "src", "action"):
            value = attribute_map.get(attribute_name)
            if value:
                self._add_candidate(value)

        for attribute_name, value in attribute_map.items():
            if not value:
                continue
            if attribute_name.startswith("data-") and any(
                keyword in attribute_name for keyword in ("href", "url", "link", "download", "file", "src")
            ):
                self._add_candidate(value)

        onclick = attribute_map.get("onclick")
        if onclick:
            self._extract_urls_from_text(onclick)

        if tag.lower() == "meta":
            http_equiv = attribute_map.get("http-equiv", "").lower()
            content = attribute_map.get("content", "")
            if http_equiv == "refresh" and "url=" in content.lower():
                match = re.search(r"url\s*=\s*(.+)", content, flags=re.IGNORECASE)
                if match:
                    self._add_candidate(match.group(1).strip("\"' "))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()
        elif tag in self._tag_stack:
            self._tag_stack.remove(tag)

    def handle_data(self, data):
        if self._tag_stack and self._tag_stack[-1] == "script":
            self._extract_urls_from_text(data)

    def _add_candidate(self, raw_value: str) -> None:
        resolved = urljoin(self.base_url, raw_value.strip())
        parsed = urlparse(resolved)
        if parsed.scheme not in {"http", "https"}:
            return
        if resolved not in self.candidates:
            self.candidates.append(resolved)

    def _extract_urls_from_text(self, text: str) -> None:
        for match in re.finditer(r"""(?ix)
            (?:
                https?://[^\s"'<>\\)]+
                |
                /[^\s"'<>\\)]+
            )
        """, text):
            self._add_candidate(match.group(0))


def fetch_remote_source(source_url: str, upload_id: str) -> RemoteFetchResult:
    normalized_url = validate_and_normalize_url(source_url)
    destination_root = Path(tempfile.gettempdir()) / "safegate" / "remote"
    destination_root.mkdir(parents=True, exist_ok=True)
    destination_path = destination_root / f"{upload_id}.bin"

    try:
        result = _download_with_redirects(
            normalized_url=normalized_url,
            destination_path=destination_path,
            redirects_remaining=MAX_REDIRECTS,
            destination_root=destination_root,
            upload_id=upload_id,
            allow_candidate_follow=True,
        )
        return result
    except Exception:
        if destination_path.exists():
            destination_path.unlink(missing_ok=True)
        raise


def _download_with_redirects(
    *,
    normalized_url: str,
    destination_path: Path,
    redirects_remaining: int,
    destination_root: Path,
    upload_id: str,
    allow_candidate_follow: bool,
) -> RemoteFetchResult:
    opener = urllib.request.build_opener(NoRedirectHandler())
    request = urllib.request.Request(
        normalized_url,
        headers={
            "User-Agent": "SafeGate/0.1",
            "Accept": "*/*",
        },
        method="GET",
    )

    try:
        response = opener.open(request, timeout=REMOTE_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            if redirects_remaining <= 0:
                raise ValueError("Too many redirects.")

            location = exc.headers.get("Location")
            if not location:
                raise ValueError("Redirect response did not include a Location header.")

            next_url = urljoin(normalized_url, location)
            return _download_with_redirects(
                normalized_url=validate_and_normalize_url(next_url),
                destination_path=destination_path,
                redirects_remaining=redirects_remaining - 1,
                destination_root=destination_root,
                upload_id=upload_id,
                allow_candidate_follow=allow_candidate_follow,
            )

        raise ValueError(f"Remote fetch failed with HTTP {exc.code}.") from exc

    with response:
        content_type = response.headers.get_content_type()
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_REMOTE_BYTES:
                    raise ValueError("Remote file exceeds the SafeGate fetch limit.")
            except ValueError as exc:
                if "Remote file exceeds" in str(exc):
                    raise
                raise ValueError("Remote file returned an invalid Content-Length header.") from exc

        if content_type in {"text/html", "application/xhtml+xml"}:
            return _download_landing_page(
                response=response,
                normalized_url=normalized_url,
                destination_path=destination_path,
                content_type=content_type,
                destination_root=destination_root,
                upload_id=upload_id,
                allow_candidate_follow=allow_candidate_follow,
            )

        return _download_file(
            response=response,
            normalized_url=normalized_url,
            destination_path=destination_path,
            content_type=content_type,
        )


def _download_landing_page(
    *,
    response,
    normalized_url: str,
    destination_path: Path,
    content_type: str,
    destination_root: Path,
    upload_id: str,
    allow_candidate_follow: bool,
) -> RemoteFetchResult:
    size_bytes = 0
    page_bytes = bytearray()

    with destination_path.open("wb") as buffer:
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break

            size_bytes += len(chunk)
            if size_bytes > MAX_LANDING_PAGE_BYTES:
                raise ValueError("Landing page exceeds the SafeGate HTML fetch limit.")

            buffer.write(chunk)
            page_bytes.extend(chunk)

    if size_bytes == 0:
        raise ValueError("Remote landing page was empty.")

    extractor = DownloadLinkExtractor(base_url=normalized_url)
    try:
        extractor.feed(page_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    candidate_details = _rank_candidate_urls(extractor.candidates, normalized_url)
    candidate_urls = [candidate.url for candidate in candidate_details]
    notes = ["landing-page-detected"]
    if candidate_urls:
        notes.append("candidate-download-links-found")

    if allow_candidate_follow and candidate_urls:
        followed_candidate = _attempt_best_candidate_download(
            candidate_details=candidate_details,
            destination_root=destination_root,
            upload_id=upload_id,
            redirects_remaining=MAX_REDIRECTS,
        )
        if followed_candidate is not None:
            candidate_result, selected_candidate_url = followed_candidate
            destination_path.unlink(missing_ok=True)
            candidate_result.notes = notes + ["candidate-download-link-followed"] + candidate_result.notes
            candidate_result.candidate_urls = candidate_urls
            candidate_result.candidate_details = candidate_details
            return RemoteFetchResult(
                stored_path=candidate_result.stored_path,
                size_bytes=candidate_result.size_bytes,
                final_url=candidate_result.final_url,
                content_type=candidate_result.content_type,
                fetch_kind="landing_page_followed",
                selected_candidate_url=selected_candidate_url,
                candidate_urls=candidate_urls,
                candidate_details=candidate_details,
                notes=candidate_result.notes,
            )

    return RemoteFetchResult(
        stored_path=destination_path,
        size_bytes=size_bytes,
        final_url=normalized_url,
        content_type=content_type,
        fetch_kind="landing_page",
        selected_candidate_url=None,
        candidate_urls=candidate_urls,
        candidate_details=candidate_details,
        notes=notes,
    )


def _attempt_best_candidate_download(
    *,
    candidate_details: list[CandidateLinkInfo],
    destination_root: Path,
    upload_id: str,
    redirects_remaining: int,
) -> tuple[RemoteFetchResult, str] | None:
    for index, candidate in enumerate(candidate_details):
        candidate_url = candidate.url
        candidate_destination = destination_root / f"{upload_id}-candidate-{index}.bin"
        try:
            candidate_result = _download_with_redirects(
                normalized_url=validate_and_normalize_url(candidate_url),
                destination_path=candidate_destination,
                redirects_remaining=redirects_remaining,
                destination_root=destination_root,
                upload_id=upload_id,
                allow_candidate_follow=False,
            )
        except Exception:
            if candidate_destination.exists():
                candidate_destination.unlink(missing_ok=True)
            continue

        if candidate_result.fetch_kind == "direct_file":
            return candidate_result, candidate_url

        if candidate_destination.exists():
            candidate_destination.unlink(missing_ok=True)

    return None


def _download_file(
    *,
    response,
    normalized_url: str,
    destination_path: Path,
    content_type: str,
) -> RemoteFetchResult:
    size_bytes = 0
    with destination_path.open("wb") as buffer:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break

            size_bytes += len(chunk)
            if size_bytes > MAX_REMOTE_BYTES:
                raise ValueError("Remote file exceeds the SafeGate fetch limit.")

            buffer.write(chunk)

    if size_bytes == 0:
        raise ValueError("Remote file was empty.")

    return RemoteFetchResult(
        stored_path=destination_path,
        size_bytes=size_bytes,
        final_url=normalized_url,
        content_type=content_type,
        fetch_kind="direct_file",
        selected_candidate_url=None,
        notes=["direct-file-detected"],
    )


def _rank_candidate_urls(candidate_urls: list[str], base_url: str) -> list[CandidateLinkInfo]:
    scored_candidates: list[CandidateLinkInfo] = []
    
    executables = (".exe", ".msi", ".apk", ".dmg", ".pkg", ".deb", ".rpm", ".bat", ".cmd", ".sh", ".bin", ".run")
    archives = (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".img")
    documents = (".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".rtf", ".txt", ".csv", ".epub")
    videos = (".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".mpeg")
    audios = (".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a")
    images = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".tiff")
    webpages = (".html", ".htm", ".php", ".asp", ".aspx", ".jsp")

    for candidate_url in candidate_urls:
        score = 0
        reasons: list[str] = []
        lowered = candidate_url.lower().split("?", 1)[0].split("#", 1)[0]
        
        if lowered.endswith(executables):
            score += 50
            reasons.append("executable-priority")
        elif lowered.endswith(archives):
            score += 40
            reasons.append("archive-priority")
        elif lowered.endswith(documents):
            score += 30
            reasons.append("document-priority")
        elif lowered.endswith(videos):
            score += 20
            reasons.append("video-priority")
        elif lowered.endswith(audios):
            score += 15
            reasons.append("audio-priority")
        elif lowered.endswith(images):
            score += 10
            reasons.append("image-priority")
        elif lowered.endswith(webpages):
            score -= 5
            reasons.append("webpage-low-priority")

        lowered_full = candidate_url.lower()
        if looks_like_download_url(candidate_url):
            score += 3
            reasons.append("download-extension")
        if any(keyword in lowered_full for keyword in ("download", "dl", "file", "server", "media")):
            score += 2
            reasons.append("download-keyword")
        if candidate_url.startswith(base_url):
            score += 1
            reasons.append("same-base-url")
        if any(keyword in lowered_full for keyword in ("play", "stream", "watch")):
            score -= 1
            reasons.append("streaming-language")
        if any(keyword in lowered_full for keyword in ("html", "htm", "php", "asp", "aspx")) and not looks_like_download_url(candidate_url):
            score -= 1
            reasons.append("page-like-url")
            
        scored_candidates.append(CandidateLinkInfo(url=candidate_url, score=score, reasons=reasons))

    scored_candidates.sort(key=lambda item: (item.score, len(item.reasons), item.url), reverse=True)
    ordered = [candidate for candidate in scored_candidates if candidate.score > 0]
    if not ordered:
        ordered = scored_candidates
    return ordered[:10]


def looks_like_download_url(url: str) -> bool:
    lowered = url.lower().split("?", 1)[0].split("#", 1)[0]
    extensions = (
        ".mp4",
        ".mkv",
        ".mp3",
        ".pdf",
        ".jpg",
        ".jpeg",
        ".png",
        ".webp",
        ".zip",
        ".rar",
        ".7z",
        ".docx",
        ".xlsx",
        ".pptx",
        ".exe",
        ".msi",
        ".apk",
        ".iso",
        ".img",
    )
    return lowered.endswith(extensions)
