from __future__ import annotations

import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin

from .security import validate_and_normalize_url

MAX_REMOTE_BYTES = 50 * 1024 * 1024
MAX_REDIRECTS = 3
REMOTE_TIMEOUT_SECONDS = 15


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_remote_file(source_url: str, upload_id: str) -> tuple[Path, int, str, str]:
    normalized_url = validate_and_normalize_url(source_url)
    destination_root = Path(tempfile.gettempdir()) / "safegate" / "remote"
    destination_root.mkdir(parents=True, exist_ok=True)
    destination_path = destination_root / f"{upload_id}.bin"

    try:
        final_url, content_type = _download_with_redirects(
            normalized_url=normalized_url,
            destination_path=destination_path,
            redirects_remaining=MAX_REDIRECTS,
        )
        size_bytes = destination_path.stat().st_size
        return destination_path, size_bytes, final_url, content_type
    except Exception:
        if destination_path.exists():
            destination_path.unlink(missing_ok=True)
        raise


def _download_with_redirects(
    *,
    normalized_url: str,
    destination_path: Path,
    redirects_remaining: int,
) -> tuple[str, str]:
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

        return normalized_url, content_type
