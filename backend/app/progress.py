from __future__ import annotations

# Global dictionary to track real-time URL download progress.
# Key: upload_id (str) -> Value: progress percentage (int, 0 to 100), or -1 for indeterminate.
progress_store: dict[str, int] = {}
