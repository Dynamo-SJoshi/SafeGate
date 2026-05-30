from __future__ import annotations

import os
from pathlib import Path


_ENV_FILES = (
    Path(__file__).resolve().parents[1] / ".env",
    Path(__file__).resolve().parents[2] / ".env",
)


def load_local_env_files() -> None:
    for env_file in _ENV_FILES:
        if not env_file.exists():
            continue
        for key, value in _parse_env_file(env_file).items():
            os.environ.setdefault(key, value)


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key:
            values[key] = value
    return values
