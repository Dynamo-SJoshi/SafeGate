from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .environment import load_local_env_files


load_local_env_files()

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1/models"
MAX_ANALYSIS_CHARS = 12000
MAX_CHAT_HISTORY_MESSAGES = 8


def explain_analysis_with_gemini(analysis: dict[str, Any]) -> str:
    prompt = (
        "Explain the SafeGate technical data in very simple terms using at most 2 lines. "
        "Focus on what the file/link appears to be, whether it looks safe or suspicious, and why. "
        "Do not use bullets. Do not mention internal JSON fields unless needed."
    )
    analysis_block = _compact_analysis(analysis)
    raw_text = _generate_text(prompt=prompt, analysis_block=analysis_block)
    return _limit_to_two_lines(raw_text)


def ask_gemini_about_analysis(
    *,
    analysis: dict[str, Any],
    question: str,
    history: list[dict[str, str]] | None = None,
) -> str:
    history = (history or [])[-MAX_CHAT_HISTORY_MESSAGES:]
    prompt_lines = [
        "You are helping the user understand SafeGate analysis.",
        "Answer the user's related doubt using simple terms in at most 2 lines.",
        "Do not use bullets. Do not mention that you are an AI model.",
        "If the analysis does not contain enough information, say that briefly.",
        "",
        "SAFEGATE ANALYSIS:",
        _compact_analysis(analysis),
    ]
    if history:
        prompt_lines.extend(["", "CHAT HISTORY:"])
        for item in history:
            role = item.get("role", "unknown")
            content = item.get("content", "")
            prompt_lines.append(f"{role}: {content}")
    prompt_lines.extend(["", f"USER QUESTION: {question}"])
    raw_text = _generate_text(prompt="\n".join(prompt_lines), analysis_block=None)
    return _limit_to_two_lines(raw_text)


def _generate_text(*, prompt: str, analysis_block: str | None) -> str:
    api_key = _get_api_key()
    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    url = f"{GEMINI_API_BASE}/{urllib.parse.quote(model, safe='')}:generateContent"

    if analysis_block:
        prompt = f"{prompt}\n\nANALYSIS JSON:\n{analysis_block}"

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 120,
        },
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_text = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Gemini API request failed with HTTP {exc.code}: {error_text}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Gemini API request failed: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("Gemini API returned invalid JSON.") from exc

    text = _extract_text(response_data)
    if not text:
        raise RuntimeError("Gemini API returned no usable text.")
    return text


def _extract_text(response_data: dict[str, Any]) -> str:
    candidates = response_data.get("candidates") or []
    for candidate in candidates:
        content = candidate.get("content") or {}
        parts = content.get("parts") or []
        texts = [part.get("text", "") for part in parts if isinstance(part, dict) and part.get("text")]
        if texts:
            return "\n".join(texts).strip()
    return ""


def _get_api_key() -> str:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY is not set. Add it to backend/.env or the backend terminal before starting SafeGate."
        )
    return api_key.strip()


def _compact_analysis(analysis: dict[str, Any]) -> str:
    relevant_keys = {
        "status",
        "source_kind",
        "source_state",
        "source_url",
        "selected_candidate_url",
        "candidate_urls",
        "candidate_details",
        "filename",
        "content_type",
        "size_bytes",
        "fingerprint",
        "analysis_state",
        "database_state",
        "notes",
        "preview_kind",
        "preview_title",
        "summary",
        "items",
        "text",
        "preview",
    }
    compact = {key: analysis.get(key) for key in relevant_keys if key in analysis}
    text = json.dumps(compact, ensure_ascii=False, indent=2)
    return text[:MAX_ANALYSIS_CHARS]


def _limit_to_two_lines(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) == 1:
        return lines[0]
    return "\n".join(lines[:2])
