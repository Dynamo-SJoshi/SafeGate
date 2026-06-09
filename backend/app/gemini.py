from __future__ import annotations

import json
import os
import time
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
TRANSIENT_ERROR_MARKERS = (
    "high demand",
    "temporarily unavailable",
    "quota",
    "rate limit",
    "rate limited",
    "HTTP 429",
    "HTTP 503",
)


def explain_analysis_with_gemini(analysis: dict[str, Any]) -> str:
    prompt = (
        "Explain the SafeGate technical data in very simple terms.\n"
        "Return exactly 2 lines.\n"
        "Line 1 must start with 'Summary:' and describe what the file/link appears to be.\n"
        "Line 2 must start with 'Advice:' and say if it looks safe, suspicious, or still pending, with a short reason.\n"
        "Do not use bullets or extra lines. Ensure you write complete, fully finished sentences. Do not leave quotes or statements unfinished."
    )
    analysis_block = _compact_analysis(analysis)
    raw_text = _generate_text(prompt=prompt, analysis_block=analysis_block)
    return _normalize_two_line_answer(raw_text)


def ask_gemini_about_analysis(
    *,
    analysis: dict[str, Any],
    question: str,
    history: list[dict[str, str]] | None = None,
) -> str:
    history = (history or [])[-MAX_CHAT_HISTORY_MESSAGES:]
    prompt_lines = [
        "You are helping the user understand SafeGate analysis.",
        "Answer the user's related doubt using simple terms in exactly 2 lines.",
        "Line 1 must start with 'Summary:' and answer directly.",
        "Line 2 must start with 'Advice:' and add one short follow-up reason or next step.",
        "Do not use bullets. Do not mention that you are an AI model. Ensure you write complete, fully finished sentences. Do not leave quotes or statements unfinished.",
        "If the analysis does not contain enough information, say that briefly and clearly.",
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
    return _normalize_two_line_answer(raw_text)


def build_fallback_explanation(analysis: dict[str, Any]) -> str:
    summary = _local_summary_line(analysis)
    advice = _local_advice_line(analysis)
    return "\n".join([summary, advice])


def build_fallback_chat_answer(analysis: dict[str, Any], question: str) -> str:
    summary = _local_summary_line(analysis, question=question)
    advice = _local_advice_line(analysis, question=question)
    return "\n".join([summary, advice])


import threading

_keys_lock = threading.Lock()
_api_keys_queue: list[str] = []
_keys_initialized = False


def _initialize_keys() -> None:
    global _keys_initialized, _api_keys_queue
    with _keys_lock:
        if _keys_initialized:
            return
        
        # Check GEMINI_API_KEYS, GEMINI_API_KEY, or GOOGLE_API_KEY (comma separated)
        keys_str = os.getenv("GEMINI_API_KEYS") or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if keys_str:
            _api_keys_queue = [k.strip("'\" \t\r\n") for k in keys_str.split(",") if k.strip("'\" \t\r\n")]
        
        _keys_initialized = True


def _get_keys_list() -> list[str]:
    _initialize_keys()
    with _keys_lock:
        return list(_api_keys_queue)


def _move_key_to_end(key: str) -> None:
    with _keys_lock:
        if key in _api_keys_queue:
            _api_keys_queue.remove(key)
            _api_keys_queue.append(key)


def _generate_text(*, prompt: str, analysis_block: str | None) -> str:
    keys = _get_keys_list()
    if not keys:
        raise ValueError(
            "No API keys configured. Set GEMINI_API_KEYS (comma-separated) or GEMINI_API_KEY in backend/.env"
        )

    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    base_url = f"{GEMINI_API_BASE}/{urllib.parse.quote(model, safe='')}:generateContent"

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
            "maxOutputTokens": 512,
        },
        "safetySettings": [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_NONE",
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_NONE",
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_NONE",
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_NONE",
            },
        ],
    }

    last_error: Exception | None = None

    for api_key in keys:
        url_with_key = f"{base_url}?key={urllib.parse.quote(api_key)}"
        request = urllib.request.Request(
            url_with_key,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
            },
        )

        response_data = None
        for attempt in range(2):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    response_data = json.loads(response.read().decode("utf-8"))
                
                text = _extract_text(response_data)
                if not text:
                    raise RuntimeError("Gemini API returned no usable text.")
                return text
                
            except urllib.error.HTTPError as exc:
                error_text = exc.read().decode("utf-8", errors="ignore")
                last_error = RuntimeError(f"Gemini API request failed with HTTP {exc.code}: {error_text}")
                
                if exc.code in {429, 503}:
                    # Move this rate-limited key to the end of the queue
                    _move_key_to_end(api_key)
                    # Try next key
                    break
                
                # For other errors, try the next key immediately
                break
                
            except urllib.error.URLError as exc:
                last_error = RuntimeError(f"Gemini API request failed: {exc.reason}")
                if attempt == 1:
                    # Move to end on network failure
                    _move_key_to_end(api_key)
                    break
                time.sleep(0.5 * (attempt + 1))
                
            except json.JSONDecodeError as exc:
                last_error = RuntimeError("Gemini API returned invalid JSON.")
                break

    if last_error is not None:
        raise last_error
    raise RuntimeError("All configured Gemini API keys failed.")


def _extract_text(response_data: dict[str, Any]) -> str:
    candidates = response_data.get("candidates") or []
    for candidate in candidates:
        content = candidate.get("content") or {}
        parts = content.get("parts") or []
        texts = [part.get("text", "") for part in parts if isinstance(part, dict) and part.get("text")]
        if texts:
            return "\n".join(texts).strip()
    return ""


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
        "error",
        "detail",
    }
    compact = {key: analysis.get(key) for key in relevant_keys if key in analysis}
    text = json.dumps(compact, ensure_ascii=False, indent=2)
    return text[:MAX_ANALYSIS_CHARS]


def _normalize_two_line_answer(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    normalized = []
    for index, line in enumerate(lines[:2]):
        if index == 0 and not line.lower().startswith("summary:"):
            line = f"Summary: {line}"
        if index == 1 and not line.lower().startswith("advice:"):
            line = f"Advice: {line}"
        normalized.append(line)
    if len(normalized) == 1:
        normalized.append("Advice: More analysis is needed before SafeGate can be more specific.")
    return "\n".join(normalized[:2])


def _local_summary_line(analysis: dict[str, Any], question: str | None = None) -> str:
    error_msg = analysis.get("error") or analysis.get("detail")
    if error_msg:
        base = f"Summary: SafeGate encountered an error during analysis: {error_msg}."
        if question:
            base = f"{base} (Question: {question[:120]})"
        return _ensure_prefix(base, "Summary:")

    source_kind = str(analysis.get("source_kind") or "file")
    source_state = str(analysis.get("source_state") or analysis.get("analysis_state") or "unknown")
    match_status = str((analysis.get("fingerprint") or {}).get("match_status") or "unknown")
    detected_type = str((analysis.get("fingerprint") or {}).get("detected_content_type") or analysis.get("content_type") or "unknown")

    if source_state == "pending":
        base = f"Summary: SafeGate has received the {source_kind}, but the analysis is still pending."
    elif source_state == "landing_page":
        base = "Summary: This looks like a webpage that points to a download, not the final file yet."
    elif source_state == "landing_page_followed":
        base = "Summary: SafeGate found a landing page and followed the most likely download file."
    elif match_status == "mismatch":
        base = f"Summary: The file does not match its expected type and looks suspicious."
    elif match_status == "match":
        base = f"Summary: The file type looks consistent and is detected as {detected_type}."
    else:
        base = f"Summary: SafeGate sees a {source_kind} with detected type {detected_type}."

    if question:
        base = f"{base} (Question: {question[:120]})"
    return _ensure_prefix(base, "Summary:")


def _local_advice_line(analysis: dict[str, Any], question: str | None = None) -> str:
    error_msg = analysis.get("error") or analysis.get("detail")
    if error_msg:
        advice = "Advice: Review the error message. Verify that the URL is public, active, and contains a downloadable file."
        if question and "safe" in question.lower():
            advice = f"{advice} Safety cannot be determined due to the scan failure."
        return _ensure_prefix(advice, "Advice:")

    source_state = str(analysis.get("source_state") or analysis.get("analysis_state") or "unknown")
    match_status = str((analysis.get("fingerprint") or {}).get("match_status") or "unknown")
    confidence = str((analysis.get("fingerprint") or {}).get("confidence") or "unknown")

    if source_state == "pending":
        advice = "Advice: Wait for deeper analysis before deciding."
    elif source_state == "landing_page":
        advice = "Advice: Open a candidate link only if the file source looks trustworthy."
    elif source_state == "landing_page_followed":
        advice = "Advice: Check the selected candidate and compare the other links too."
    elif match_status == "mismatch":
        advice = "Advice: Treat it as suspicious and avoid downloading it locally."
    elif match_status == "match" and confidence == "high":
        advice = "Advice: It looks consistent, but still review the source before trusting it."
    else:
        advice = "Advice: Review the source carefully before opening or downloading."

    if question and "safe" in question.lower():
        advice = f"{advice} Safety depends on the source and analysis state."
    return _ensure_prefix(advice, "Advice:")



def _ensure_prefix(text: str, prefix: str) -> str:
    stripped = text.strip()
    if stripped.lower().startswith(prefix.lower()):
        return stripped
    return f"{prefix} {stripped}"


def is_transient_gemini_error(error: Exception) -> bool:
    message = str(error)
    return any(marker.lower() in message.lower() for marker in TRANSIENT_ERROR_MARKERS)
