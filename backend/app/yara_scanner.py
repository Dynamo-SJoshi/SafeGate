import yara
from pathlib import Path

RULES_PATH = Path("/app/analyzers/rules.yar")

def scan_file_with_yara(file_path: Path) -> dict[str, object]:
    """Compiles rules and scans the target file."""
    if not RULES_PATH.exists():
        return {"verdict": "skipped", "matches": [], "details": "No YARA rules configured."}
        
    try:
        rules = yara.compile(filepath=str(RULES_PATH))
        matches = rules.match(str(file_path))
        match_list = []
        for match in matches:
            match_list.append({
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta
            })
            
        verdict = "suspicious" if match_list else "clean"
        details = f"Matched {len(match_list)} YARA rules." if match_list else "No YARA rules matched."
        return {"verdict": verdict, "matches": match_list, "details": details}
    except Exception as exc:
        return {"verdict": "error", "matches": [], "details": f"YARA scanning failed: {str(exc)}"}
