import json
import subprocess
from pathlib import Path

def extract_metadata_with_exiftool(file_path: Path) -> dict[str, object]:
    """Runs exiftool to extract metadata as JSON."""
    try:
        result = subprocess.run(
            ["exiftool", "-json", str(file_path)],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode == 0:
            parsed = json.loads(result.stdout)
            if parsed and isinstance(parsed, list):
                metadata = parsed[0]
                metadata.pop("SourceFile", None)
                metadata.pop("Directory", None)
                return {"status": "success", "metadata": metadata}
        return {"status": "error", "details": f"ExifTool returned code {result.returncode}"}
    except Exception as exc:
        return {"status": "error", "details": f"ExifTool execution error: {str(exc)}"}
