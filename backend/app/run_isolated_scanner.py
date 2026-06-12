import sys
import json
from pathlib import Path
from app.yara_scanner import scan_file_with_yara
from app.exif_scanner import extract_metadata_with_exiftool

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided."}))
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(json.dumps({"error": f"File not found: {file_path}"}))
        sys.exit(1)

    try:
        yara_res = scan_file_with_yara(file_path)
        exif_res = extract_metadata_with_exiftool(file_path)
        
        print(json.dumps({
            "yara": yara_res,
            "exiftool": exif_res
        }))
    except Exception as e:
        print(json.dumps({"error": f"Scanners execution error: {str(e)}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()
