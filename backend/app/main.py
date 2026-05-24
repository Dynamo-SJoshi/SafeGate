from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile

app = FastAPI(title="SafeGate API", version="0.1.0")

UPLOAD_ROOT = Path(tempfile.gettempdir()) / "safegate" / "uploads"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024

UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "safegate-api"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")

    upload_id = str(uuid4())
    stored_path = UPLOAD_ROOT / f"{upload_id}-{Path(file.filename).name}"
    sha256 = hashlib.sha256()
    size_bytes = 0

    try:
        with stored_path.open("wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break

                size_bytes += len(chunk)
                if size_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 50 MB MVP upload limit.",
                    )

                sha256.update(chunk)
                buffer.write(chunk)
    except HTTPException:
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    return {
        "status": "received",
        "upload_id": upload_id,
        "filename": file.filename,
        "content_type": file.content_type or "application/octet-stream",
        "size_bytes": size_bytes,
        "sha256": sha256.hexdigest(),
        "analysis_state": "pending",
    }
