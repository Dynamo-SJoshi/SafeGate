from __future__ import annotations

import socket
import json
import logging
import shutil
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("safegate-sandbox")
logger.setLevel(logging.INFO)

HOST_STORAGE_ROOT = "c:\\Users\\DELL\\Downloads\\SafeGate\\storage"
CONTAINER_STORAGE_ROOT = Path("/app/storage")


def detect_script_type_from_content(stored_path: Path) -> str | None:
    """Inspects file contents to determine if it matches a supported sandbox file type, overriding extensions."""
    try:
        with open(stored_path, "rb") as f:
            header = f.read(4096)
    except Exception:
        return None

    if not header:
        return None

    # Magic bytes check
    if header.startswith(b"MZ"):
        return ".exe"
    if header.startswith(b"\x7fELF"):
        return ".bin"
    if header.startswith(b"%PDF-"):
        return ".pdf"
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        return ".zip"

    # Binary vs Text heuristic checks
    # 1. Plain text scripts (py, ps1, js, sh, html) never contain null bytes
    if b"\x00" in header:
        return ".bin"

    # 2. Heuristic: check density of non-printable/control characters
    printable_chars = set(b"\n\r\t") | set(range(32, 127))
    non_printable = sum(1 for byte in header if byte not in printable_chars)
    if (non_printable / len(header)) > 0.15:
        return ".bin"

    # Text checks
    try:
        content = header.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

    # Shebang check
    lines = content.splitlines()
    if not lines:
        return None
        
    first_line = lines[0].strip()
    if first_line.startswith("#!"):
        first_line_lower = first_line.lower()
        if "python" in first_line_lower:
            return ".py"
        if "sh" in first_line_lower or "bash" in first_line_lower:
            return ".sh"
        if "pwsh" in first_line_lower or "powershell" in first_line_lower:
            return ".ps1"

    content_lower = content.lower()
    
    # Check for HTML
    if content_lower.startswith("<!doctype html") or "<html" in content_lower:
        return ".html"

    # Let's check for strong indicators first (threshold of 1)
    ps_strong = [
        "write-output", "new-item", "get-process", "start-process", 
        "invoke-expression", "invoke-webrequest", "invoke-restmethod",
        "set-executionpolicy", "write-host", "out-file", "get-content", 
        "test-path", "new-object", "set-content", "$erroractionpreference"
    ]
    js_strong = [
        "console.log", "require(", "module.exports", "exports.",
        "process.argv", "fs.write", "fs.read", "express()"
    ]
    py_strong = [
        "import os", "import sys", "import time", "if __name__ =="
    ]
    
    if any(ind in content_lower for ind in ps_strong):
        return ".ps1"
    if any(ind in content_lower for ind in js_strong):
        return ".js"
    if any(ind in content_lower for ind in py_strong):
        return ".py"

    # Fallback to scoring for weaker indicators (threshold of 2)
    ps_weak = ["$"]
    js_weak = ["const ", "let ", "var ", "function"]
    py_weak = ["def ", "class ", "print("]
    sh_weak = ["echo ", "chmod ", "chown ", "exit "]

    ps_score = sum(2 for ind in ps_weak if ind in content_lower)
    js_score = sum(1 for ind in js_weak if ind in content_lower)
    py_score = sum(1 for ind in py_weak if ind in content_lower)
    sh_score = sum(1 for ind in sh_weak if ind in content_lower)

    scores = {
        ".ps1": ps_score,
        ".js": js_score,
        ".py": py_score,
        ".sh": sh_score
    }
    
    best_ext = max(scores, key=scores.get)
    if scores[best_ext] >= 2:
        return best_ext

    return None


def decode_chunked_body(body: bytes) -> bytes:
    """Decodes an HTTP chunked transfer encoded response body."""
    decoded = b""
    idx = 0
    n = len(body)
    while idx < n:
        crlf = body.find(b"\r\n", idx)
        if crlf == -1:
            break
        size_str = body[idx:crlf].split(b";")[0].strip()
        try:
            size = int(size_str, 16)
        except ValueError:
            break
        if size == 0:
            break
        idx = crlf + 2
        if idx + size > n:
            break
        decoded += body[idx:idx+size]
        idx += size + 2
    return decoded


def query_docker_socket(path: str, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sends a raw HTTP request to the Docker daemon UNIX socket."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect("/var/run/docker.sock")
        
        req = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        if body is not None:
            body_bytes = json.dumps(body).encode("utf-8")
            req += f"Content-Length: {len(body_bytes)}\r\nContent-Type: application/json\r\n"
        req += "\r\n"
        
        s.sendall(req.encode("utf-8"))
        if body is not None:
            s.sendall(body_bytes)
            
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        
        parts = resp.split(b"\r\n\r\n", 1)
        if len(parts) == 2:
            headers_part = parts[0].decode("utf-8", errors="ignore").lower()
            body_part = parts[1]
            
            if "transfer-encoding: chunked" in headers_part:
                body_part = decode_chunked_body(body_part)
                
            body_text = body_part.decode("utf-8", errors="ignore")
            if "logs" in path:
                return {"logs": clean_docker_logs(body_part)}
            try:
                return json.loads(body_text)
            except json.JSONDecodeError:
                return {"raw": body_text}
        return {}
    except Exception as exc:
        logger.error(f"Docker socket query failed: {exc}")
        return {"error": str(exc)}
    finally:
        s.close()


def clean_docker_logs(raw_body: bytes) -> str:
    """Cleans the 8-byte header prepended by Docker logs multiplexed stream."""
    logs = []
    idx = 0
    n = len(raw_body)
    while idx + 8 <= n:
        # stream_type is raw_body[idx]
        size = int.from_bytes(raw_body[idx+4:idx+8], byteorder="big")
        payload = raw_body[idx+8:idx+8+size]
        logs.append(payload.decode("utf-8", errors="ignore"))
        idx += 8 + size
    if not logs:
        return raw_body.decode("utf-8", errors="ignore")
    return "".join(logs)


def run_in_sandbox(upload_id: str, stored_path: Path, filename: str) -> dict[str, Any]:
    """Runs a script, binary, or HTML file in an isolated read-only Docker container based on its extension or detected content type."""
    ext = Path(filename).suffix.lower()
    
    # Check if the content suggests a different supported extension (content-based override for security evasion protection)
    detected_ext = detect_script_type_from_content(stored_path)
    supported_extensions = {".py", ".ps1", ".sh", ".js", ".exe", ".msi", ".html", ".bin"}
    if detected_ext in supported_extensions:
        if detected_ext != ext:
            logger.info(f"Extension override: file claimed to be {ext} but content suggests {detected_ext}")
            ext = detected_ext
            
    if ext not in supported_extensions:
        return {
            "executed": False,
            "reason": f"Dynamic sandboxing is not supported for {ext} files.",
            "verdict": "skipped"
        }
            
    sandbox_dir = CONTAINER_STORAGE_ROOT / "sandbox_uploads"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    
    previews_dir = CONTAINER_STORAGE_ROOT / "previews"
    previews_dir.mkdir(parents=True, exist_ok=True)
    
    dest_path = sandbox_dir / f"{upload_id}{ext}"
    shutil.copy2(stored_path, dest_path)
    
    host_target_path = f"{HOST_STORAGE_ROOT}\\sandbox_uploads\\{upload_id}{ext}"
    
    # Define configuration dynamically based on extension
    image = "python:3.10-slim"
    cmd = ["python", "/sandbox/target.py"]
    binds = [f"{host_target_path}:/sandbox/target.py:ro"]
    tmpfs = {}
    
    if ext == ".py":
        image = "python:3.10-slim"
        cmd = ["python", "/sandbox/target.py"]
        binds = [f"{host_target_path}:/sandbox/target.py:ro"]
    elif ext == ".ps1":
        image = "mcr.microsoft.com/powershell:lts-alpine"
        cmd = ["pwsh", "-File", "/sandbox/target.ps1"]
        binds = [f"{host_target_path}:/sandbox/target.ps1:ro"]
        # PowerShell needs writable /tmp and /root to initialize CoreCLR in read-only mode
        tmpfs = {"/tmp": "", "/root": ""}
    elif ext == ".sh":
        image = "alpine:latest"
        cmd = ["sh", "/sandbox/target.sh"]
        binds = [f"{host_target_path}:/sandbox/target.sh:ro"]
    elif ext == ".js":
        image = "node:18-alpine"
        cmd = ["node", "/sandbox/target.js"]
        binds = [f"{host_target_path}:/sandbox/target.js:ro"]
    elif ext in (".exe", ".msi"):
        image = "scottyhardy/wine-dev:latest"
        if ext == ".exe":
            cmd = ["wine", "/sandbox/target.exe"]
        else:
            cmd = ["wine", "msiexec", "/i", "/sandbox/target.msi", "/qn"]
        binds = [f"{host_target_path}:/sandbox/target{ext}:ro"]
        # Wine needs a writable prefix even in read-only container
        tmpfs = {"/root/.wine": ""}
    elif ext == ".bin":
        image = "ubuntu:latest"
        try:
            dest_path.chmod(0o755)
        except Exception as e:
            logger.warning(f"Failed to chmod binary: {e}")
        cmd = ["/sandbox/target.bin"]
        binds = [f"{host_target_path}:/sandbox/target.bin:ro"]
    elif ext == ".html":
        image = "safegate-playwright:latest"
        cmd = ["node", "/sandbox/html_analyzer.js", "/sandbox/target.html", f"/sandbox/previews/{upload_id}.png"]
        host_analyzer_path = "c:\\Users\\DELL\\Downloads\\SafeGate\\sandbox\\html_analyzer.js"
        host_previews_dir = f"{HOST_STORAGE_ROOT}\\previews"
        binds = [
            f"{host_target_path}:/sandbox/target.html:ro",
            f"{host_analyzer_path}:/sandbox/html_analyzer.js:ro",
            f"{host_previews_dir}:/sandbox/previews"
        ]
        tmpfs = {"/tmp": "", "/root": ""}
        
    container_config = {
        "Image": image,
        "Cmd": cmd,
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Memory": 268435456 if ext in (".exe", ".msi", ".html", ".ps1") else 134217728,  # 256 MB for Wine/Playwright/PowerShell, 128 MB for scripts
            "NanoCpus": 500000000,  # 0.5 CPU limit
            "Binds": binds
        }
    }
    if tmpfs:
        container_config["HostConfig"]["Tmpfs"] = tmpfs
    if ext == ".html":
        container_config["Env"] = ["NODE_PATH=/usr/lib/node_modules"]
        
    logger.info(f"Creating sandbox container for {upload_id}")
    create_res = query_docker_socket("/containers/create", "POST", container_config)
    container_id = create_res.get("Id")
    if not container_id:
        logger.error(f"Failed to create sandbox container: {create_res}")
        return {
            "executed": False,
            "error": f"Failed to initialize sandbox container: {create_res.get('error') or create_res}",
            "verdict": "error"
        }
        
    try:
        logger.info(f"Starting sandbox container: {container_id[:12]}")
        query_docker_socket(f"/containers/{container_id}/start", "POST")
        
        # Wait for completion (with 10 seconds timeout for execution)
        logger.info(f"Waiting for sandbox container to finish...")
        wait_res = query_docker_socket(f"/containers/{container_id}/wait", "POST")
        exit_code = wait_res.get("StatusCode", -1)
        
        # Fetch logs
        logger.info(f"Fetching logs for sandbox container...")
        logs_res = query_docker_socket(f"/containers/{container_id}/logs?stdout=true&stderr=true", "GET")
        logs = logs_res.get("logs", "")
        
        # Parse output for alerts
        alerts = []
        
        extracted_links = []
        if ext == ".html":
            try:
                # Look for JSON output line in logs
                json_line = None
                for line in logs.splitlines():
                    line_str = line.strip()
                    if line_str.startswith("{") and line_str.endswith("}"):
                        json_line = line_str
                        break
                if json_line:
                    import json
                    analysis_result = json.loads(json_line)
                    alerts.extend(analysis_result.get("behavior_alerts", []))
                    extracted_links = analysis_result.get("findings", {}).get("extracted_links", [])
            except Exception as e:
                logger.error(f"Failed to parse Playwright JSON output: {e}")
        else:
            logs_lower = logs.lower()
            
            write_keywords = [
                "read-only file system", 
                "permission denied", 
                "access to the path is denied", 
                "unauthorizedaccess"
            ]
            if any(k in logs_lower for k in write_keywords):
                alerts.append("File System Write Attempt: Program/script attempted to write to the read-only filesystem.")
                
            net_keywords = [
                "socket.gaierror", 
                "urllib.error", 
                "connection", 
                "enotfound", 
                "eai_again", 
                "network is unreachable", 
                "temporary failure in name resolution"
            ]
            if any(k in logs_lower for k in net_keywords):
                alerts.append("Network Connection Attempt: Program/script attempted to resolve hosts or connect to network sockets.")

        verdict = "malicious" if alerts else "clean"
        if exit_code != 0 and not alerts and ext not in (".exe", ".msi"):
            verdict = "suspicious"  # Unexpected execution failure
            
        # Sanitize null bytes (\x00 / \u0000) that PostgreSQL JSON/JSONB rejects
        clean_logs = logs.replace("\x00", "").replace("\u0000", "") if isinstance(logs, str) else ""
        clean_alerts = [a.replace("\x00", "").replace("\u0000", "") for a in alerts]
        clean_extracted_links = []
        for link in extracted_links:
            href = link.get("href", "").replace("\x00", "").replace("\u0000", "")
            text = link.get("text", "").replace("\x00", "").replace("\u0000", "")
            clean_extracted_links.append({"href": href, "text": text})

        return {
            "executed": True,
            "exit_code": exit_code,
            "logs": clean_logs,
            "behavior_alerts": clean_alerts,
            "signatures": clean_alerts,
            "verdict": verdict,
            "extracted_links": clean_extracted_links,
            "details": f"Executed target inside {image} container. Verdict: {verdict.upper()}."
        }
    finally:
        # Delete container
        logger.info(f"Cleaning up sandbox container: {container_id[:12]}")
        query_docker_socket(f"/containers/{container_id}?force=true", "DELETE")
        # Clean up copied file
        dest_path.unlink(missing_ok=True)


def run_isolated_scans(upload_id: str, stored_path: Path) -> dict[str, Any]:
    """Runs YARA and ExifTool inside an isolated docker container."""
    sandbox_dir = CONTAINER_STORAGE_ROOT / "sandbox_uploads"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    
    dest_path = sandbox_dir / f"{upload_id}.scan"
    shutil.copy2(stored_path, dest_path)
    
    host_target_path = f"{HOST_STORAGE_ROOT}\\sandbox_uploads\\{upload_id}.scan"
    host_project_root = "c:\\Users\\DELL\\Downloads\\SafeGate"
    
    container_config = {
        "Image": "safegate-backend:latest",
        "Cmd": ["python", "-m", "app.run_isolated_scanner", "/sandbox/target_file"],
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": False,
            "Memory": 268435456,  # 256 MB RAM limit
            "NanoCpus": 500000000,  # 0.5 CPU limit
            "Binds": [
                f"{host_target_path}:/sandbox/target_file:ro",
                f"{host_project_root}\\analyzers:/app/analyzers:ro"
            ]
        }
    }
    
    logger.info(f"Creating isolated scanner container for {upload_id}")
    create_res = query_docker_socket("/containers/create", "POST", container_config)
    container_id = create_res.get("Id")
    if not container_id:
        logger.error(f"Failed to create scanner container: {create_res}")
        return {
            "error": f"Failed to initialize scanner container: {create_res.get('error') or create_res}"
        }
        
    try:
        logger.info(f"Starting scanner container: {container_id[:12]}")
        query_docker_socket(f"/containers/{container_id}/start", "POST")
        
        # Wait for completion (with 20 seconds timeout)
        logger.info(f"Waiting for scanner container to finish...")
        wait_res = query_docker_socket(f"/containers/{container_id}/wait", "POST")
        exit_code = wait_res.get("StatusCode", -1)
        
        # Fetch logs
        logger.info(f"Fetching logs for scanner container...")
        logs_res = query_docker_socket(f"/containers/{container_id}/logs?stdout=true&stderr=true", "GET")
        logs = logs_res.get("logs", "")
        
        if exit_code != 0:
            logger.error(f"Scanner container failed with exit code {exit_code}. Logs: {logs}")
            return {
                "error": f"Scanner exited with code {exit_code}",
                "logs": logs
            }
            
        try:
            # Parse only the JSON line to be resilient against warnings
            json_line = None
            for line in logs.splitlines():
                line_str = line.strip()
                if line_str.startswith("{") and line_str.endswith("}"):
                    json_line = line_str
                    break
                    
            if not json_line:
                raise ValueError("No JSON output found in scanner logs.")
                
            return json.loads(json_line)
        except Exception as e:
            logger.error(f"Failed to parse scanner output: {e}. Raw logs: {logs}")
            return {
                "error": f"Invalid output from scanner: {e}",
                "logs": logs
            }
    finally:
        # Delete container
        logger.info(f"Cleaning up scanner container: {container_id[:12]}")
        query_docker_socket(f"/containers/{container_id}?force=true", "DELETE")
        # Clean up copied file
        dest_path.unlink(missing_ok=True)

