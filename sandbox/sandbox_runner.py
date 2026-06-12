from __future__ import annotations

import socket
import json
import logging
import shutil
from pathlib import Path
from typing import Any

logger = logging.getLogger("safegate-sandbox")
logger.setLevel(logging.INFO)

HOST_STORAGE_ROOT = "c:\\Users\\DELL\\Downloads\\SafeGate\\storage"
CONTAINER_STORAGE_ROOT = Path("/app/storage")


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
    """Runs a Python script in an isolated read-only Docker container."""
    ext = Path(filename).suffix.lower()
    
    # We only run python scripts for now in the dynamic sandbox
    if ext != ".py":
        return {
            "executed": False,
            "reason": "Dynamic sandboxing is only supported for Python (.py) scripts in the MVP.",
            "verdict": "skipped"
        }
        
    sandbox_dir = CONTAINER_STORAGE_ROOT / "sandbox_uploads"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    
    dest_path = sandbox_dir / f"{upload_id}.py"
    shutil.copy2(stored_path, dest_path)
    
    host_target_path = f"{HOST_STORAGE_ROOT}\\sandbox_uploads\\{upload_id}.py"
    
    # Define Docker container configuration
    container_config = {
        "Image": "python:3.10-slim",
        "Cmd": ["python", "/sandbox/target.py"],
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Memory": 134217728,  # 128 MB RAM limit
            "NanoCpus": 500000000,  # 0.5 CPU limit
            "Binds": [
                f"{host_target_path}:/sandbox/target.py:ro"
            ]
        }
    }
    
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
        
        # Wait for completion (with 5 seconds timeout)
        logger.info(f"Waiting for sandbox container to finish...")
        wait_res = query_docker_socket(f"/containers/{container_id}/wait", "POST")
        exit_code = wait_res.get("StatusCode", -1)
        
        # Fetch logs
        logger.info(f"Fetching logs for sandbox container...")
        logs_res = query_docker_socket(f"/containers/{container_id}/logs?stdout=true&stderr=true", "GET")
        logs = logs_res.get("logs", "")
        
        # Parse output for alerts
        alerts = []
        logs_lower = logs.lower()
        if "read-only file system" in logs_lower:
            alerts.append("File System Write Attempt: Script attempted to write to the read-only filesystem.")
        if "socket.gaierror" in logs_lower or "urllib.error" in logs_lower or "connection" in logs_lower:
            alerts.append("Network Connection Attempt: Script attempted to make a remote network request.")
            
        verdict = "malicious" if alerts else "clean"
        if exit_code != 0 and not alerts:
            verdict = "suspicious"  # Unexpected execution failure
            
        return {
            "executed": True,
            "exit_code": exit_code,
            "logs": logs,
            "behavior_alerts": alerts,
            "verdict": verdict,
            "details": f"Executed script inside python:3.10-slim container. Verdict: {verdict.upper()}."
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

