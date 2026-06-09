import os
import clamd
from pathlib import Path

CLAMAV_URL = os.getenv("CLAMAV_URL", "tcp://clamav:3310")

def scan_file_with_clamav(file_path: Path) -> dict[str, object]:
    """Streams the file bytes to the ClamAV daemon over TCP socket."""
    if not file_path.exists():
        return {"verdict": "error", "details": "File not found for scanning."}
        
    try:
        if CLAMAV_URL.startswith("tcp://"):
            host, port = CLAMAV_URL.replace("tcp://", "").split(":")
            cd = clamd.ClamdNetworkSocket(host=host, port=int(port), timeout=30)
        else:
            cd = clamd.ClamdUnixSocket(path=CLAMAV_URL, timeout=30)
            
        # Stream file bytes directly to prevent loading heavy files into RAM
        with file_path.open("rb") as f:
            scan_res = cd.instream(f)
            
        # instream returns a dict like: {'stream': ('OK', None)} or {'stream': ('FOUND', 'Eicar-Test-Signature')}
        if not scan_res or "stream" not in scan_res:
            return {"verdict": "error", "details": "Empty scan response from ClamAV daemon."}
            
        status, virus_name = scan_res["stream"]
        if status == "OK":
            return {"verdict": "clean", "details": "No malware detected by ClamAV."}
        elif status == "FOUND":
            return {"verdict": "infected", "details": f"Infected with: {virus_name}"}
        else:
            return {"verdict": "error", "details": f"ClamAV scan status: {status}"}
            
    except Exception as exc:
        import socket
        exc_str = str(exc).lower()
        if isinstance(exc, (socket.timeout, TimeoutError)) or "timeout" in exc_str:
            return {"verdict": "timeout", "details": "ClamAV scan timed out."}
        elif isinstance(exc, ConnectionRefusedError) or "refused" in exc_str or "connection" in exc_str or "socket" in exc_str:
            return {"verdict": "unavailable", "details": "ClamAV service is temporarily unavailable."}
        return {"verdict": "error", "details": f"ClamAV connection/scan error: {str(exc)}"}

