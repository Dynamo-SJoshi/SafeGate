import subprocess
import os
import sys

def main():
    # Read environment variables
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    port = os.getenv("PORT", "8000")
    
    print("--------------------------------------------------")
    print(f"Starting RQ Background Scan Worker (connecting to {redis_url})...")
    # Start the worker in the background
    worker_proc = subprocess.Popen([
        "rq", "worker", "scans", 
        "--url", redis_url
    ])
    
    print(f"Starting FastAPI Backend Server on port {port}...")
    print("--------------------------------------------------")
    try:
        # Start uvicorn in the foreground (blocks until server stops)
        subprocess.run([
            "uvicorn", "backend.app.main:app", 
            "--host", "0.0.0.0", 
            "--port", port
        ], check=True)
    except KeyboardInterrupt:
        print("\nStopping services...")
    finally:
        # Ensure the background worker is cleaned up on exit
        worker_proc.terminate()
        worker_proc.wait()
        print("Services stopped.")

if __name__ == "__main__":
    main()
