import io
import zipfile
import requests
import sys

def main():
    backend_api = "http://localhost:8000"

    print("Generating a test ZIP archive in-memory...")
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. A short Python script
        zf.writestr(
            "folder1/script.py", 
            "def main():\n    print('Hello SafeGate!')\n\nif __name__ == '__main__':\n    main()\n"
        )
        
        # 2. A JSON config
        zf.writestr(
            "folder1/subfolder2/config.json", 
            '{\n  "app": "SafeGate",\n  "status": "active",\n  "port": 8000\n}\n'
        )
        
        # 3. A text file with more than 100 lines to test truncation
        lines = [f"Line number {i} of notes." for i in range(120)]
        zf.writestr("benign_notes.txt", "\n".join(lines) + "\n")
        
        # 4. A binary file (extension .exe)
        zf.writestr("binary_file.exe", b"\x00\x01\x02\x03MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

    zip_bytes = zip_buffer.getvalue()

    print("\nUploading ZIP archive to SafeGate backend...")
    try:
        response = requests.post(
            f"{backend_api}/upload",
            files={"file": ("test_archive.zip", zip_bytes, "application/zip")},
            timeout=10
        )
    except Exception as e:
        print(f"Error connecting to backend: {e}")
        print("Please ensure your backend server is running on http://localhost:8000")
        sys.exit(1)

    if response.status_code != 200:
        print(f"Upload failed. Status code: {response.status_code}, Body: {response.text}")
        sys.exit(1)

    data = response.json()
    upload_id = data.get("upload_id")
    print(f"Upload successful. ID: {upload_id}")

    # Fetch initial preview
    print("\nFetching initial archive preview structure...")
    preview_res = requests.post(
        f"{backend_api}/preview",
        json={"upload_id": upload_id},
        timeout=10
    )
    if preview_res.status_code != 200:
        print(f"Preview fetch failed: {preview_res.text}")
        sys.exit(1)
        
    preview_data = preview_res.json()
    print(f"Preview Kind: {preview_data.get('preview_kind')}")
    print(f"Preview Items Count: {len(preview_data.get('items', []))}")
    for item in preview_data.get("items", []):
        print(f" - {item['name']} (Size: {item['size']} B, is_directory: {item['is_directory']})")

    # Test file contents extraction endpoint
    print("\nTesting GET /preview/{upload_id}/zip-file endpoint...")
    
    # Test 1: Short Python script (previewable)
    print("\n[Test 1] Fetching folder1/script.py:")
    file_res = requests.get(
        f"{backend_api}/preview/{upload_id}/zip-file",
        params={"file_path": "folder1/script.py"},
        timeout=10
    )
    if file_res.status_code == 200:
        content_data = file_res.json()
        print(f"Success! is_binary: {content_data.get('is_binary')}")
        print("Content:")
        print(content_data.get("content"))
    else:
        print(f"Failed to fetch content: {file_res.status_code} - {file_res.text}")

    # Test 2: JSON file (previewable)
    print("\n[Test 2] Fetching folder1/subfolder2/config.json:")
    file_res = requests.get(
        f"{backend_api}/preview/{upload_id}/zip-file",
        params={"file_path": "folder1/subfolder2/config.json"},
        timeout=10
    )
    if file_res.status_code == 200:
        content_data = file_res.json()
        print(f"Success! is_binary: {content_data.get('is_binary')}")
        print("Content:")
        print(content_data.get("content"))
    else:
        print(f"Failed to fetch content: {file_res.status_code} - {file_res.text}")

    # Test 3: Large text file (>100 lines, checking truncation)
    print("\n[Test 3] Fetching benign_notes.txt (>100 lines):")
    file_res = requests.get(
        f"{backend_api}/preview/{upload_id}/zip-file",
        params={"file_path": "benign_notes.txt"},
        timeout=10
    )
    if file_res.status_code == 200:
        content_data = file_res.json()
        print(f"Success! is_binary: {content_data.get('is_binary')}")
        lines = content_data.get("content", "").split("\n")
        print(f"Returned lines count: {len(lines)}")
        print("Tail of returned content:")
        print("\n".join(lines[-5:]))
    else:
        print(f"Failed to fetch content: {file_res.status_code} - {file_res.text}")

    # Test 4: Binary file (.exe, checking safety block)
    print("\n[Test 4] Fetching binary_file.exe (non-previewable):")
    file_res = requests.get(
        f"{backend_api}/preview/{upload_id}/zip-file",
        params={"file_path": "binary_file.exe"},
        timeout=10
    )
    if file_res.status_code == 200:
        content_data = file_res.json()
        print(f"Success! is_binary: {content_data.get('is_binary')}")
        print("Content:")
        print(content_data.get("content"))
    else:
        print(f"Failed to fetch content: {file_res.status_code} - {file_res.text}")

if __name__ == "__main__":
    main()
