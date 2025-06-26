#!/usr/bin/env python3

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

def calculate_file_hash(filepath: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def generate_integrity_manifest(base_dir: str = ".") -> dict:
    manifest = {
        "version": "1.0.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files": {}
    }
    
    files_to_check = [
        "main.py",
        "requirements.txt",
        "security/test_signature.py", 
        "security/test_full_flow.py"
    ]
    
    for file_path in files_to_check:
        full_path = os.path.join(base_dir, file_path)
        if os.path.exists(full_path):
            file_hash = calculate_file_hash(full_path)
            file_size = os.path.getsize(full_path)
            manifest["files"][file_path] = {
                "sha256": file_hash,
                "size": file_size
            }
    
    return manifest

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    manifest = generate_integrity_manifest(script_dir)
    
    output_file = os.path.join(script_dir, "integrity.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    
    print(f"[+] Манифест интегрити сгенерирован: {output_file}")
    print(f"[+] Проверено файлов: {len(manifest['files'])}")

if __name__ == "__main__":
    main() 