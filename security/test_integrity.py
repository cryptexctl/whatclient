import requests
import hmac
import hashlib
import json

BASE_URL = "http://127.0.0.1:8000"
SECRET_KEY = "lainapi.gay".encode('utf-8')

def get_signature(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def make_signed_request(method: str, endpoint: str, data: dict = None):
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    body_bytes = b""
    path_bytes = endpoint.encode('utf-8')

    if data:
        body_bytes = json.dumps(data).encode('utf-8')
    
    data_to_sign = body_bytes if method.upper() in ["POST", "PUT"] else path_bytes
    signature = get_signature(SECRET_KEY, data_to_sign)
    headers["X-Signature"] = signature
    
    if method.upper() == "POST":
        return requests.post(url, headers=headers, data=body_bytes)
    else:
        return requests.get(url, headers=headers)

def test_get_official_manifest():
    print("[*] Тестирование получения официального манифеста...")
    
    try:
        response = make_signed_request("GET", "/getOfficialManifest")
        
        if response.status_code == 200:
            manifest = response.json()
            print(f"[+] SUCCESS: Получен манифест версии {manifest.get('version', 'unknown')}")
            print(f"[+] Файлов в манифесте: {len(manifest.get('files', {}))}")
            
            if "main.py" in manifest.get("files", {}):
                main_hash = manifest["files"]["main.py"]["sha256"]
                print(f"[+] Хеш main.py: {main_hash}")
            return manifest
        else:
            print(f"[-] FAILURE: Статус {response.status_code}")
            print(f"    Ответ: {response.text}")
            return None
            
    except Exception as e:
        print(f"[-] FAILURE: {e}")
        return None

def test_verify_integrity():
    print("\n[*] Тестирование проверки интегрити...")
    
    fake_manifest = {
        "version": "1.0.0",
        "files": {
            "main.py": {
                "sha256": "fake_hash_12345",
                "size": 1000
            }
        }
    }
    
    try:
        response = make_signed_request("POST", "/verifyIntegrity", 
                                     data={"client_manifest": fake_manifest})
        
        if response.status_code == 200:
            result = response.json()
            print(f"[+] SUCCESS: Статус проверки: {result.get('status')}")
            print(f"[+] Сообщение: {result.get('message')}")
            
            if result.get("status") == "fail":
                details = result.get("details", {})
                print(f"[+] Модифицированные файлы: {details.get('modified_files', [])}")
            
            return result
        else:
            print(f"[-] FAILURE: Статус {response.status_code}")
            print(f"    Ответ: {response.text}")
            return None
            
    except Exception as e:
        print(f"[-] FAILURE: {e}")
        return None

def test_valid_integrity():
    print("\n[*] Тестирование проверки с правильным манифестом...")
    
    official_manifest = test_get_official_manifest()
    if not official_manifest:
        print("[-] Не удалось получить официальный манифест для теста")
        return
    
    try:
        response = make_signed_request("POST", "/verifyIntegrity", 
                                     data={"client_manifest": official_manifest})
        
        if response.status_code == 200:
            result = response.json()
            print(f"[+] SUCCESS: Статус проверки: {result.get('status')}")
            print(f"[+] Сообщение: {result.get('message')}")
            return result
        else:
            print(f"[-] FAILURE: Статус {response.status_code}")
            
    except Exception as e:
        print(f"[-] FAILURE: {e}")

def main():
    print("=== Тесты системы интегрити ===")
    
    manifest = test_get_official_manifest()
    test_verify_integrity()
    
    if manifest:
        test_valid_integrity()
    
    print("\n=== Тесты завершены ===")
    print("ПРИМЕЧАНИЕ: Для работы тестов backend должен быть запущен")

if __name__ == "__main__":
    main() 