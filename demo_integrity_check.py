#!/usr/bin/env python3

import requests
import json
import hmac
import hashlib
from urllib.parse import urlparse

API_BASE_URL = "https://exteraapi.lainapi.gay"
API_SECRET_KEY = "lainapi.gay".encode('utf-8')
OFFICIAL_MANIFEST_HASH = "427b5bf4c74befd3b670fc99b66680d1171f54ffd0199baf921f6aa38ab924ad"

def make_signed_request(method: str, url: str, data: dict = None):
    """Создает подписанный запрос к API"""
    headers = {"Content-Type": "application/json"}
    body_bytes = b""
    
    if method.upper() in ["POST", "PUT"] and data:
        body_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8')
    elif method.upper() == "GET":
        parsed_url = urlparse(url)
        body_bytes = parsed_url.path.encode('utf-8')
    
    signature = hmac.new(API_SECRET_KEY, body_bytes, hashlib.sha256).hexdigest()
    headers["X-Signature"] = signature
    
    if method.upper() == "POST":
        return requests.post(url, headers=headers, data=body_bytes)
    else:
        return requests.get(url, headers=headers)

def verify_server_integrity():
    """Проверяет интегрити сервера - основная функция"""
    print(" Проверка интегрити сервера...")
    
    try:
        # Шаг 1: Получаем официальный манифест с сервера
        print(f" Запрашиваем манифест с {API_BASE_URL}/getOfficialManifest")
        
        url = f"{API_BASE_URL}/getOfficialManifest"
        response = make_signed_request("GET", url)
        
        if response.status_code != 200:
            print(f"[-] Ошибка получения манифеста: HTTP {response.status_code}")
            return False
        
        manifest = response.json()
        print(f"[-] Получен манифест версии: {manifest.get('version', 'unknown')}")
        
        # Шаг 2: Извлекаем хеш main.py из манифеста
        main_py_info = manifest.get("files", {}).get("main.py", {})
        server_hash = main_py_info.get("sha256", "")
        
        print(f"[-] Хеш main.py с сервера: {server_hash}")
        print(f"[-] Ожидаемый хеш main.py: {OFFICIAL_MANIFEST_HASH}")
        
        # Шаг 3: Сравниваем хеши
        if server_hash == OFFICIAL_MANIFEST_HASH:
            print("[OK] ПРОВЕРКА ПРОЙДЕНА: Сервер является официальным")
            print(f"[-] Проверено файлов: {len(manifest.get('files', {}))}")
            return True
        else:
            print("[-]  ВНИМАНИЕ: СЕРВЕР МОДИФИЦИРОВАН!")
            print("[-] Данный сервер может быть небезопасным!")
            return False
            
    except Exception as e:
        print(f"[-] Ошибка проверки: {str(e)}")
        return False

def demo_manual_verification():
    """Демонстрирует ручную проверку манифеста"""
    print("\n" + "="*50)
    print("[-] ДЕМОНСТРАЦИЯ РУЧНОЙ ПРОВЕРКИ МАНИФЕСТА")
    print("="*50)
    
    # Создаем поддельный манифест для демо
    fake_manifest = {
        "version": "1.0.0",
        "files": {
            "main.py": {
                "sha256": "fake_hash_abcdef123456789",
                "size": 5000
            },
            "requirements.txt": {
                "sha256": "another_fake_hash_987654321",
                "size": 50
            }
        }
    }
    
    print("[-] Отправляем поддельный манифест на проверку...")
    
    try:
        url = f"{API_BASE_URL}/verifyIntegrity"
        response = make_signed_request("POST", url, data={"client_manifest": fake_manifest})
        
        if response.status_code == 200:
            result = response.json()
            print(f"[-] Статус проверки: {result.get('status')}")
            print(f"[-] Сообщение: {result.get('message')}")
            
            if result.get("status") == "fail":
                details = result.get("details", {})
                print(f"[-] Модифицированные файлы: {details.get('modified_files', [])}")
        else:
            print(f"[-] Ошибка проверки: HTTP {response.status_code}")
            
    except Exception as e:
        print(f"[-] Ошибка: {str(e)}")

def main():
    print("[-]  ДЕМОНСТРАЦИЯ СИСТЕМЫ ПРОВЕРКИ ИНТЕГРИТИ WCLIENT")
    print("="*60)
    
    # Основная проверка интегрити
    success = verify_server_integrity()
    
    # Демонстрация ручной проверки
    demo_manual_verification()
    
    print("\n" + "="*60)
    print("[-] КАК ЭТО РАБОТАЕТ В ПЛАГИНЕ:")   
    print("1. При загрузке плагин автоматически вызывает verify_server_integrity()")
    print("2. Команды .wci или .whatclientintegrity также вызывают эту функцию")
    print("3. Если сервер скомпрометирован - показывается предупреждение")
    print("4. Встроенный хеш защищает от подмены манифеста")
    print("="*60)

if __name__ == "__main__":
    main() 