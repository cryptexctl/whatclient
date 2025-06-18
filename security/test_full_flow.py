import requests
import hmac
import hashlib
import json
import time

# --- Config ---
BASE_URL = "http://127.0.0.1:8000"
SECRET_KEY = "lainapi.gay".encode('utf-8')
POLL_INTERVAL_S = 0.5  # How often to poll for results
MAX_WAIT_S = 5         # Max time to wait for a result

# --- User Simulation ---
ALICE_ID = 111
BOB_ID = 222
BOB_CLIENT_PACKAGE = "com.radolyn.ayugram"
BOB_CLIENT_NAME = "AyuGram"


def get_signature(key: bytes, data: bytes) -> str:
    """Computes HMAC-SHA256 signature."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def make_request(method: str, endpoint: str, data: dict = None):
    """Helper to make a signed request and return JSON response."""
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    body_bytes = b""
    path_bytes = endpoint.encode('utf-8')

    if data:
        body_bytes = json.dumps(data).encode('utf-8')
    
    data_to_sign = body_bytes if method.upper() in ["POST", "PUT"] else path_bytes
    signature = get_signature(SECRET_KEY, data_to_sign)
    headers["X-Signature"] = signature
    
    try:
        if method.upper() == "POST":
            response = requests.post(url, headers=headers, data=body_bytes)
        else:
            response = requests.get(url, headers=headers)
        
        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed for {method} {endpoint}: {e}")
        return None

def run_simulation():
    """Simulates the entire Alice-Bob interaction."""
    print("--- Running Full Flow Simulation ---")
    
    # 1. Alice requests Bob's client
    print(f"\n[1] Alice ({ALICE_ID}) requests client info from Bob ({BOB_ID})")
    request_payload = {"requester_id": ALICE_ID, "target_id": BOB_ID}
    response_data = make_request("POST", "/requestClient", data=request_payload)
    if not response_data or "request_id" not in response_data:
        print("[-] Failed to initiate request. Aborting.")
        return
    
    request_id = response_data["request_id"]
    print(f"[+] Request initiated successfully. Request ID: {request_id}")

    # 2. Bob's plugin polls for tasks
    print(f"\n[2] Bob's plugin ({BOB_ID}) polls for tasks")
    tasks_data = make_request("GET", f"/getTasks/{BOB_ID}")
    if not tasks_data or request_id not in tasks_data.get("tasks", []):
        print("[-] Bob's plugin did not find the task. Aborting.")
        return
    print(f"[+] Bob's plugin found task: {request_id}")

    # 3. Bob's plugin submits the result
    print(f"\n[3] Bob's plugin submits its client name: '{BOB_CLIENT_PACKAGE}'")
    submit_payload = {"request_id": request_id, "client_name": BOB_CLIENT_PACKAGE}
    submit_data = make_request("POST", "/submitTaskResult", data=submit_payload)
    if not submit_data or submit_data.get("status") != "success":
        print("[-] Bob's plugin failed to submit the result. Aborting.")
        return
    print("[+] Bob's plugin submitted result successfully.")

    # 4. Alice's plugin polls for the result
    print(f"\n[4] Alice's plugin polls for the result of request {request_id}")
    start_time = time.time()
    final_result = None
    while time.time() - start_time < MAX_WAIT_S:
        print(f"    - Polling...")
        result_data = make_request("GET", f"/getRequestResult/{request_id}")
        if result_data and result_data.get("status") == "completed":
            final_result = result_data.get("client_name")
            break
        time.sleep(POLL_INTERVAL_S)

    if not final_result:
        print("[-] Alice's plugin timed out waiting for the result.")
        return

    print(f"[+] Alice received the result: '{final_result}'")
    
    # Verification
    if final_result == BOB_CLIENT_NAME:
        print("\n--- ✅ SUCCESS: Full flow completed and result is correct! ---")
    else:
        print(f"\n--- ❌ FAILURE: Result mismatch! Expected '{BOB_CLIENT_NAME}', Got '{final_result}' ---")
    
    print("NOTE: For this test to work, the backend server must be running.")

if __name__ == "__main__":
    run_simulation() 