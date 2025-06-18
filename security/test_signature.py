import requests
import hmac
import hashlib
import json

# --- Config ---
BASE_URL = "http://127.0.0.1:8000"
# WARNING: This must match the key used by the server!
# The server reads it from the API_SECRET_KEY environment variable.
SECRET_KEY = "lainapi.gay".encode('utf-8')

def get_signature(key: bytes, data: bytes) -> str:
    """Computes HMAC-SHA256 signature."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def test_endpoint(method: str, endpoint: str, data: dict = None, expected_status: int = 200, use_valid_signature: bool = True):
    """
    Tests a single endpoint with specified parameters.
    """
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    body_bytes = b""
    path_bytes = endpoint.encode('utf-8')

    if data:
        body_bytes = json.dumps(data).encode('utf-8')
    
    # Data to be signed depends on the request method
    data_to_sign = body_bytes if method.upper() in ["POST", "PUT"] else path_bytes

    if use_valid_signature:
        signature = get_signature(SECRET_KEY, data_to_sign)
    else:
        # Use a wrong key to generate an invalid signature
        invalid_key = b'wrong_secret_key'
        signature = get_signature(invalid_key, data_to_sign)

    headers["X-Signature"] = signature
    
    try:
        if method.upper() == "POST":
            response = requests.post(url, headers=headers, data=body_bytes)
        else: # GET
            response = requests.get(url, headers=headers)
        
        print(f"[*] Testing {method} {endpoint}... ", end="")
        
        if response.status_code == expected_status:
            print(f"SUCCESS (Status: {response.status_code})")
            return True
        else:
            print(f"FAILURE (Expected: {expected_status}, Got: {response.status_code})")
            print(f"    Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"FAILURE: Request to {url} failed: {e}")
        return False

def run_tests():
    print("--- Running Signature Security Tests ---")
    
    # Test cases for /requestClient
    valid_request_payload = {"requester_id": 123, "target_id": 456}
    test_endpoint("POST", "/requestClient", data=valid_request_payload, expected_status=200, use_valid_signature=True)
    test_endpoint("POST", "/requestClient", data=valid_request_payload, expected_status=403, use_valid_signature=False)

    # Test cases for /getTasks/{user_id}
    test_endpoint("GET", "/getTasks/456", expected_status=200, use_valid_signature=True)
    test_endpoint("GET", "/getTasks/456", expected_status=403, use_valid_signature=False)

    # Test cases for /submitTaskResult
    submit_payload = {"request_id": "test-id", "client_name": "com.exteragram.messenger"}
    test_endpoint("POST", "/submitTaskResult", data=submit_payload, expected_status=404, use_valid_signature=True) # 404 is expected as request_id is not real
    test_endpoint("POST", "/submitTaskResult", data=submit_payload, expected_status=403, use_valid_signature=False)

    # Test cases for /getRequestResult/{request_id}
    test_endpoint("GET", "/getRequestResult/test-id", expected_status=200, use_valid_signature=True) # 200 is expected as server returns {"status": "expired"}
    test_endpoint("GET", "/getRequestResult/test-id", expected_status=403, use_valid_signature=False)
    
    print("\n--- Tests Finished ---")
    print("NOTE: For this test to work, the backend server must be running.")
    print(f"Ensure the server is using the same SECRET_KEY: '{SECRET_KEY.decode('utf-8')}'")

if __name__ == "__main__":
    run_tests() 