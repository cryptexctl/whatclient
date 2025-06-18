from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel
from typing import Dict, Optional, List, Callable
from datetime import datetime, timedelta
import uuid
import hmac
import hashlib
import os
import base64

SECRET_KEY = os.environ.get("API_SECRET_KEY", "lainapi.gay").encode('utf-8')
EPHEMERAL_KEY = os.urandom(32)

def xor_cipher(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_data(data: str) -> str:
    encrypted_bytes = xor_cipher(data.encode('utf-8'), EPHEMERAL_KEY)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_data(encoded_data: str) -> str:
    decoded_bytes = base64.b64decode(encoded_data.encode('utf-8'))
    decrypted_bytes = xor_cipher(decoded_bytes, EPHEMERAL_KEY)
    return decrypted_bytes.decode('utf-8')

class SignedAPIRoute(APIRoute):
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            signature_header = request.headers.get("X-Signature")
            if not signature_header:
                raise HTTPException(status_code=403, detail="X-Signature header is missing.")

            data_to_sign = b""
            if request.method in ["POST", "PUT"]:
                body = await request.body()
                request._body = body
                data_to_sign = body
            elif request.method == "GET":
                data_to_sign = request.url.path.encode('utf-8')
            
            if not data_to_sign:
                 return await original_route_handler(request)

            expected_signature = hmac.new(SECRET_KEY, data_to_sign, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature_header, expected_signature):
                raise HTTPException(status_code=403, detail="Invalid signature.")

            return await original_route_handler(request)

        return custom_route_handler


app = FastAPI()
app.router.route_class = SignedAPIRoute

class RequestClientPayload(BaseModel):
    requester_id: int
    target_id: int

class SubmitTaskPayload(BaseModel):
    request_id: str
    client_name: str

class ClientRequest:
    def __init__(self, requester_id: int, target_id: int):
        self.request_id = str(uuid.uuid4())
        self.requester_id = requester_id
        self.target_id = target_id
        self.status = "pending"  # pending -> completed | expired
        self.result: Optional[str] = None
        self.timestamp = datetime.now()

PENDING_REQUESTS: Dict[str, ClientRequest] = {}
REQUEST_TIMEOUT_MINUTES = 2

def cleanup_expired_requests():
    """Removes requests older than REQUEST_TIMEOUT_MINUTES."""
    now = datetime.now()
    expired_ids = [
        req_id for req_id, req in PENDING_REQUESTS.items()
        if now - req.timestamp > timedelta(minutes=REQUEST_TIMEOUT_MINUTES)
    ]
    for req_id in expired_ids:
        del PENDING_REQUESTS[req_id]

def get_client_name_from_package(package_name: str) -> str:
    """Maps package name to a user-friendly client name."""
    client_map = {
        "com.exteragram.messenger": "exteraGram",
        "com.radolyn.ayugram": "AyuGram",
    }
    return client_map.get(package_name, "Unknown Client")

@app.post("/requestClient")
async def request_client(payload: RequestClientPayload):
    cleanup_expired_requests()
    
    new_request = ClientRequest(
        requester_id=payload.requester_id,
        target_id=payload.target_id
    )
    PENDING_REQUESTS[new_request.request_id] = new_request
    
    return {"request_id": new_request.request_id}

@app.get("/getTasks/{user_id}")
async def get_tasks(user_id: int):
    """Periodically polled by Bob's plugin to see if anyone is asking for his client."""
    cleanup_expired_requests()
    
    tasks = [
        req.request_id for req in PENDING_REQUESTS.values()
        if req.target_id == user_id and req.status == "pending"
    ]
    
    return {"tasks": tasks}

@app.post("/submitTaskResult")
async def submit_task_result(payload: SubmitTaskPayload):
    """Used by Bob's plugin to submit his client name for a specific request."""
    request = PENDING_REQUESTS.get(payload.request_id)
    
    if not request or request.status != "pending":
        raise HTTPException(status_code=404, detail="Request not found or already processed.")
        
    client_name = get_client_name_from_package(payload.client_name)
    request.result = encrypt_data(client_name)
    request.status = "completed"
    
    return {"status": "success"}

@app.get("/getRequestResult/{request_id}")
async def get_request_result(request_id: str):
    """Periodically polled by Alice's plugin to get the result."""
    request = PENDING_REQUESTS.get(request_id)

    if not request:
        return {"status": "expired"}
        
    if request.status == "completed":
        try:
            client_name = decrypt_data(request.result)
        except Exception:
            raise HTTPException(status_code=500, detail="Could not decrypt result.")
        del PENDING_REQUESTS[request_id]
        return {"status": "completed", "client_name": client_name}
    
    return {"status": "pending"} 