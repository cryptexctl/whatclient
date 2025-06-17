from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import uuid

app = FastAPI()

class RequestClientPayload(BaseModel):
    requester_id: int
    target_id: int

class SubmitTaskPayload(BaseModel):
    request_id: str
    client_name: str

# --- In-Memory Storage ---
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

# --- Helper Functions ---
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
        "com.radolyn.ayugram": "ayuGram",
    }
    return client_map.get(package_name, "Unknown Client")

# --- API Endpoints ---
@app.post("/requestClient")
async def request_client(payload: RequestClientPayload):
    """Initiated by Alice to request Bob's client info."""
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
    request.result = client_name
    request.status = "completed"
    
    return {"status": "success"}

@app.get("/getRequestResult/{request_id}")
async def get_request_result(request_id: str):
    """Periodically polled by Alice's plugin to get the result."""
    request = PENDING_REQUESTS.get(request_id)

    if not request:
        return {"status": "expired"}
        
    if request.status == "completed":
        client_name = request.result
        del PENDING_REQUESTS[request_id]
        return {"status": "completed", "client_name": client_name}
    
    return {"status": "pending"} 