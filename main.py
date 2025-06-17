from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
import secrets
import json
from typing import Dict, Optional
from datetime import datetime, timedelta
import base64
import os
import hashlib

app = FastAPI()

class ClientInfo(BaseModel):
    package_name: str
    device_model: str
    android_version: str

class ClientKey(BaseModel):
    client_key: str

class Session:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.client_info = None
        self.client_key = None
        self.created_at = datetime.now()

user_clients: Dict[str, Dict] = {}

sessions: Dict[str, Session] = {}

def cleanup_old_sessions():
    now = datetime.now()
    old_sessions = [
        sid for sid, session in sessions.items()
        if now - session.created_at > timedelta(hours=1)
    ]
    for sid in old_sessions:
        del sessions[sid]

def generate_session():
    session_id = secrets.token_hex(16)
    sessions[session_id] = Session(session_id)
    return session_id

def verify_client_key(session_id: str, client_key: str) -> bool:
    expected_key = hashlib.sha256(session_id.encode()).hexdigest()
    return client_key == expected_key

def get_client_name(package_name: str) -> str:
    if package_name == "com.exteragram.messenger":
        return "exteraGram"
    elif package_name == "com.radolyn.ayugram":
        return "ayuGram"
    elif package_name == "org.telegram.messenger":
        return "Official Telegram"
    else:
        return "Unknown Client"

@app.post("/whatClient")
async def init_client_check(client_info: ClientInfo):
    cleanup_old_sessions()
    session_id = generate_session()
    sessions[session_id].client_info = client_info
    return {"session_id": session_id}

@app.post("/whatClient/{session_id}")
async def verify_client(session_id: str, client_key: ClientKey):
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    if not verify_client_key(session_id, client_key.client_key):
        raise HTTPException(status_code=403, detail="Invalid client key")
        
    if not session.client_info:
        raise HTTPException(status_code=400, detail="No client info")
        
    user_clients[session.client_info.package_name] = {
        "client_info": session.client_info,
        "cached_at": datetime.now()
    }
    
    return {"client_name": get_client_name(session.client_info.package_name)} 