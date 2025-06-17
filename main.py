from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
import secrets
import json
from typing import Dict, Optional
from datetime import datetime, timedelta
import base64
import os

app = FastAPI()

class ClientInfo(BaseModel):
    package_name: str
    device_model: str
    android_version: str

class Session:
    def __init__(self, session_id: str, client_key: str):
        self.session_id = session_id
        self.client_key = client_key
        self.client_info = None
        self.created_at = datetime.now()

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
    client_key = base64.b64encode(os.urandom(32)).decode('utf-8')
    sessions[session_id] = Session(session_id, client_key)
    return session_id, client_key

def get_session(session_id: str, client_key: str) -> Optional[Session]:
    session = sessions.get(session_id)
    if not session or session.client_key != client_key:
        return None
    return session

@app.get("/extera/whatClient")
async def get_session_key():
    cleanup_old_sessions()
    session_id, client_key = generate_session()
    return {
        "session_id": session_id,
        "client_key": client_key
    }

@app.post("/extera/myClient")
async def set_client_info(
    client_info: ClientInfo,
    x_session_id: str = Header(...),
    x_client_key: str = Header(...)
):
    session = get_session(x_session_id, x_client_key)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
        
    session.client_info = client_info
    return {"status": "ok"}

@app.get("/extera/whatClient/{user_id}")
async def get_client_info(
    user_id: int,
    x_session_id: str = Header(...),
    x_client_key: str = Header(...)
):
    session = get_session(x_session_id, x_client_key)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
        
    if not session.client_info:
        return {"client_name": "Unknown Client"}
        
    if session.client_info.package_name == "com.exteragram.messenger":
        return {"client_name": "exteraGram"}
    elif session.client_info.package_name == "com.radolyn.ayugram":
        return {"client_name": "ayuGram"}
    else:
        return {"client_name": "Official Telegram"} 