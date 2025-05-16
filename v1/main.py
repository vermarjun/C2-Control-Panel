import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from sliver import SliverClientConfig, SliverClient
import asyncio
import time
from fastapi import Query

class Session(BaseModel):
    id: str
    name: str
    hostname: str
    username: str
    uid: str
    os: str
    arch: str
    transport: str
    remote_address: str
    pid: int
    filename: str
    last_checkin: str
    active_c2: str
    version: str

class ErrorResponse(BaseModel):
    detail: str

# Global client instance
_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the Sliver client lifecycle"""
    global _client
    # Startup code — no connection now
    yield
    # Shutdown code
    if _client is not None:
        await _client.close()
        _client = None

app = FastAPI(
    title="Sliver API",
    description="REST API for interacting with Sliver C2",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_client() -> SliverClient:
    """Get the Sliver client instance"""
    global _client
    if _client is None:
        raise HTTPException(status_code=500, detail="Sliver client not initialized")
    return _client

# @app.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Get details for a specific session"""
    print("request to session came")
    try:
        client = await get_client()
        sessions = await client.sessions()
        for session in sessions:
            if session.ID == session_id:
                return client
        raise HTTPException(status_code=404, detail="Session not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sessions/{session_id}/files")
async def list_files(session_id: str, path: Optional[str] = Query("/")):
    try:
        client = await get_client()
        sessions = await client.sessions()
        session_obj = next((s for s in sessions if s.ID == session_id), None)
        if not session_obj:
            raise HTTPException(status_code=404, detail="Session not found")

        session = await client.interact_session(session_id)

        if "windows" in session_obj.OS.lower():
            # Windows payload
            command = "cmd.exe"
            args = ["/c", f"dir {path}"]
        else:
            # *nix payload
            command = "ls"
            args = ["-la", path]

        result = await session.execute(command, args, output=True)
        output = result.result

        # You can parse dir output differently for windows or unix
        return {
            "path": path,
            "output": output
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/connected")
async def connected_or_not():
    global _client
    return _client is not None and _client.is_connected()

@app.get("/operators")
async def list_operators():
    """List all operators"""
    print("request to operators came")
    try:
        client = await get_client()
        operators = await client.operators()
        obj_to_be_returned = []
        id = 1
        for op in operators:
            obj_to_be_returned.append({"id": id, "name": op.Name})
            id += 1
        return obj_to_be_returned
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/connect")
async def connect_sliver():
    """Connect to Sliver server"""
    print("connect request came")
    try :
        global _client
        print(_client)
        if _client is None:
            config = SliverClientConfig.parse_config_file(os.path.join('./arjun.cfg'))
            _client = SliverClient(config)
        if not _client.is_connected():
            await _client.connect()
        return True
    except Exception as e:
        print("COULD NOT ESTABLISH CONNECTION WITH SLIVER SERVER!!!!")
        print(e)    
        _client = None
        return False

@app.get("/sessions")
async def list_sessions():
    print("request to sessions came")
    """List all active sessions"""
    try:
        client = await get_client()
        sessions = await client.sessions()
        sessions_to_be_returned = []
        for session in sessions:
            sessions_to_be_returned.append({"id":session.ID, "hostname":session.Hostname, "username":session.Username, "transport":session.Transport, "remoteaddress":session.RemoteAddress, "os":session.OS})
        return sessions_to_be_returned
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Service health check"""
    return {"status": "healthy"}
