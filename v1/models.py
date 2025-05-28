from pydantic import BaseModel

class SessionData(BaseModel):
    Arch: str
    Burned: bool
    Extensions: dict
    GID: str
    OS: str
    PID: int
    Proxy_URL: str
    Remote_Address: str
    UID: str
    Username: str
    Version: str
    status: str
    Active_C2: str
    session_id: str

class SessionPayload(BaseModel):
    Hostname: str
    Name: str
    Filename: str
    Reconnect_Interval: int
    session_data: SessionData