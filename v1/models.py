from datetime import datetime, UTC
from typing import Optional, List, Any, Annotated, Dict
from pydantic import BaseModel, EmailStr, Field, ConfigDict, BeforeValidator, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema
from bson import ObjectId
import json

# ObjectId validation and serialization
def validate_object_id(v: Any) -> ObjectId:
    if isinstance(v, ObjectId):
        return v
    if not ObjectId.is_valid(str(v)):
        raise ValueError("Invalid ObjectId")
    return ObjectId(str(v))

def serialize_object_id(obj: ObjectId) -> str:
    return str(obj)

# Custom ObjectId type with Pydantic v2 support
class PyObjectId(ObjectId):
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Any, _handler: GetJsonSchemaHandler) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.str_schema(),
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(ObjectId),
                core_schema.chain_schema([
                    core_schema.str_schema(),
                    core_schema.no_info_plain_validator_function(validate_object_id)
                ])
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                serialize_object_id,
                return_schema=core_schema.str_schema(),
                when_used='json'
            )
        )

# Base model with MongoDB support
class MongoBaseModel(BaseModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
        from_attributes=True
    )

# User metadata models
class GeoLocation(MongoBaseModel):
    ip: str
    city: str
    country: str
    latitude: float = 0
    longitude: float = 0
    date: datetime = Field(default_factory=datetime.utcnow)

class ActionLog(MongoBaseModel):
    action: str
    details: str
    date: datetime = Field(default_factory=datetime.utcnow)

class PageVisit(MongoBaseModel):
    url: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ApiCall(MongoBaseModel):
    route: str
    method: str
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class FailedLoginAttempt(MongoBaseModel):
    ip: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    reason: str

class SessionToken(MongoBaseModel):
    token: str
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    ip: str

class PasswordChange(MongoBaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class UserMetadata(MongoBaseModel):
    """User metadata model"""
    account_created_at: datetime
    last_active: datetime
    total_active_hours_per_day: Dict[str, float] = Field(default_factory=dict)
    ip_addresses: List[Dict[str, Any]] = Field(default_factory=list)
    locations: List[GeoLocation] = Field(default_factory=list)
    user_agents: List[Dict[str, Any]] = Field(default_factory=list)
    device_fingerprints: List[Dict[str, Any]] = Field(default_factory=list)
    actions: List[ActionLog] = Field(default_factory=list)
    pages_visited: List[PageVisit] = Field(default_factory=list)
    api_calls_made: List[ApiCall] = Field(default_factory=list)
    failed_login_attempts: List[FailedLoginAttempt] = Field(default_factory=list)
    session_tokens_issued: List[SessionToken] = Field(default_factory=list)
    password_change_history: List[PasswordChange] = Field(default_factory=list)
    last_ip_change: Optional[datetime] = None
    last_location_change: Optional[datetime] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "account_created_at": "2024-03-10T04:49:48.473+00:00",
                "last_active": "2024-03-10T04:49:48.473+00:00",  # Updated example
                "total_active_hours_per_day": {
                    "2024-03-10": 1.5
                },
                "ip_addresses": [
                    {
                        "ip": "192.168.1.1",
                        "timestamp": "2024-03-10T04:49:48.473+00:00"
                    }
                ],
                "locations": [
                    {
                        "city": "New York",
                        "country": "USA",
                        "latitude": 40.7128,
                        "longitude": -74.0060,
                        "date": "2024-03-10T04:49:48.473+00:00"
                    }
                ],
                "user_agents": [
                    {
                        "user_agent": "Mozilla/5.0...",
                        "timestamp": "2024-03-10T04:49:48.473+00:00"
                    }
                ],
                "device_fingerprints": [
                    {
                        "device_fingerprint": "abc123"
                    }
                ],
                "actions": [
                    {
                        "action": "login",
                        "details": "User logged in",
                        "date": "2024-03-10T04:49:48.473+00:00"
                    }
                ],
                "pages_visited": [
                    {
                        "url": "/dashboard",
                        "timestamp": "2024-03-10T04:49:48.473+00:00"
                    }
                ],
                "api_calls_made": [
                    {
                        "route": "/api/user/activity",
                        "method": "POST",
                        "timestamp": "2024-03-10T04:49:48.473+00:00"
                    }
                ],
                "failed_login_attempts": [
                    {
                        "ip": "192.168.1.1",
                        "timestamp": "2024-03-10T04:49:48.473+00:00",
                        "reason": "Invalid password"
                    }
                ],
                "session_tokens_issued": [
                    {
                        "token": "eyJ0eXAi...",
                        "issued_at": "2024-03-10T04:49:48.473+00:00",
                        "expires_at": "2024-03-10T05:19:48.473+00:00",
                        "ip": "192.168.1.1"
                    }
                ],
                "password_change_history": [
                    {
                        "timestamp": "2024-03-10T04:49:48.473+00:00"
                    }
                ]
            }
        }
    )

# User models
class UserBase(MongoBaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern="^[a-zA-Z0-9_-]+$",
        description="Username must be 3-50 characters long and can only contain letters, numbers, underscores, and hyphens",
        error_messages={
            "min_length": "Username must be at least 3 characters long",
            "max_length": "Username cannot be longer than 50 characters",
            "pattern": "Username can only contain letters, numbers, underscores, and hyphens"
        }
    )
    email: EmailStr = Field(
        ...,
        description="Please enter a valid email address",
        error_messages={
            "type": "Please enter a valid email address",
            "format": "Please enter a valid email address"
        }
    )
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    metadata: Optional[UserMetadata] = Field(default_factory=UserMetadata)

class UserCreate(MongoBaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern="^[a-zA-Z0-9_-]+$",
        description="Username must be 3-50 characters long and can only contain letters, numbers, underscores, and hyphens",
        error_messages={
            "min_length": "Username must be at least 3 characters long",
            "max_length": "Username cannot be longer than 50 characters",
            "pattern": "Username can only contain letters, numbers, underscores, and hyphens"
        }
    )
    email: EmailStr = Field(
        ...,
        description="Please enter a valid email address",
        error_messages={
            "type": "Please enter a valid email address",
            "format": "Please enter a valid email address"
        }
    )
    password: str = Field(
        ...,
        min_length=4,
        description="Password must be at least 4 characters long",
        error_messages={
            "min_length": "Password must be at least 4 characters long"
        }
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "johndoe",
                "email": "john@example.com",
                "password": "pass123"
            }
        }
    )

class UserInDB(UserBase):
    hashed_password: str
    id: Optional[PyObjectId] = Field(alias="_id", default=None)

class User(UserBase):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)

class UserUpdate(MongoBaseModel):
    """Model for updating user information"""
    username: Optional[str] = Field(
        None,
        min_length=3,
        max_length=50,
        pattern="^[a-zA-Z0-9_-]+$",
        description="Username must be 3-50 characters long and can only contain letters, numbers, underscores, and hyphens"
    )
    email: Optional[EmailStr] = Field(
        None,
        description="Please enter a valid email address"
    )
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "johndoe",
                "email": "john@example.com",
                "is_active": True,
                "is_admin": False
            }
        }
    )

class UserResponse(MongoBaseModel):
    """Model for user API responses"""
    id: PyObjectId = Field(alias="_id")
    username: str
    email: EmailStr
    is_active: bool
    is_admin: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    metadata: Optional[UserMetadata] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "_id": "507f1f77bcf86cd799439011",
                "username": "johndoe",
                "email": "john@example.com",
                "is_active": True,
                "is_admin": False,
                "created_at": "2024-03-10T04:49:48.473+00:00",
                "last_login": "2024-03-10T05:19:48.473+00:00"
            }
        }
    )

# Authentication models
class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    token: str
    token_type: str
    user: Dict[str, Any]  # This will contain username, email, and is_admin

class TokenData(BaseModel):
    username: Optional[str] = None

# Session models
class SliverSession(MongoBaseModel):
    """Model for storing Sliver C2 session information"""
    session_id: str = Field(
        ...,
        unique=True,
        min_length=1,
        description="Unique identifier for the Sliver session"
    )
    name: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)
    uid: str = Field(..., min_length=1)
    gid: str = Field(..., min_length=1)
    os: str = Field(..., pattern="^(windows|linux|darwin)$")
    arch: str = Field(..., pattern="^(amd64|x86|arm|arm64)$")
    transport: str = Field(..., pattern="^(tcp|udp|http|https|dns|mtls|wg)$")
    remote_address: str = Field(
        ...,
        pattern="^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}$"
    )
    pid: int = Field(..., gt=0)
    filename: str = Field(..., min_length=1)
    active_c2: str = Field(
        ...,
        pattern="^https?://[\\w\\-]+(\\.[\\w\\-]+)+(:[0-9]+)?(/[\\w\\-./?%&=]*)?$"
    )
    version: str = Field(..., min_length=1)
    reconnect_interval: int = Field(..., ge=0)
    proxy_url: str = Field(default="")
    burned: bool = Field(default=False)
    extensions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional session extensions and metadata"
    )
    is_dead: bool = Field(default=False)
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the session was first seen"
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the session was last seen"
    )
    id: Optional[PyObjectId] = Field(alias="_id", default=None)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "aae73700-05d2-4ddf-8585-ef2dbd6480b2",
                "name": "CONSERVATION_FUNCTION",
                "hostname": "Arjun",
                "username": "ARJUN\\verma",
                "uid": "S-1-5-21-3069436526-1816513034-3893018473-1001",
                "gid": "S-1-5-21-3069436526-1816513034-3893018473-1001",
                "os": "windows",
                "arch": "amd64",
                "transport": "http",
                "remote_address": "192.168.198.59:55919",
                "pid": 7392,
                "filename": "C:\\Users\\verma\\Downloads\\shared\\CONSERVATION_FUNCTION.exe",
                "active_c2": "https://192.168.198.123",
                "version": "10 build 19045 x86_64",
                "reconnect_interval": 60000000000,
                "proxy_url": "",
                "burned": False,
                "extensions": {},
                "is_dead": False,
                "first_seen": "2024-03-10T04:49:48.473+00:00",
                "last_seen": "2024-03-10T04:49:48.473+00:00"
            }
        }
    )

# Command models
class CommandItem(BaseModel):
    command: str = Field(..., min_length=1)

class ListenerCommandItem(BaseModel):
    command: str = Field(..., min_length=1)
    config: Dict[str, Any] = Field(default_factory=dict)

class GenerateCommandItem(BaseModel):
    command: str = Field(..., min_length=1)
    config: Dict[str, Any] = Field(default_factory=dict)

# Error response model
class ErrorResponse(BaseModel):
    detail: str

# Connection models
class ConnectionBase(MongoBaseModel):
    name: str
    config: str  # Store as string since it's JSON
    created_by: PyObjectId
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = False

class ConnectionCreate(MongoBaseModel):
    name: str
    config: str  # Store as string since it's JSON

class ConnectionUpdate(MongoBaseModel):
    """Model for updating connection information"""
    name: Optional[str] = Field(
        None,
        min_length=1,
        description="Name of the connection"
    )
    config: Optional[str] = Field(
        None,
        description="Connection configuration as JSON string"
    )
    is_active: Optional[bool] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Updated Connection",
                "config": "{\"key\": \"value\"}",
                "is_active": True
            }
        }
    )

class ConnectionStatus(MongoBaseModel):
    """Model for connection status information"""
    id: PyObjectId = Field(alias="_id")
    is_active: bool
    last_used: datetime
    created_by: PyObjectId

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "_id": "507f1f77bcf86cd799439011",
                "is_active": True,
                "last_used": "2024-03-10T05:19:48.473+00:00",
                "created_by": "507f1f77bcf86cd799439012"
            }
        }
    )

class Connection(ConnectionBase):
    id: PyObjectId = Field(alias="_id")

class ConnectionResponse(MongoBaseModel):
    id: PyObjectId = Field(alias="_id")
    name: str
    created_at: datetime
    last_used: datetime
    is_active: bool
    created_by: PyObjectId
