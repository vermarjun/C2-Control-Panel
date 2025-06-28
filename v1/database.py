import os
from datetime import datetime, timedelta, UTC
from typing import Dict, List, Optional, Any, Tuple, Union
from models import (
    # User models
    User,
    UserCreate,
    UserInDB,
    UserMetadata,
    GeoLocation,
    
    # Connection models
    Connection,
    ConnectionCreate,
    ConnectionUpdate,
    ConnectionStatus,
    ConnectionResponse,
    
    # Session models
    SliverSession,
    
    # Base models
    MongoBaseModel,
    PyObjectId,
    
    # Auth models
    Token,
    TokenData,
    
    # Utility functions
    generate_device_id
)

from jose import JWTError, jwt
from dotenv import load_dotenv
import bcrypt
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import asyncio
import geoip2.database
import geoip2.errors

# Load environment variables
load_dotenv()

# MongoDB connection settings
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "sliver_db")

# JWT settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Add these constants
IGNORED_ENDPOINTS = {
    "/api/user/activity",
    "/api/user/page-visit",
    "/auth/verify",
    "/health",
    "/connections",
    "/sessions",
    "/jobs",
    "/operators",
    "/veirfy",
    "/connected",
}

# Initialize GeoIP2 reader
try:
    geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception as e:
    print(f"Warning: Could not load GeoLite2 database: {e}")
    geoip_reader = None

# Password hashing - use direct bcrypt instead of passlib
def get_password_hash(password: str) -> str:
    """Generate password hash using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash using bcrypt"""
    try:
        return bcrypt.checkpw(
            plain_password.encode(),
            hashed_password.encode()
        )
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

# MongoDB client
client = AsyncIOMotorClient(MONGODB_URL)
db = client[DATABASE_NAME]

# Collections
users_collection = db.users
sessions_collection = db.sessions
operators_collection = db.operators
connections_collection = db.connections

async def init_db():
    """Initialize database indexes"""
    try:
        # Create unique indexes
        await users_collection.create_index("username", unique=True)
        await users_collection.create_index("email", unique=True)
        
        # Session collection indexes
        await sessions_collection.create_index("session_id", unique=True)
        await sessions_collection.create_index("device_id")  # Index for device_id queries
        await sessions_collection.create_index("last_seen", expireAfterSeconds=30*24*60*60)  # 30 days TTL
        await sessions_collection.create_index([("is_dead", 1), ("last_seen", -1)])
        await sessions_collection.create_index("remote_address")
        await sessions_collection.create_index("hostname")
        
        print("Database indexes initialized successfully")
    except Exception as e:
        print(f"Error initializing database indexes: {e}")
        raise

# User operations
async def get_user(username: str) -> Optional[UserInDB]:
    """Get user by username"""
    try:
        user_dict = await users_collection.find_one({"username": username})
        if user_dict:
            # Convert ObjectId to string for JSON serialization
            if "_id" in user_dict:
                user_dict["_id"] = str(user_dict["_id"])
            return UserInDB(**user_dict)
        return None
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

async def get_all_users() -> List[UserInDB]:
    """Get all users from the database with their metadata."""
    try:
        users = await users_collection.find().to_list(length=None)
        # Convert ObjectId to string for JSON serialization
        for user in users:
            if "_id" in user:
                user["_id"] = str(user["_id"])
        return [UserInDB(**user) for user in users]
    except Exception as e:
        print(f"Error getting all users: {e}")
        raise e

async def get_user_by_id(user_id: str) -> Optional[UserInDB]:
    """Get a user by their ID."""
    try:
        if not ObjectId.is_valid(user_id):
            return None
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            # Convert ObjectId to string for JSON serialization
            user["_id"] = str(user["_id"])
            return UserInDB(**user)
        return None
    except Exception as e:
        print(f"Error getting user by ID: {e}")
        raise e

async def get_user_by_email(email: str) -> Optional[UserInDB]:
    """Get user by email"""
    try:
        if (user := await users_collection.find_one({"email": email})) is not None:
            return UserInDB(**user)
        return None
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None

async def create_user(user: UserCreate) -> UserInDB:
    """Create a new user with initialized metadata"""
    try:
        # Check if user already exists
        if await get_user(user.username):
            raise ValueError("Username already registered")
        if await get_user_by_email(user.email):
            raise ValueError("Email already registered")

        # Create user document with initialized metadata
        user_dict = user.model_dump()
        user_dict["hashed_password"] = get_password_hash(user.password)
        del user_dict["password"]
        
        # Set default values
        user_dict["is_admin"] = False  # Explicitly set is_admin to False
        user_dict["is_active"] = True  # Explicitly set is_active to True
        
        # Initialize metadata with proper types
        now = datetime.now(UTC)
        user_dict["metadata"] = {
            "account_created_at": now,
            "last_active": now,  # Single timestamp for last activity
            "total_active_hours_per_day": {},  # Initialize as empty dict
            "ip_addresses": [],
            "locations": [],
            "user_agents": [],
            "device_fingerprint": None,
            "actions": [],
            "pages_visited": [],
            "api_calls_made": [],
            "failed_login_attempts": [],
            "session_tokens_issued": [],
            "password_change_history": []
        }
        
        # Insert user
        result = await users_collection.insert_one(user_dict)
        user_dict["_id"] = result.inserted_id
        
        return UserInDB(**user_dict)
    except Exception as e:
        print(f"Error creating user: {e}")
        raise

async def delete_user(username: str) -> bool:
    """Delete a user from the database"""
    try:
        result = await users_collection.delete_one({"username": username})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting user: {e}")
        raise

async def authenticate_user(username: str, password: str, ip: str) -> Optional[UserInDB]:
    print("Authenticating user: ", username, password, ip)
    """Authenticate user with username and password, logging failed attempts"""
    try:
        user = await get_user(username)
        print("User found: ", user)
        if not user:
            print(f"User not found: {username}")
            await log_failed_login(username, ip, "User not found")
            return None
        if not verify_password(password, user.hashed_password):
            print(f"Invalid password for user: {username}")
            await log_failed_login(username, ip, "Invalid password")
            return None
        return user
    except Exception as e:
        print(f"Authentication error: {e}")
        return None

def create_access_token(data: Dict[str, Any], ip: str) -> str:
    """Create JWT access token and log its issuance"""
    try:
        to_encode = data.copy()
        expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        # Log token issuance asynchronously
        asyncio.create_task(log_session_token(data["sub"], token, ip, expire))
        
        return token
    except Exception as e:
        print(f"Error creating access token: {e}")
        raise

# Add these utility functions at the top after imports
async def _safe_update_one(collection, query: dict, update: dict) -> bool:
    """Utility function for safe update operations with error handling"""
    try:
        result = await collection.update_one(query, update)
        return result.modified_count > 0
    except Exception as e:
        print(f"Database update error: {e}")
        return False

async def _safe_find_one(collection, query: dict) -> Optional[dict]:
    """Utility function for safe find operations with error handling"""
    try:
        return await collection.find_one(query)
    except Exception as e:
        print(f"Database find error: {e}")
        return None

async def _update_user_metadata(username: str, update_data: dict) -> bool:
    """Utility function to update user metadata"""
    return await _safe_update_one(
        users_collection,
        {"username": username},
        {"$set": update_data}
    )

async def _push_to_user_metadata(username: str, field: str, value: Any) -> bool:
    """Utility function to push data to user metadata array"""
    return await _safe_update_one(
        users_collection,
        {"username": username},
        {"$push": {f"metadata.{field}": value}}
    )

# User metadata operations
async def update_user_activity(
    username: str,
    ip: str,
    user_agent: str,
    device_fingerprint: Optional[str] = None
) -> None:
    """Update user's activity metadata with improved tracking"""
    try:
        print(f"\n=== Starting update_user_activity for {username} ===")
        print(f"Input params - IP: {ip}, User Agent: {user_agent}, Device Fingerprint: {device_fingerprint}")
        
        now = datetime.now(UTC)
        today = now.strftime("%Y-%m-%d")
        print(f"Current time: {now}, Today's date: {today}")
        
        # Get current user data
        user = await get_user(username)
        if not user:
            print(f"ERROR: User {username} not found!")
            return
        if not user.metadata:
            print(f"ERROR: No metadata found for user {username}!")
            return
            
        print(f"Current user metadata state:")
        print(f"- Last active: {user.metadata.last_active}")
        print(f"- Total active hours today: {user.metadata.total_active_hours_per_day.get(today, 0) if user.metadata.total_active_hours_per_day else 0}")
        print(f"- IP addresses count: {len(user.metadata.ip_addresses) if user.metadata.ip_addresses else 0}")
        print(f"- Locations count: {len(user.metadata.locations) if user.metadata.locations else 0}")
        print(f"- User agents count: {len(user.metadata.user_agents) if user.metadata.user_agents else 0}")
        print(f"- Device fingerprints count: {len(user.metadata.device_fingerprints) if user.metadata.device_fingerprints else 0}")
            
        # Get current last_active timestamp
        last_active = user.metadata.last_active
        if last_active and last_active.tzinfo is None:
            last_active = last_active.replace(tzinfo=UTC)
            
        # Calculate time difference in minutes
        time_diff_minutes = 0
        if last_active:
            time_diff_minutes = (now - last_active).total_seconds() / 60
            print(f"Time since last activity: {time_diff_minutes:.2f} minutes")
            
        # Only update if at least 1 minute has passed since last update
        if not last_active or time_diff_minutes >= 1:
            print("Proceeding with update as time threshold met")
            
            # Get current active minutes for today
            current_minutes = 0.0
            if user.metadata.total_active_hours_per_day:
                current_minutes = float(user.metadata.total_active_hours_per_day.get(today, 0.0)) * 60
            print(f"Current active minutes today: {current_minutes}")
            
            # Add 1 minute of activity
            new_minutes = current_minutes + 1.0
            print(f"New active minutes: {new_minutes}")
            
            # Get location data
            location_data = await get_location_from_ip(ip)
            print(f"Location data retrieved: {location_data}")
            
            # Prepare all updates
            updates = {
                "$set": {
                    "metadata.last_active": now,
                    f"metadata.total_active_hours_per_day.{today}": new_minutes / 60  # Convert back to hours
                }
            }
            print(f"Base updates prepared: {updates}")
            
            # Handle device fingerprint
            if device_fingerprint:
                # Check if this device fingerprint already exists
                existing_fingerprints = {
                    fp["device_fingerprint"] 
                    for fp in user.metadata.device_fingerprints
                } if user.metadata.device_fingerprints else set()
                
                if device_fingerprint not in existing_fingerprints:
                    print(f"Adding new device fingerprint: {device_fingerprint}")
                    new_fingerprint_data = {
                        "device_fingerprint": device_fingerprint,
                        "first_seen": now,
                        "last_seen": now,
                        "user_agent": user_agent,
                        "ip": ip
                    }
                    if "$push" not in updates:
                        updates["$push"] = {}
                    updates["$push"]["metadata.device_fingerprints"] = new_fingerprint_data
                else:
                    # Update last_seen for existing fingerprint
                    print(f"Updating last_seen for existing device fingerprint: {device_fingerprint}")
                    updates["$set"] = {
                        **updates["$set"],
                        "metadata.device_fingerprints.$[elem].last_seen": now,
                        "metadata.device_fingerprints.$[elem].ip": ip,
                        "metadata.device_fingerprints.$[elem].user_agent": user_agent
                    }
                    updates["arrayFilters"] = [{"elem.device_fingerprint": device_fingerprint}]
            
            # Prepare arrays to update
            new_ip_data = {
                "ip": ip,
                "timestamp": now
            }
            
            new_location_data = {
                "ip": ip,
                "city": location_data.city,
                "country": location_data.country,
                "latitude": location_data.latitude,
                "longitude": location_data.longitude,
                "date": now
            }
            
            new_user_agent_data = {
                "user_agent": user_agent,
                "timestamp": now
            }
            
            # Check if we need to add new IP
            existing_ips = {loc["ip"] for loc in user.metadata.ip_addresses} if user.metadata.ip_addresses else set()
            if ip not in existing_ips:
                print(f"Adding new IP: {ip}")
                if "$push" not in updates:
                    updates["$push"] = {}
                updates["$push"]["metadata.ip_addresses"] = new_ip_data
            
            # Check if we need to add new location
            existing_locations = {
                (loc["city"], loc["country"], loc["latitude"], loc["longitude"])
                for loc in user.metadata.locations
            } if user.metadata.locations else set()
            
            new_location_tuple = (location_data.city, location_data.country, location_data.latitude, location_data.longitude)
            if new_location_tuple not in existing_locations and (location_data.latitude != 0 or location_data.longitude != 0):
                print(f"Adding new location: {location_data.city}, {location_data.country}")
                if "$push" not in updates:
                    updates["$push"] = {}
                updates["$push"]["metadata.locations"] = new_location_data
            
            # Check if we need to add new user agent
            existing_user_agents = {ua["user_agent"] for ua in user.metadata.user_agents} if user.metadata.user_agents else set()
            if user_agent not in existing_user_agents:
                print(f"Adding new user agent: {user_agent}")
                if "$push" not in updates:
                    updates["$push"] = {}
                updates["$push"]["metadata.user_agents"] = new_user_agent_data
            
            print(f"Final updates to be applied: {updates}")
            
            # Update the database with all changes
            if updates:
                result = await users_collection.update_one(
                    {"username": username},
                    updates
                )
                
                print(f"Database update result - Modified count: {result.modified_count}")
                if result.modified_count > 0:
                    print("=== Update successful ===")
                    print(f"Updated activity for user {username}:")
                    print(f"- Added 1 minute of activity (total: {new_minutes/60:.2f} hours today)")
                    if "$push" in updates:
                        if "metadata.ip_addresses" in updates["$push"]:
                            print(f"- Added new IP: {ip}")
                        if "metadata.locations" in updates["$push"]:
                            print(f"- Added new location: {location_data.city}, {location_data.country}")
                        if "metadata.user_agents" in updates["$push"]:
                            print(f"- Added new user agent: {user_agent}")
                        if "metadata.device_fingerprints" in updates["$push"]:
                            print(f"- Added new device fingerprint: {device_fingerprint}")
                else:
                    print("WARNING: Database update did not modify any documents!")
        else:
            print(f"Skipping update - only {time_diff_minutes:.2f} minutes since last activity (threshold: 1 minute)")
            
    except Exception as e:
        print(f"ERROR in update_user_activity: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        # Don't raise the error, just log it to prevent login failures
        pass
    finally:
        print("=== End of update_user_activity ===\n")

async def log_user_action(username: str, action: str, details: str) -> None:
    """Log a user action"""
    try:
        action_data = {
            "action": action,
            "details": details,
            "date": datetime.now(UTC)
        }
        await users_collection.update_one(
            {"username": username},
            {"$push": {"metadata.actions": action_data}}
        )
    except Exception as e:
        print(f"Error logging user action: {e}")

async def log_page_visit(username: str, url: str) -> None:
    """Log a page visit"""
    try:
        visit_data = {
            "url": url,
            "timestamp": datetime.now(UTC)
        }
        await users_collection.update_one(
            {"username": username},
            {"$push": {"metadata.pages_visited": visit_data}}
        )
    except Exception as e:
        print(f"Error logging page visit: {e}")

async def log_api_call(
    route: str,
    method: str,
    payload: Optional[Dict[str, Any]] = None,
    username: Optional[str] = None
) -> None:
    """Log an API call"""
    if not username or route in IGNORED_ENDPOINTS:
        return
        
    try:
        api_call_data = {
            "route": route,
            "method": method,
            "timestamp": datetime.now(UTC),
            "payload": None  # Don't store payload for security
        }
        await users_collection.update_one(
            {"username": username},
            {"$push": {"metadata.api_calls_made": api_call_data}}
        )
    except Exception as e:
        print(f"Error logging API call: {e}")

async def log_failed_login(username: str, ip: str, reason: str) -> None:
    """Log a failed login attempt"""
    try:
        failed_login_data = {
            "ip": ip,
            "timestamp": datetime.now(UTC),
            "reason": reason
        }
        await users_collection.update_one(
            {"username": username},
            {"$push": {"metadata.failed_login_attempts": failed_login_data}}
        )
    except Exception as e:
        print(f"Error logging failed login: {e}")

async def log_session_token(username: str, token: str, ip: str, expires_at: datetime) -> None:
    """Log a session token issuance"""
    try:
        token_data = {
            "token": token,
            "issued_at": datetime.now(UTC),
            "expires_at": expires_at,
            "ip": ip
        }
        await users_collection.update_one(
            {"username": username},
            {"$push": {"metadata.session_tokens_issued": token_data}}
        )
    except Exception as e:
        print(f"Error logging session token: {e}")

async def log_password_change(username: str) -> None:
    """Log a password change"""
    try:
        change_data = {
            "timestamp": datetime.now(UTC)
        }
        await users_collection.update_one(
            {"username": username},
            {"$push": {"metadata.password_change_history": change_data}}
        )
    except Exception as e:
        print(f"Error logging password change: {e}")

async def update_user_location(
    username: str,
    ip: str,
    city: str,
    country: str,
    latitude: float = 0,
    longitude: float = 0
) -> None:
    """Update user's location information with coordinates, only for new locations"""
    try:
        # Get current user data
        user = await get_user(username)
        if not user or not user.metadata:
            return

        # Create sets of existing IPs and locations for quick lookup
        existing_ips = {loc["ip"] for loc in user.metadata.ip_addresses} if user.metadata.ip_addresses else set()
        existing_locations = {
            (loc["city"], loc["country"], loc["latitude"], loc["longitude"])
            for loc in user.metadata.locations
        } if user.metadata.locations else set()

        # Create new location data
        new_location = {
            "ip": ip,
            "city": city,
            "country": country,
            "latitude": latitude,
            "longitude": longitude,
            "date": datetime.now(UTC)
        }

        # Check if this is a new IP or location
        is_new_ip = ip not in existing_ips
        is_new_location = (city, country, latitude, longitude) not in existing_locations

        if is_new_ip or is_new_location:
            print(f"Logging new {'IP' if is_new_ip else 'location'} for user {username}: {ip} - {city}, {country}")
            
            # Prepare update operations
            update_ops = {}
            
            if is_new_ip:
                update_ops["metadata.ip_addresses"] = {
                    "ip": ip,
                    "timestamp": datetime.now(UTC)
                }
            
            if is_new_location:
                update_ops["metadata.locations"] = new_location

            # Only update if we have new data to add
            if update_ops:
                await users_collection.update_one(
                    {"username": username},
                    {"$addToSet": update_ops}
                )
    except Exception as e:
        print(f"Error updating user location: {e}")
        # Don't raise the error to prevent login failures
        pass

# Sliver C2 Session operations
async def update_sliver_session(payload: Dict[str, Any]) -> None:
    """Update Sliver C2 session information in MongoDB with first_seen and last_seen tracking"""
    try:
        now = datetime.now(UTC)
        
        # Generate device_id from session data
        device_id = generate_device_id(payload)
        payload["device_id"] = device_id
        
        # Validate the payload using the model
        try:
            session = SliverSession(**payload)
            session_data = session.model_dump(exclude={'id'})
        except Exception as e:
            print(f"Invalid session data: {e}")
            raise ValueError(f"Invalid session data: {str(e)}")
        
        # Check if session exists
        existing_session = await sessions_collection.find_one({"session_id": session_data["session_id"]})
        
        if existing_session:
            # Update existing session, preserving first_seen
            update_data = {
                **session_data,
                "last_seen": now
            }
            result = await sessions_collection.update_one(
                {"session_id": session_data["session_id"]},
                {"$set": update_data}
            )
            # if result.modified_count == 0:
                # print(f"Warning: No changes made to session {session_data['session_id']}")
            # else:
                # print(f"Updated existing Sliver session {session_data['session_id']} - last_seen: {now}")
        else:
            # Create new session with first_seen and last_seen
            new_session = {
                **session_data,
                "first_seen": now,
                "last_seen": now
            }
            result = await sessions_collection.insert_one(new_session)
            print(f"Created new Sliver session {session_data['session_id']} with device_id {device_id} - first_seen: {now}")
            
    except Exception as e:
        print(f"Error updating Sliver session: {e}")
        raise

async def get_sliver_session(session_id: str) -> Optional[SliverSession]:
    """Get Sliver C2 session information from MongoDB"""
    try:
        if (session := await sessions_collection.find_one({"session_id": session_id})) is not None:
            return SliverSession(**session)
        return None
    except Exception as e:
        print(f"Error getting Sliver session: {e}")
        return None

async def get_all_sliver_sessions() -> List[SliverSession]:
    """Get all Sliver C2 sessions from MongoDB"""
    try:
        sessions = await sessions_collection.find().to_list(length=None)
        return [SliverSession(**session) for session in sessions]
    except Exception as e:
        print(f"Error getting all Sliver sessions: {e}")
        return []

async def delete_sliver_session(session_id: str) -> bool:
    """Delete a Sliver C2 session from MongoDB"""
    try:
        result = await sessions_collection.delete_one({"session_id": session_id})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting Sliver session: {e}")
        return False

async def get_sessions_by_device_id(device_id: str) -> List[SliverSession]:
    """Get all sessions for a specific device ID"""
    try:
        sessions = await sessions_collection.find({"device_id": device_id}).to_list(length=None)
        return [SliverSession(**session) for session in sessions]
    except Exception as e:
        print(f"Error getting sessions by device_id: {e}")
        return []

# User login operations
async def update_user_last_login(username: str) -> None:
    """Update user's last login timestamp"""
    try:
        now = datetime.now(UTC)
        result = await users_collection.update_one(
            {"username": username},
            {"$set": {"last_login": now}}
        )
        if result.modified_count > 0:
            print(f"Updated last login for user {username} to {now}")
        else:
            print(f"Warning: Could not update last login for user {username}")
    except Exception as e:
        print(f"Error updating last login: {e}")
        # Don't raise the error to prevent login failures
        pass

# Connection database functions
async def create_connection(connection_dict: dict) -> Connection:
    """Create a new connection configuration"""
    try:
        # Create a new connection document
        now = datetime.now(UTC)
        connection_doc = {
            "name": connection_dict["name"],
            "config": connection_dict["config"],  # This is already a string from the frontend
            "created_by": connection_dict["created_by"],
            "created_at": now,
            "last_used": now,
            "is_active": False
        }
        
        # Insert into database
        result = await db.connections.insert_one(connection_doc)
        
        # Create and return Connection object
        return Connection(
            id=result.inserted_id,
            name=connection_dict["name"],
            config=connection_dict["config"],
            created_by=connection_dict["created_by"],
            created_at=connection_doc["created_at"],
            last_used=connection_doc["last_used"],
            is_active=connection_doc["is_active"]
        )
    except Exception as e:
        print(f"Error in create_connection: {str(e)}")
        raise e

async def get_connections(user_id: PyObjectId) -> List[ConnectionResponse]:
    """Get all connections for a user"""
    try:
        # Find all connections for the user
        cursor = connections_collection.find({"created_by": user_id})
        connections = await cursor.to_list(length=None)
        
        # Convert MongoDB documents to Pydantic models
        response_connections = []
        for conn in connections:
            # Convert ObjectId to string for JSON serialization
            conn["_id"] = str(conn["_id"])
            conn["created_by"] = str(conn["created_by"])
            try:
                response_connections.append(ConnectionResponse(**conn))
            except Exception as e:
                print(f"Error converting connection to model: {e}")
                continue
        
        return response_connections
    except Exception as e:
        print(f"Error getting connections: {e}")
        raise

async def get_connection(connection_id: str, user_id: PyObjectId) -> Optional[Connection]:
    """Get a specific connection by ID"""
    try:
        if not ObjectId.is_valid(connection_id):
            return None
        connection = await connections_collection.find_one({
            "_id": ObjectId(connection_id),
            "created_by": user_id
        })
        return Connection(**connection) if connection else None
    except Exception as e:
        print(f"Error getting connection: {e}")
        raise

async def update_connection_status(connection_id: str, user_id: PyObjectId, is_active: bool) -> bool:
    """Update the active status of a connection"""
    try:
        if not ObjectId.is_valid(connection_id):
            return False
        result = await connections_collection.update_one(
            {"_id": ObjectId(connection_id), "created_by": user_id},
            {
            "$set": {
                    "is_active": is_active,
                    "last_used": datetime.now(UTC) if is_active else None
                }
            }
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating connection status: {e}")
        raise

async def delete_connection(connection_id: str, user_id: PyObjectId) -> bool:
    """Delete a connection configuration"""
    try:
        if not ObjectId.is_valid(connection_id):
            return False
        result = await connections_collection.delete_one({
            "_id": ObjectId(connection_id),
            "created_by": user_id
        })
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting connection: {e}")
        raise

async def get_location_from_ip(ip: str) -> GeoLocation:
    """Get location data from IP address using GeoLite2 database"""
    try:
        if geoip_reader and ip != "127.0.0.1" and not ip.startswith("192.168."):
            response = geoip_reader.city(ip)
            return GeoLocation(
                city=response.city.name or "Unknown",
                country=response.country.name or "Unknown",
                latitude=response.location.latitude,
                longitude=response.location.longitude,
                ip=ip
            )
    except (geoip2.errors.AddressNotFoundError, AttributeError):
        pass
    except Exception as e:
        print(f"Error getting location for IP {ip}: {e}")
    
    return GeoLocation(
        city="Unknown",
        country="Unknown",
        latitude=0,
        longitude=0,
        ip=ip
    )
