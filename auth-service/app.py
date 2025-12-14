from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional
import logging
import httpx

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Authentication Service", description="User authentication for microservices security pattern")

# Secret key for JWT encoding/decoding (in production, this should be stored securely)
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"

# In-memory storage for demonstration purposes (use a database in production)
users_db: Dict[str, Dict] = {}
sessions_db: Dict[str, Dict] = {}

class User(BaseModel):
    username: str
    password: str
    role: str = "user"  # default role

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenValidationRequest(BaseModel):
    token: str

class SessionInfo(BaseModel):
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

def hash_password(password: str) -> str:
    """Hashes a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_id() -> str:
    """Generates a random session ID"""
    return secrets.token_urlsafe(32)

@app.on_event("startup")
async def startup_event():
    """Initialize sample users"""
    global users_db
    
    # Create sample users
    users_db = {
        "user1": {
            "username": "user1",
            "hashed_password": hash_password("password1"),
            "role": "user",
            "email": "user1@example.com",
            "full_name": "Alice Johnson"
        },
        "admin": {
            "username": "admin",
            "hashed_password": hash_password("adminpass"),
            "role": "admin",
            "email": "admin@example.com",
            "full_name": "Admin User"
        }
    }
    
    logger.info("Authentication service started with sample users")

@app.get("/")
async def auth_info():
    """Information about the authentication service"""
    return {"message": "Authentication Service for Microservices Security Pattern", "status": "running"}

@app.post("/register")
async def register_user(user: User):
    """Register a new user"""
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    users_db[user.username] = {
        "username": user.username,
        "hashed_password": hash_password(user.password),
        "role": user.role,
        "email": f"{user.username}@example.com",  # Default email
        "full_name": user.username  # Default full name
    }
    
    logger.info(f"New user registered: {user.username}")
    return {"message": "User registered successfully", "username": user.username}

@app.post("/login")
async def login(login_request: LoginRequest, background_tasks: BackgroundTasks):
    """Authenticate user and return JWT token"""
    username = login_request.username
    password = login_request.password
    
    # Check if user exists
    if username not in users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = users_db[username]
    
    # Check password
    if user["hashed_password"] != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate JWT token
    expiration_time = datetime.utcnow() + timedelta(hours=24)
    token_data = {
        "sub": username,
        "user_id": user.get("id", username),
        "role": user["role"],
        "exp": expiration_time
    }
    
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    # Log successful login
    logger.info(f"Successful login for user: {username}")
    
    # Create session
    session_id = generate_session_id()
    sessions_db[session_id] = {
        "user_id": user.get("id", username),
        "created_at": datetime.utcnow(),
        "expires_at": expiration_time,
        "last_activity": datetime.utcnow(),
        "ip_address": "unknown",  # Will be updated later if available
        "user_agent": "unknown"
    }
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_info": {
            "username": user["username"],
            "role": user["role"],
            "email": user.get("email", ""),
            "full_name": user.get("full_name", "")
        },
        "session_id": session_id
    }

@app.post("/validate_token")
async def validate_token(token_request: TokenValidationRequest):
    """Validate JWT token and return user info"""
    token = token_request.token
    
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        if username not in users_db:
            raise HTTPException(status_code=401, detail="Token invalid - user not found")
        
        user = users_db[username]
        
        # Update last activity for the session
        for session_id, session in sessions_db.items():
            if session["user_id"] == user.get("id", username) and session["expires_at"] > datetime.utcnow():
                session["last_activity"] = datetime.utcnow()
                break
        
        return {
            "valid": True,
            "user_id": user.get("id", username),
            "username": username,
            "role": user["role"],
            "exp": payload.get("exp")
        }
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/logout")
async def logout(session_id: str):
    """Logout user by invalidating session"""
    if session_id in sessions_db:
        del sessions_db[session_id]
        return {"message": "Logged out successfully"}
    else:
        raise HTTPException(status_code=404, detail="Session not found")

@app.get("/user/{username}")
async def get_user_info(username: str):
    """Get information about a specific user"""
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = users_db[username]
    return {
        "username": user["username"],
        "role": user["role"],
        "email": user.get("email", ""),
        "full_name": user.get("full_name", "")
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "auth-service"}

@app.get("/sessions")
async def list_sessions():
    """List active sessions (for admin use)"""
    active_sessions = []
    now = datetime.utcnow()
    
    for session_id, session in sessions_db.items():
        if session["expires_at"] > now:
            active_sessions.append({
                "session_id": session_id,
                "user_id": session["user_id"],
                "created_at": session["created_at"],
                "expires_at": session["expires_at"],
                "last_activity": session["last_activity"]
            })
    
    return {"active_sessions": active_sessions}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8901)