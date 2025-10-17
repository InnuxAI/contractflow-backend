from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
import warnings
# Suppress bcrypt version warning
warnings.filterwarnings("ignore", message=".*bcrypt.*", category=UserWarning)
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
import os
import hashlib
from dotenv import load_dotenv
from database import get_user_by_id

# Import audit logging
from audit_logger import (
    log_audit, EventType, Actor, Target, Outcome, ObjectType, 
    ActorType, OutcomeStatus, log_login_success, log_login_failure,
    start_audit_session, end_audit_session, log_session_event
)
from audit_middleware import (
    get_current_request_meta, set_current_user, 
    create_request_meta_from_context
)

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_token_fingerprint(token: str) -> str:
    """Generate a secure fingerprint of the token for audit logging"""
    return hashlib.sha256(token.encode()).hexdigest()[:16]

async def authenticate_user(email: str, password: str, request: Request = None):
    """
    Authenticate user and start audit session if successful.
    Returns tuple (user, session_id) if successful, (None, None) if failed.
    """
    request_meta = get_current_request_meta() or create_request_meta_from_context()
    
    user = get_user_by_id(email) if "@" not in email else get_user_by_email(email)
    
    if not user:
        # Log failed login - user not found (legacy logging for failed attempts)
        log_login_failure(
            email=email,
            reason="user_not_found",
            request_meta=request_meta
        )
        return None, None
    
    if not verify_password(password, user["password"]):
        # Log failed login - invalid password (legacy logging for failed attempts)
        log_login_failure(
            email=email,
            reason="invalid_password", 
            request_meta=request_meta
        )
        return None, None
    
    # Start audit session for successful login
    session_meta = {
        "login_method": "password",
        "user_role": user.get("role", "user"),
        "ip": request_meta.ip if hasattr(request_meta, 'ip') else None,
        "user_agent": request_meta.user_agent if hasattr(request_meta, 'user_agent') else None
    }
    
    session_id = start_audit_session(
        user_id=str(user["_id"]),
        user_email=user["email"],
        session_meta=session_meta
    )
    
    return user, session_id

async def create_and_log_token(user: dict, session_id: str, expires_delta: Optional[timedelta] = None):
    """Create access token and log the token issuance in session"""
    access_token = create_access_token(
        data={
            "sub": str(user["_id"]),
            "email": user["email"],
            "role": user["role"],
            "session_id": session_id  # Include session_id in token
        },
        expires_delta=expires_delta
    )
    
    # Log token issuance in session
    request_meta_dict = {"request_id": str(user["_id"]) + "_token", "session_id": session_id}
    token_fingerprint = get_token_fingerprint(access_token)
    
    log_session_event(
        session_id=session_id,
        event_type="user.token.issued",
        actor={"user_id": str(user["_id"]), "user_email": user["email"], "actor_type": "user"},
        target={"object_type": "token", "object_id": token_fingerprint},
        outcome={"status": "success", "code": "TOKEN_ISSUED"},
        details={
            "token_fingerprint": token_fingerprint,
            "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
            "user_role": user["role"]
        },
        request_meta=request_meta_dict
    )
    
    return access_token

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    request_meta = get_current_request_meta() or create_request_meta_from_context()
    token_fingerprint = get_token_fingerprint(token)
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        session_id: str = payload.get("session_id")  # Extract session_id from token
        if user_id is None:
            raise credentials_exception
    except JWTError as e:
        # Log failed token validation (legacy logging for security events)
        log_audit(
            event_type=EventType.USER_TOKEN_REVOKED,
            actor=Actor(actor_type=ActorType.SYSTEM),
            target=Target(object_type=ObjectType.TOKEN, object_id=token_fingerprint),
            outcome=Outcome(
                status=OutcomeStatus.FAILURE, 
                code="TOKEN_VALIDATION_FAILED",
                message=str(e)
            ),
            details={"error": "jwt_decode_error", "token_fingerprint": token_fingerprint},
            request_meta=request_meta,
            retention_tag="retention_7y"
        )
        raise credentials_exception
    
    user = get_user_by_id(user_id)
    if user is None:
        # Log failed user lookup (legacy logging for security events)
        log_audit(
            event_type=EventType.USER_TOKEN_REVOKED,
            actor=Actor(user_id=user_id, actor_type=ActorType.USER),
            target=Target(object_type=ObjectType.TOKEN, object_id=token_fingerprint),
            outcome=Outcome(
                status=OutcomeStatus.FAILURE,
                code="USER_NOT_FOUND",
                message="User not found for valid token"
            ),
            details={"user_id": user_id, "token_fingerprint": token_fingerprint},
            request_meta=request_meta,
            retention_tag="retention_7y"
        )
        raise credentials_exception
    
    # Add session_id to user context
    user["session_id"] = session_id
    
    # Set user in context for audit logging
    set_current_user(user)
    
    return user

async def logout_user(user: dict, token: str, session_id: str = None):
    """Log user logout and end audit session"""
    print(f"🚪 LOGOUT PROCESS: User {user.get('email')} | Session: {session_id}")
    request_meta_dict = {"request_id": str(user["_id"]) + "_logout", "session_id": session_id}
    token_fingerprint = get_token_fingerprint(token)
    
    if session_id:
        print(f"📝 Logging logout event to session {session_id}")
        # Log logout in session before ending it
        log_session_event(
            session_id=session_id,
            event_type="user.logout", 
            actor={"user_id": str(user["_id"]), "user_email": user["email"], "actor_type": "user"},
            target={"object_type": "user", "object_id": str(user["_id"])},
            outcome={"status": "success", "code": "LOGOUT_SUCCESS"},
            details={"token_fingerprint": token_fingerprint},
            request_meta=request_meta_dict
        )
        
        print(f"🔚 Ending audit session {session_id}")
        # End the audit session
        end_audit_session(session_id, "user_logout")
    else:
        # Fallback to legacy logging if no session
        request_meta = get_current_request_meta() or create_request_meta_from_context()
        log_audit(
            event_type=EventType.USER_LOGOUT,
            actor=Actor(
                user_id=str(user["_id"]),
                user_email=user["email"],
                actor_type=ActorType.USER
            ),
            target=Target(object_type=ObjectType.USER, object_id=str(user["_id"])),
            outcome=Outcome(status=OutcomeStatus.SUCCESS, code="LOGOUT_SUCCESS"),
            details={"token_fingerprint": token_fingerprint},
            request_meta=request_meta,
            retention_tag="retention_7y"
        )

# Import here to avoid circular imports
from database import get_user_by_email
