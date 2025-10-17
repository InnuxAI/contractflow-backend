#!/usr/bin/env python3
"""
Session-based batch audit logging system for contractflow application.

This module provides comprehensive audit logging capabilities with:
- Session-based event batching to reduce database writes
- Local storage backup for resilience
- Immutable log entries with cryptographic integrity
- Structured JSON event schema
- Request correlation and tracing
- Privacy-compliant data handling
- Automated retention policy management
- Recovery mechanism for incomplete sessions
"""

import uuid
import hashlib
import hmac
import json
import os
import threading
import atexit
import signal
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from enum import Enum
from pydantic import BaseModel
from pathlib import Path
from dataclasses import dataclass, asdict

class DateTimeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

from pymongo import MongoClient
from dotenv import load_dotenv
import logging

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
AUDIT_SECRET_KEY = os.getenv("AUDIT_SECRET_KEY", "your-audit-secret-key-change-this")
AUDIT_COLLECTION_NAME = "audit_logs"
SESSION_AUDIT_COLLECTION = "session_audit_logs"
LOCAL_STORAGE_PATH = "audit_sessions"

# Connect to MongoDB
client = MongoClient(MONGODB_URL)
db = client["document_review_db"]
audit_collection = db[AUDIT_COLLECTION_NAME]  # Legacy collection
session_audit_collection = db[SESSION_AUDIT_COLLECTION]  # New session-based collection

# Create indexes for performance and integrity
audit_collection.create_index("timestamp_utc")
audit_collection.create_index("event_type")
audit_collection.create_index("actor.user_id")
audit_collection.create_index("request_meta.request_id")
audit_collection.create_index("retention_policy_tag")
audit_collection.create_index("target.object_id")

# New session-based indexes
session_audit_collection.create_index("session_id")
session_audit_collection.create_index("user_id")
session_audit_collection.create_index("session_start_time")
session_audit_collection.create_index("session_end_time")
session_audit_collection.create_index("events.event_type")

class EventType(str, Enum):
    """Hierarchical event types for audit logging"""
    # Authentication events
    USER_LOGIN_SUCCESS = "user.login.success"
    USER_LOGIN_FAILED = "user.login.failed"
    USER_LOGOUT = "user.logout"
    USER_TOKEN_ISSUED = "user.token.issued"
    USER_TOKEN_REVOKED = "user.token.revoked"
    USER_PASSWORD_RESET_REQUEST = "user.password.reset.request"
    USER_PASSWORD_RESET_COMPLETE = "user.password.reset.complete"
    
    # Authorization & RBAC
    USER_ROLE_CHANGE = "user.role.change"
    PERMISSION_GRANT = "permission.grant"
    PERMISSION_REVOKE = "permission.revoke"
    
    # Document lifecycle
    DOCUMENT_CREATE = "document.create"
    DOCUMENT_OPEN = "document.open"
    DOCUMENT_UPDATE = "document.update"
    DOCUMENT_STATUS_CHANGE = "document.status_change"
    DOCUMENT_ASSIGN_APPROVER = "document.assign_approver"
    DOCUMENT_APPROVE = "document.approve"
    DOCUMENT_REJECT = "document.reject"
    DOCUMENT_DELETE = "document.delete"
    DOCUMENT_DOWNLOAD = "document.download"
    
    # Data exports & reports
    REPORT_EXPORT = "report.export"
    DATA_EXPORT = "data.export"
    
    # Communication
    EMAIL_SENT = "email.sent"
    WEBHOOK_SENT = "webhook.sent"
    SMS_SENT = "sms.sent"
    
    # System & background jobs
    JOB_STARTED = "job.started"
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    MIGRATION_RUN = "migration.run"
    
    # Admin operations
    ADMIN_USER_DELETE = "admin.user_delete"
    ADMIN_COLLECTION_CLEAR = "admin.collection_clear"
    ADMIN_MIGRATE_DOCUMENTS = "admin.migrate_documents"
    ADMIN_SCRIPT_EXECUTE = "admin.script_execute"
    
    # AI/Chat interactions
    AI_QUERY_SUBMITTED = "ai.query.submitted"
    AI_COMPLIANCE_CHECK = "ai.compliance.check"
    
    # Security & suspicious activity
    SECURITY_FAILED_LOGIN_ATTEMPT = "security.failed_login_attempt"
    SECURITY_PRIVILEGE_ESCALATION = "security.privilege_escalation"
    SECURITY_UNUSUAL_APPROVAL = "security.unusual_approval"
    SECURITY_RATE_LIMIT_EXCEEDED = "security.rate_limit_exceeded"
    
    # Audit system events
    AUDIT_READ = "audit.read"
    AUDIT_INTEGRITY_CHECK = "audit.integrity_check"
    AUDIT_RETENTION_PURGE = "audit.retention_purge"
    
    # Session events
    SESSION_START = "session.start"
    SESSION_END = "session.end"
    SESSION_FORCED_END = "session.forced_end"
    SESSION_RECOVERED = "session.recovered"

@dataclass
class SessionAuditEvent:
    """Individual audit event within a session"""
    event_id: str
    timestamp: datetime
    event_type: str
    actor: Dict[str, Any]
    target: Dict[str, Any]
    outcome: Dict[str, Any]
    details: Dict[str, Any]
    request_meta: Dict[str, Any]

@dataclass
class SessionAuditLog:
    """Complete session audit log"""
    session_id: str
    user_id: str
    user_email: str
    session_start_time: datetime
    session_end_time: Optional[datetime]
    events: List[SessionAuditEvent]
    session_meta: Dict[str, Any]
    integrity_hash: str
    is_complete: bool = False

class SessionAuditManager:
    """Manages session-based audit logging"""
    
    def __init__(self):
        self.active_sessions: Dict[str, SessionAuditLog] = {}
        self.local_storage_path = Path(LOCAL_STORAGE_PATH)
        self.local_storage_path.mkdir(exist_ok=True)
        self._setup_shutdown_handlers()
        self._recover_incomplete_sessions()
    
    def _setup_shutdown_handlers(self):
        """Setup handlers for graceful shutdown"""
        atexit.register(self._flush_all_sessions)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info("Received shutdown signal, flushing audit sessions...")
        self._flush_all_sessions()
        sys.exit(0)
    
    def start_session(self, user_id: str, user_email: str, session_meta: Dict[str, Any] = None) -> str:
        """Start a new audit session"""
        session_id = str(uuid.uuid4())
        
        session_log = SessionAuditLog(
            session_id=session_id,
            user_id=user_id,
            user_email=user_email,
            session_start_time=datetime.now(timezone.utc),
            session_end_time=None,
            events=[],
            session_meta=session_meta or {},
            integrity_hash="",
            is_complete=False
        )
        
        self.active_sessions[session_id] = session_log
        self._save_to_local_storage(session_id)
        
        # Log session start event
        self.add_event(
            session_id=session_id,
            event_type="session.start",
            actor={"user_id": user_id, "user_email": user_email, "actor_type": "user"},
            target={"object_type": "session", "object_id": session_id},
            outcome={"status": "success", "code": "SESSION_STARTED"},
            details={"session_meta": session_meta or {}},
            request_meta={"request_id": str(uuid.uuid4()), "session_id": session_id}
        )
        
        logger.info(f"Started audit session: {session_id} for user: {user_id}")
        return session_id
    
    def add_event(self, session_id: str, event_type: str, actor: Dict[str, Any], 
                  target: Dict[str, Any], outcome: Dict[str, Any], 
                  details: Dict[str, Any], request_meta: Dict[str, Any]):
        """Add an audit event to the session"""
        if session_id not in self.active_sessions:
            logger.warning(f"Session {session_id} not found, creating emergency session")
            self._create_emergency_session(session_id, actor.get("user_id", "unknown"))
        
        event = SessionAuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            actor=self._sanitize_data(actor),
            target=target,
            outcome=outcome,
            details=self._sanitize_data(details),
            request_meta=request_meta
        )
        
        self.active_sessions[session_id].events.append(event)
        self._save_to_local_storage(session_id)
        
        print(f"✅ Event {event_type} added to session {session_id} (Total events: {len(self.active_sessions[session_id].events)})")
        logger.debug(f"Added event {event_type} to session {session_id}")
    
    def end_session(self, session_id: str, end_reason: str = "user_logout") -> bool:
        """End a session and flush to database"""
        if session_id not in self.active_sessions:
            logger.warning(f"Cannot end session {session_id} - not found")
            return False
        
        session_log = self.active_sessions[session_id]
        
        # Add session end event
        self.add_event(
            session_id=session_id,
            event_type="session.end",
            actor={"user_id": session_log.user_id, "user_email": session_log.user_email, "actor_type": "user"},
            target={"object_type": "session", "object_id": session_id},
            outcome={"status": "success", "code": "SESSION_ENDED"},
            details={"end_reason": end_reason, "event_count": len(session_log.events)},
            request_meta={"request_id": str(uuid.uuid4()), "session_id": session_id}
        )
        
        # Finalize session
        session_log.session_end_time = datetime.now(timezone.utc)
        session_log.is_complete = True
        session_log.integrity_hash = self._calculate_session_hash(session_log)
        
        # Flush to database
        success = self._flush_session_to_db(session_id)
        
        if success:
            # Remove from active sessions and local storage
            del self.active_sessions[session_id]
            self._remove_from_local_storage(session_id)
            logger.info(f"Session {session_id} ended and flushed to database")
        
        return success
    
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize sensitive data from audit details"""
        sanitized = data.copy() if data else {}
        
        sensitive_fields = [
            'password', 'token', 'secret', 'key', 'credential',
            'auth_token', 'refresh_token', 'access_token', 'api_key'
        ]
        
        def sanitize_recursive(obj):
            if isinstance(obj, dict):
                for key, value in list(obj.items()):
                    key_lower = key.lower()
                    
                    if any(sensitive_field in key_lower for sensitive_field in sensitive_fields):
                        obj[key] = "[REDACTED]"
                    elif isinstance(value, (dict, list)):
                        sanitize_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        sanitize_recursive(item)
        
        sanitize_recursive(sanitized)
        return sanitized
    
    def _calculate_session_hash(self, session_log: SessionAuditLog) -> str:
        """Calculate integrity hash for the entire session"""
        # Create canonical representation
        session_data = {
            "session_id": session_log.session_id,
            "user_id": session_log.user_id,
            "session_start_time": session_log.session_start_time.isoformat(),
            "session_end_time": session_log.session_end_time.isoformat() if session_log.session_end_time else None,
            "events": [
                {
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type,
                    "actor": event.actor,
                    "target": event.target,
                    "outcome": event.outcome,
                    "details": event.details,
                    "request_meta": event.request_meta
                }
                for event in session_log.events
            ]
        }
        
        canonical_json = json.dumps(session_data, sort_keys=True, separators=(',', ':'))
        return hmac.new(
            AUDIT_SECRET_KEY.encode('utf-8'),
            canonical_json.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def _save_to_local_storage(self, session_id: str):
        """Save session to local storage as backup"""
        try:
            session_log = self.active_sessions[session_id]
            session_file = self.local_storage_path / f"{session_id}.json"
            
            # Convert to JSON-serializable format
            session_data = {
                "session_id": session_log.session_id,
                "user_id": session_log.user_id,
                "user_email": session_log.user_email,
                "session_start_time": session_log.session_start_time.isoformat(),
                "session_end_time": session_log.session_end_time.isoformat() if session_log.session_end_time else None,
                "events": [
                    {
                        "event_id": event.event_id,
                        "timestamp": event.timestamp.isoformat(),
                        "event_type": event.event_type,
                        "actor": event.actor.dict() if hasattr(event.actor, 'dict') else event.actor,
                        "target": event.target.dict() if hasattr(event.target, 'dict') else event.target,
                        "outcome": event.outcome.dict() if hasattr(event.outcome, 'dict') else event.outcome,
                        "details": event.details,
                        "request_meta": event.request_meta
                    }
                    for event in session_log.events
                ],
                "session_meta": session_log.session_meta,
                "is_complete": session_log.is_complete
            }
            
            with open(session_file, 'w') as f:
                json.dump(session_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save session {session_id} to local storage: {e}")
    
    def _remove_from_local_storage(self, session_id: str):
        """Remove session file from local storage"""
        try:
            session_file = self.local_storage_path / f"{session_id}.json"
            if session_file.exists():
                session_file.unlink()
        except Exception as e:
            logger.error(f"Failed to remove session {session_id} from local storage: {e}")
    
    def _recover_incomplete_sessions(self):
        """Recover incomplete sessions from local storage on startup"""
        try:
            logger.info("Recovering incomplete audit sessions from local storage...")
            
            for session_file in self.local_storage_path.glob("*.json"):
                try:
                    with open(session_file, 'r') as f:
                        session_data = json.load(f)
                    
                    # Convert back to SessionAuditLog
                    events = [
                        SessionAuditEvent(
                            event_id=event_data["event_id"],
                            timestamp=datetime.fromisoformat(event_data["timestamp"]),
                            event_type=event_data["event_type"],
                            actor=event_data["actor"],
                            target=event_data["target"],
                            outcome=event_data["outcome"],
                            details=event_data["details"],
                            request_meta=event_data["request_meta"]
                        )
                        for event_data in session_data["events"]
                    ]
                    
                    session_log = SessionAuditLog(
                        session_id=session_data["session_id"],
                        user_id=session_data["user_id"],
                        user_email=session_data["user_email"],
                        session_start_time=datetime.fromisoformat(session_data["session_start_time"]),
                        session_end_time=datetime.fromisoformat(session_data["session_end_time"]) if session_data["session_end_time"] else None,
                        events=events,
                        session_meta=session_data["session_meta"],
                        integrity_hash="",
                        is_complete=session_data["is_complete"]
                    )
                    
                    if not session_log.is_complete:
                        # Force end the session and flush to DB
                        session_log.session_end_time = datetime.now(timezone.utc)
                        session_log.is_complete = True
                        session_log.integrity_hash = self._calculate_session_hash(session_log)
                        
                        # Add recovery event
                        recovery_event = SessionAuditEvent(
                            event_id=str(uuid.uuid4()),
                            timestamp=datetime.now(timezone.utc),
                            event_type="session.recovered",
                            actor={"actor_type": "system"},
                            target={"object_type": "session", "object_id": session_log.session_id},
                            outcome={"status": "success", "code": "SESSION_RECOVERED"},
                            details={"recovery_reason": "server_restart", "original_event_count": len(session_log.events)},
                            request_meta={"request_id": str(uuid.uuid4()), "session_id": session_log.session_id}
                        )
                        session_log.events.append(recovery_event)
                        
                        # Flush to database
                        self._flush_session_to_db_direct(session_log)
                        session_file.unlink()  # Remove after successful flush
                        
                        logger.info(f"Recovered incomplete session: {session_log.session_id}")
                    else:
                        # Complete session, just flush to DB
                        self._flush_session_to_db_direct(session_log)
                        session_file.unlink()
                        logger.info(f"Flushed complete session: {session_log.session_id}")
                        
                except Exception as e:
                    logger.error(f"Failed to recover session from {session_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Error during session recovery: {e}")
    
    def _flush_session_to_db(self, session_id: str) -> bool:
        """Flush a session to the database"""
        if session_id not in self.active_sessions:
            return False
        
        session_log = self.active_sessions[session_id]
        return self._flush_session_to_db_direct(session_log)
    
    def _flush_session_to_db_direct(self, session_log: SessionAuditLog) -> bool:
        """Flush a session log directly to the database"""
        print(f"💾 FLUSHING SESSION TO DB: {session_log.session_id} with {len(session_log.events)} events")
        try:
            # Convert to database document
            doc = {
                "session_id": session_log.session_id,
                "user_id": session_log.user_id,
                "user_email": session_log.user_email,
                "session_start_time": session_log.session_start_time,
                "session_end_time": session_log.session_end_time,
                "session_duration_seconds": (session_log.session_end_time - session_log.session_start_time).total_seconds() if session_log.session_end_time else None,
                "event_count": len(session_log.events),
                "events": [
                    {
                        "event_id": event.event_id,
                        "timestamp": event.timestamp,
                        "event_type": event.event_type,
                        "actor": event.actor.dict() if hasattr(event.actor, 'dict') else event.actor,
                        "target": event.target.dict() if hasattr(event.target, 'dict') else event.target,
                        "outcome": event.outcome.dict() if hasattr(event.outcome, 'dict') else event.outcome,
                        "details": event.details,
                        "request_meta": event.request_meta
                    }
                    for event in session_log.events
                ],
                "session_meta": session_log.session_meta,
                "integrity_hash": session_log.integrity_hash,
                "is_complete": session_log.is_complete,
                "schema_version": "2.0"
            }
            
            session_audit_collection.insert_one(doc)
            print(f"✅ Successfully flushed session {session_log.session_id} to database")
            logger.info(f"Flushed session {session_log.session_id} to database with {len(session_log.events)} events")
            return True
            
        except Exception as e:
            print(f"❌ Failed to flush session {session_log.session_id} to database: {e}")
            logger.error(f"Failed to flush session {session_log.session_id} to database: {e}")
            return False
    
    def _flush_all_sessions(self):
        """Flush all active sessions to database"""
        logger.info(f"Flushing {len(self.active_sessions)} active sessions...")
        
        for session_id in list(self.active_sessions.keys()):
            try:
                session_log = self.active_sessions[session_id]
                
                # Add forced end event
                forced_end_event = SessionAuditEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    event_type="session.forced_end",
                    actor={"actor_type": "system"},
                    target={"object_type": "session", "object_id": session_id},
                    outcome={"status": "success", "code": "SESSION_FORCED_END"},
                    details={"end_reason": "server_shutdown", "event_count": len(session_log.events)},
                    request_meta={"request_id": str(uuid.uuid4()), "session_id": session_id}
                )
                session_log.events.append(forced_end_event)
                
                # Finalize session
                session_log.session_end_time = datetime.now(timezone.utc)
                session_log.is_complete = True
                session_log.integrity_hash = self._calculate_session_hash(session_log)
                
                # Flush to database
                if self._flush_session_to_db_direct(session_log):
                    self._remove_from_local_storage(session_id)
                
            except Exception as e:
                logger.error(f"Failed to flush session {session_id}: {e}")
    
    def _create_emergency_session(self, session_id: str, user_id: str):
        """Create emergency session for orphaned events"""
        logger.warning(f"Creating emergency session {session_id} for user {user_id}")
        
        session_log = SessionAuditLog(
            session_id=session_id,
            user_id=user_id,
            user_email="unknown@emergency.session",
            session_start_time=datetime.now(timezone.utc),
            session_end_time=None,
            events=[],
            session_meta={"emergency_session": True},
            integrity_hash="",
            is_complete=False
        )
        
        self.active_sessions[session_id] = session_log
        self._save_to_local_storage(session_id)

class ActorType(str, Enum):
    USER = "user"
    SYSTEM = "system"
    API = "api"

class OutcomeStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"

class ObjectType(str, Enum):
    DOCUMENT = "document"
    USER = "user"
    CLAUSE = "clause"
    TOKEN = "token"
    JOB = "job"
    COLLECTION = "collection"
    MIGRATION = "migration"
    EMAIL = "email"

class Actor(BaseModel):
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    actor_type: ActorType
    ip_address: Optional[str] = None

class Target(BaseModel):
    object_type: ObjectType
    object_id: Optional[str] = None
    object_name: Optional[str] = None

class Outcome(BaseModel):
    status: OutcomeStatus
    code: str
    message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None

class RequestMeta(BaseModel):
    request_id: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    origin: Optional[str] = None
    trace_id: Optional[str] = None
    session_id: Optional[str] = None

class AuditEntry(BaseModel):
    id: str
    timestamp_utc: datetime
    schema_version: str = "1.0"
    event_type: EventType
    actor: Actor
    target: Target
    outcome: Outcome
    details: Dict[str, Any]
    request_meta: RequestMeta
    checksum: str
    signature: Optional[str] = None
    retention_policy_tag: str
    legal_hold: bool = False

def _generate_checksum(entry_data: Dict[str, Any]) -> str:
    """Generate SHA256 checksum for audit entry integrity"""
    # Create canonical representation with datetime support
    canonical_json = json.dumps(entry_data, sort_keys=True, separators=(',', ':'), cls=DateTimeJSONEncoder)
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

def _generate_signature(entry_data: Dict[str, Any]) -> str:
    """Generate HMAC signature for tamper evidence"""
    canonical_json = json.dumps(entry_data, sort_keys=True, separators=(',', ':'), cls=DateTimeJSONEncoder)
    return hmac.new(
        AUDIT_SECRET_KEY.encode('utf-8'),
        canonical_json.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def _sanitize_sensitive_data(details: Dict[str, Any]) -> Dict[str, Any]:
    """Remove or hash sensitive data from audit details"""
    sanitized = details.copy()
    
    # Fields to completely remove
    sensitive_fields = [
        'password', 'token', 'secret', 'key', 'credential',
        'auth_token', 'refresh_token', 'access_token', 'api_key'
    ]
    
    # Fields to hash instead of remove
    hash_fields = ['email', 'phone', 'ssn', 'credit_card']
    
    def sanitize_recursive(obj, path=""):
        if isinstance(obj, dict):
            for key, value in list(obj.items()):
                current_path = f"{path}.{key}" if path else key
                key_lower = key.lower()
                
                # Remove sensitive fields
                if any(sensitive_field in key_lower for sensitive_field in sensitive_fields):
                    if 'id' in key_lower or 'fingerprint' in key_lower:
                        # Keep ID/fingerprint fields but hash them
                        obj[key] = hashlib.sha256(str(value).encode()).hexdigest()[:16]
                    else:
                        obj[key] = "[REDACTED]"
                
                # Hash PII fields
                elif any(hash_field in key_lower for hash_field in hash_fields):
                    obj[key] = hashlib.sha256(str(value).encode()).hexdigest()[:16]
                
                # Recursively sanitize nested objects
                elif isinstance(value, (dict, list)):
                    sanitize_recursive(value, current_path)
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    sanitize_recursive(item, f"{path}[{i}]")
    
    sanitize_recursive(sanitized)
    return sanitized

def log_audit(
    event_type: EventType,
    actor: Actor,
    target: Target,
    outcome: Outcome,
    details: Dict[str, Any],
    request_meta: RequestMeta,
    retention_tag: str = "retention_7y",
    legal_hold: bool = False
) -> str:
    """
    Log an audit event with tamper-evident properties.
    
    Args:
        event_type: The type of event being logged
        actor: Information about who performed the action
        target: Information about what was acted upon
        outcome: The result of the action
        details: Additional structured metadata
        request_meta: Request correlation data
        retention_tag: Data retention policy tag
        legal_hold: Whether this record is under legal hold
    
    Returns:
        The unique audit entry ID
    """
    try:
        # Generate unique ID
        audit_id = str(uuid.uuid4())
        
        # Sanitize sensitive data
        sanitized_details = _sanitize_sensitive_data(details)
        
        # Create entry data for checksum calculation
        entry_data = {
            "id": audit_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "schema_version": "1.0",
            "event_type": event_type.value,
            "actor": actor.model_dump(),
            "target": target.model_dump(),
            "outcome": outcome.model_dump(),
            "details": sanitized_details,
            "request_meta": request_meta.model_dump(),
            "retention_policy_tag": retention_tag,
            "legal_hold": legal_hold
        }
        
        # Generate integrity checksum and signature on the entry data
        checksum = _generate_checksum(entry_data)
        signature = _generate_signature(entry_data)
        
        # Add checksum and signature to the entry data
        entry_data["checksum"] = checksum
        entry_data["signature"] = signature
        
        # Store in append-only collection directly (don't use Pydantic model to avoid datetime conversion)
        audit_collection.insert_one(entry_data)
        
        logger.info(f"Audit entry created: {audit_id} - {event_type.value}")
        return audit_id
        
    except Exception as e:
        logger.error(f"Failed to create audit entry: {e}")
        # Don't raise exception to avoid breaking main application flow
        return "audit_failed"

def verify_audit_integrity(audit_id: str) -> bool:
    """Verify the integrity of an audit entry"""
    try:
        entry = audit_collection.find_one({"id": audit_id})
        if not entry:
            return False
        
        # Extract stored checksum and signature
        stored_checksum = entry.pop("checksum")
        stored_signature = entry.pop("signature", None)
        
        # Remove MongoDB ObjectId for verification
        entry.pop("_id", None)
        
        # Fix timestamp format to match creation: MongoDB stores datetime objects,
        # but checksum was calculated with ISO string format
        if "timestamp_utc" in entry:
            timestamp = entry["timestamp_utc"]
            if isinstance(timestamp, datetime):
                # Convert to timezone-aware if needed, then to ISO format like during creation
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                entry["timestamp_utc"] = timestamp.isoformat()
        
        # Recalculate checksum
        calculated_checksum = _generate_checksum(entry)
        calculated_signature = _generate_signature(entry)
        
        checksum_valid = calculated_checksum == stored_checksum
        signature_valid = calculated_signature == stored_signature if stored_signature else True
        
        return checksum_valid and signature_valid
        
    except Exception as e:
        logger.error(f"Error verifying audit integrity for {audit_id}: {e}")
        return False

def get_audit_entries(
    event_types: Optional[List[EventType]] = None,
    user_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Query audit entries with proper access control.
    This function should only be called by authorized users.
    """
    try:
        query = {}
        
        if event_types:
            query["event_type"] = {"$in": [et.value for et in event_types]}
        
        if user_id:
            query["actor.user_id"] = user_id
        
        if start_time or end_time:
            time_query = {}
            if start_time:
                time_query["$gte"] = start_time
            if end_time:
                time_query["$lte"] = end_time
            query["timestamp_utc"] = time_query
        
        # Log the audit read access
        log_audit_read_access(user_id, query)
        
        entries = list(audit_collection.find(query).sort("timestamp_utc", -1).limit(limit))
        
        # Remove MongoDB ObjectId for response
        for entry in entries:
            entry.pop("_id", None)
        
        return entries
        
    except Exception as e:
        logger.error(f"Error querying audit entries: {e}")
        return []

def log_audit_read_access(reader_user_id: str, query_details: Dict[str, Any]):
    """Log when someone reads audit logs (audit-of-audit)"""
    try:
        log_audit(
            event_type=EventType.AUDIT_READ,
            actor=Actor(user_id=reader_user_id, actor_type=ActorType.USER),
            target=Target(object_type=ObjectType.COLLECTION, object_id="audit_logs"),
            outcome=Outcome(status=OutcomeStatus.SUCCESS, code="AUDIT_READ"),
            details={"query_parameters": query_details},
            request_meta=RequestMeta(request_id=str(uuid.uuid4())),
            retention_tag="retention_7y"
        )
    except Exception as e:
        logger.error(f"Failed to log audit read access: {e}")

def run_integrity_check() -> Dict[str, Any]:
    """Run integrity check on all audit entries"""
    try:
        logger.info("Starting audit integrity check...")
        
        total_entries = audit_collection.count_documents({})
        verified_count = 0
        failed_count = 0
        failed_entries = []
        
        # Check last 1000 entries or all if less
        check_limit = min(1000, total_entries)
        
        entries = audit_collection.find().sort("timestamp_utc", -1).limit(check_limit)
        
        for entry in entries:
            if verify_audit_integrity(entry["id"]):
                verified_count += 1
            else:
                failed_count += 1
                failed_entries.append({
                    "id": entry["id"],
                    "timestamp": entry["timestamp_utc"],
                    "event_type": entry["event_type"]
                })
        
        result = {
            "total_checked": check_limit,
            "verified": verified_count,
            "failed": failed_count,
            "integrity_percentage": (verified_count / check_limit * 100) if check_limit > 0 else 0,
            "failed_entries": failed_entries
        }
        
        # Log the integrity check
        log_audit(
            event_type=EventType.AUDIT_INTEGRITY_CHECK,
            actor=Actor(actor_type=ActorType.SYSTEM),
            target=Target(object_type=ObjectType.COLLECTION, object_id="audit_logs"),
            outcome=Outcome(
                status=OutcomeStatus.SUCCESS if failed_count == 0 else OutcomeStatus.FAILURE,
                code="INTEGRITY_CHECK_COMPLETE",
                message=f"Checked {check_limit} entries, {failed_count} failed"
            ),
            details=result,
            request_meta=RequestMeta(request_id=str(uuid.uuid4())),
            retention_tag="retention_7y"
        )
        
        logger.info(f"Integrity check complete: {verified_count}/{check_limit} verified")
        return result
        
    except Exception as e:
        logger.error(f"Error during integrity check: {e}")
        return {"error": str(e)}

def apply_retention_policy(dry_run: bool = True) -> Dict[str, Any]:
    """Apply retention policies to audit logs"""
    try:
        logger.info(f"Starting retention policy application (dry_run={dry_run})...")
        
        # Define retention periods
        retention_policies = {
            "retention_1y": timedelta(days=365),
            "retention_3y": timedelta(days=1095),
            "retention_7y": timedelta(days=2555),
            "retention_permanent": None  # Never delete
        }
        
        now = datetime.now(timezone.utc)
        deletion_summary = {}
        
        for policy_tag, retention_period in retention_policies.items():
            if retention_period is None:
                continue  # Skip permanent retention
            
            cutoff_date = now - retention_period
            
            # Find expired entries not under legal hold
            query = {
                "retention_policy_tag": policy_tag,
                "timestamp_utc": {"$lt": cutoff_date},
                "legal_hold": {"$ne": True}
            }
            
            expired_count = audit_collection.count_documents(query)
            
            if not dry_run and expired_count > 0:
                result = audit_collection.delete_many(query)
                deletion_summary[policy_tag] = {
                    "expired_entries": expired_count,
                    "deleted": result.deleted_count
                }
            else:
                deletion_summary[policy_tag] = {
                    "expired_entries": expired_count,
                    "deleted": 0 if dry_run else expired_count
                }
        
        # Log retention policy application
        log_audit(
            event_type=EventType.AUDIT_RETENTION_PURGE,
            actor=Actor(actor_type=ActorType.SYSTEM),
            target=Target(object_type=ObjectType.COLLECTION, object_id="audit_logs"),
            outcome=Outcome(
                status=OutcomeStatus.SUCCESS,
                code="RETENTION_POLICY_APPLIED",
                message=f"Retention policy applied (dry_run={dry_run})"
            ),
            details={"deletion_summary": deletion_summary, "dry_run": dry_run},
            request_meta=RequestMeta(request_id=str(uuid.uuid4())),
            retention_tag="retention_permanent"
        )
        
        logger.info(f"Retention policy complete: {deletion_summary}")
        return deletion_summary
        
    except Exception as e:
        logger.error(f"Error applying retention policy: {e}")
        return {"error": str(e)}

# Convenience functions for common audit events
def log_login_success(user_id: str, email: str, request_meta: RequestMeta):
    """Log successful login"""
    return log_audit(
        event_type=EventType.USER_LOGIN_SUCCESS,
        actor=Actor(user_id=user_id, user_email=email, actor_type=ActorType.USER),
        target=Target(object_type=ObjectType.USER, object_id=user_id),
        outcome=Outcome(status=OutcomeStatus.SUCCESS, code="LOGIN_SUCCESS"),
        details={"login_method": "password"},
        request_meta=request_meta,
        retention_tag="retention_7y"
    )

def log_login_failure(email: str, reason: str, request_meta: RequestMeta):
    """Log failed login attempt"""
    return log_audit(
        event_type=EventType.USER_LOGIN_FAILED,
        actor=Actor(user_email=email, actor_type=ActorType.USER),
        target=Target(object_type=ObjectType.USER),
        outcome=Outcome(status=OutcomeStatus.FAILURE, code="LOGIN_FAILED", message=reason),
        details={"failure_reason": reason, "login_method": "password"},
        request_meta=request_meta,
        retention_tag="retention_7y"
    )

def log_document_access(user_id: str, document_id: str, title: str, request_meta: RequestMeta):
    """Log document access/read"""
    return log_audit(
        event_type=EventType.DOCUMENT_OPEN,
        actor=Actor(user_id=user_id, actor_type=ActorType.USER),
        target=Target(object_type=ObjectType.DOCUMENT, object_id=document_id, object_name=title),
        outcome=Outcome(status=OutcomeStatus.SUCCESS, code="DOCUMENT_ACCESSED"),
        details={"access_type": "read"},
        request_meta=request_meta,
        retention_tag="retention_7y"
    )

def log_document_update(user_id: str, document_id: str, changes: Dict[str, Any], request_meta: RequestMeta):
    """Log document update with diff information"""
    # Create a hash of the changes for audit trail without storing full content
    changes_hash = hashlib.sha256(json.dumps(changes, sort_keys=True, cls=DateTimeJSONEncoder).encode()).hexdigest()
    
    return log_audit(
        event_type=EventType.DOCUMENT_UPDATE,
        actor=Actor(user_id=user_id, actor_type=ActorType.USER),
        target=Target(object_type=ObjectType.DOCUMENT, object_id=document_id),
        outcome=Outcome(status=OutcomeStatus.SUCCESS, code="DOCUMENT_UPDATED"),
        details={
            "fields_changed": list(changes.keys()),
            "changes_hash": changes_hash,
            "change_count": len(changes)
        },
        request_meta=request_meta,
        retention_tag="retention_7y"
    )

def log_ai_interaction(user_id: str, document_id: str, query_type: str, request_meta: RequestMeta):
    """Log AI/chat interactions with privacy protection"""
    return log_audit(
        event_type=EventType.AI_QUERY_SUBMITTED,
        actor=Actor(user_id=user_id, actor_type=ActorType.USER),
        target=Target(object_type=ObjectType.DOCUMENT, object_id=document_id),
        outcome=Outcome(status=OutcomeStatus.SUCCESS, code="AI_QUERY_PROCESSED"),
        details={
            "query_type": query_type,
            "content_redacted": True,
            "ai_model": "gemini-2.0-flash"
        },
        request_meta=request_meta,
        retention_tag="retention_3y"
    )

def log_admin_operation(operator_id: str, operation: str, target_info: Dict[str, Any], request_meta: RequestMeta):
    """Log administrative operations"""
    return log_audit(
        event_type=EventType.ADMIN_SCRIPT_EXECUTE,
        actor=Actor(user_id=operator_id, actor_type=ActorType.USER),
        target=Target(object_type=ObjectType.COLLECTION, object_id=target_info.get("collection_name")),
        outcome=Outcome(status=OutcomeStatus.SUCCESS, code="ADMIN_OPERATION"),
        details={
            "operation": operation,
            "target_details": target_info,
            "execution_context": "administrative_script"
        },
        request_meta=request_meta,
        retention_tag="retention_7y"
    )

# Global session manager instance
session_audit_manager = SessionAuditManager()

# Session-based audit functions
def start_audit_session(user_id: str, user_email: str, session_meta: Dict[str, Any] = None) -> str:
    """Start a new audit session"""
    return session_audit_manager.start_session(user_id, user_email, session_meta)

def end_audit_session(session_id: str, end_reason: str = "user_logout") -> bool:
    """End an audit session"""
    print(f"🔚 ENDING SESSION: {session_id} | Reason: {end_reason}")
    result = session_audit_manager.end_session(session_id, end_reason)
    if result:
        print(f"✅ Session {session_id} ended successfully and flushed to database")
    else:
        print(f"❌ Failed to end session {session_id}")
    return result

def log_session_event(session_id: str, event_type: str, actor: Dict[str, Any], 
                     target: Dict[str, Any], outcome: Dict[str, Any], 
                     details: Dict[str, Any], request_meta: Dict[str, Any] = None):
    """Log an event to a session"""
    print(f"🔍 AUDIT LOG: {event_type} | Session: {session_id} | User: {actor.get('user_id', 'unknown')} | Target: {target.get('object_type', 'unknown')}:{target.get('object_id', 'unknown')}")
    session_audit_manager.add_event(session_id, event_type, actor, target, outcome, details, request_meta or {})

# Session-based convenience functions
def log_document_access_session(session_id: str, user_id: str, document_id: str, title: str, request_meta: Dict[str, Any]):
    """Log document access in session"""
    print(f"📖 DOCUMENT ACCESS: User {user_id} opened document {document_id} ({title}) | Session: {session_id}")
    log_session_event(
        session_id=session_id,
        event_type="document.open",
        actor={"user_id": user_id, "actor_type": "user"},
        target={"object_type": "document", "object_id": document_id, "object_name": title},
        outcome={"status": "success", "code": "DOCUMENT_ACCESSED"},
        details={"access_type": "read"},
        request_meta=request_meta
    )

def log_document_update_session(session_id: str, user_id: str, document_id: str, changes: Dict[str, Any], request_meta: Dict[str, Any]):
    """Log document update in session"""
    changes_hash = hashlib.sha256(json.dumps(changes, sort_keys=True).encode()).hexdigest()
    
    print(f"✏️ DOCUMENT UPDATE: User {user_id} modified document {document_id} | Changes: {list(changes.keys())} | Session: {session_id}")
    
    log_session_event(
        session_id=session_id,
        event_type="document.update",
        actor={"user_id": user_id, "actor_type": "user"},
        target={"object_type": "document", "object_id": document_id},
        outcome={"status": "success", "code": "DOCUMENT_UPDATED"},
        details={
            "fields_changed": list(changes.keys()),
            "changes_hash": changes_hash,
            "change_count": len(changes)
        },
        request_meta=request_meta
    )

def log_ai_interaction_session(session_id: str, user_id: str, document_id: str, query_type: str, request_meta: Dict[str, Any]):
    """Log AI interaction in session"""
    log_session_event(
        session_id=session_id,
        event_type="ai.query.submitted",
        actor={"user_id": user_id, "actor_type": "user"},
        target={"object_type": "document", "object_id": document_id},
        outcome={"status": "success", "code": "AI_QUERY_PROCESSED"},
        details={
            "query_type": query_type,
            "content_redacted": True,
            "ai_model": "gemini-2.0-flash"
        },
        request_meta=request_meta
    )

def log_login_success_session(session_id: str, user_id: str, email: str, request_meta: Dict[str, Any]):
    """Log successful login in session"""
    log_session_event(
        session_id=session_id,
        event_type="user.login.success",
        actor={"user_id": user_id, "user_email": email, "actor_type": "user"},
        target={"object_type": "user", "object_id": user_id},
        outcome={"status": "success", "code": "LOGIN_SUCCESS"},
        details={"login_method": "password"},
        request_meta=request_meta
    )

def log_logout_session(session_id: str, user_id: str, email: str, request_meta: Dict[str, Any]):
    """Log logout in session"""
    log_session_event(
        session_id=session_id,
        event_type="user.logout",
        actor={"user_id": user_id, "user_email": email, "actor_type": "user"},
        target={"object_type": "user", "object_id": user_id},
        outcome={"status": "success", "code": "LOGOUT_SUCCESS"},
        details={"logout_method": "user_action"},
        request_meta=request_meta
    )

if __name__ == "__main__":
    # Test the session audit system
    print("Testing Session-based Audit Logging System...")
    
    # Test session creation
    test_session_id = start_audit_session("test-user-123", "test@example.com", {"login_method": "password"})
    print(f"Created test session: {test_session_id}")
    
    # Test various events
    test_request_meta = {"request_id": str(uuid.uuid4()), "session_id": test_session_id, "ip": "127.0.0.1"}
    
    # Simulate document activities
    log_document_access_session(test_session_id, "test-user-123", "doc-123", "Test Document", test_request_meta)
    log_document_access_session(test_session_id, "test-user-123", "doc-456", "Another Document", test_request_meta)
    log_document_access_session(test_session_id, "test-user-123", "doc-789", "Third Document", test_request_meta)
    
    # Simulate document updates
    log_document_update_session(test_session_id, "test-user-123", "doc-123", {"title": "Updated Title", "content": "New content"}, test_request_meta)
    
    # Simulate AI interactions
    log_ai_interaction_session(test_session_id, "test-user-123", "doc-123", "compliance_check", test_request_meta)
    log_ai_interaction_session(test_session_id, "test-user-123", "doc-456", "risk_analysis", test_request_meta)
    
    print(f"Added multiple events to session {test_session_id}")
    
    # End session
    success = end_audit_session(test_session_id, "user_logout")
    if success:
        print(f"Successfully ended session {test_session_id} and flushed to database")
    else:
        print(f"Failed to end session {test_session_id}")
    
    # Test legacy system compatibility
    print("\nTesting Legacy Audit System Compatibility...")
    test_request_meta_legacy = RequestMeta(
        request_id=str(uuid.uuid4()),
        ip="127.0.0.1",
        user_agent="test-agent"
    )
    
    # Test legacy login success
    legacy_audit_id = log_login_success("test-user-456", "legacy@example.com", test_request_meta_legacy)
    print(f"Legacy audit entry created: {legacy_audit_id}")
    
    # Run integrity check
    print("\nRunning integrity check...")
    integrity_result = run_integrity_check()
    print("Integrity check result:", json.dumps(integrity_result, indent=2, cls=DateTimeJSONEncoder))
    
    print("\nSession-based audit logging system test completed successfully!")
