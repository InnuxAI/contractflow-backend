"""
Request middleware for audit logging system.
Generates request IDs, collects metadata, and provides audit context.
"""

import uuid
import time
from typing import Optional
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from contextvars import ContextVar
import logging

from audit_logger import RequestMeta

logger = logging.getLogger(__name__)

# Context variables for request-scoped data
request_id_context: ContextVar[str] = ContextVar('request_id')
request_meta_context: ContextVar[RequestMeta] = ContextVar('request_meta')
user_context: ContextVar[Optional[dict]] = ContextVar('user_context', default=None)

class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware to inject request ID and collect metadata for audit logging.
    """
    
    def __init__(self, app, secret_key: str = None):
        super().__init__(app)
        self.secret_key = secret_key
    
    async def dispatch(self, request: Request, call_next):
        # Generate or extract request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        
        # Extract client information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")
        origin = request.headers.get("Origin", "")
        
        # Create request metadata
        request_meta = RequestMeta(
            request_id=request_id,
            ip=client_ip,
            user_agent=user_agent,
            origin=origin,
            trace_id=request.headers.get("X-Trace-ID"),
            session_id=request.headers.get("X-Session-ID")
        )
        
        # Set context variables
        request_id_context.set(request_id)
        request_meta_context.set(request_meta)
        
        # Add request metadata to request state for access in endpoints
        request.state.request_id = request_id
        request.state.request_meta = request_meta
        request.state.audit_start_time = time.time()
        
        try:
            # Process the request
            response = await call_next(request)
            
            # Add request ID to response headers for client correlation
            response.headers["X-Request-ID"] = request_id
            
            # Log request completion time for performance monitoring
            duration = time.time() - request.state.audit_start_time
            if duration > 5.0:  # Log slow requests
                logger.warning(f"Slow request: {request_id} - {request.method} {request.url.path} - {duration:.2f}s")
            
            return response
            
        except Exception as e:
            # Log request errors for audit purposes
            logger.error(f"Request error: {request_id} - {request.method} {request.url.path} - {str(e)}")
            
            # Return error response with request ID
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error", "request_id": request_id},
                headers={"X-Request-ID": request_id}
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request, handling proxies"""
        # Check for forwarded headers (common in production deployments)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        # Check for real IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to direct client IP
        if request.client:
            return request.client.host
        
        return "unknown"

def get_current_request_id() -> Optional[str]:
    """Get the current request ID from context"""
    try:
        return request_id_context.get()
    except LookupError:
        return None

def get_current_request_meta() -> Optional[RequestMeta]:
    """Get the current request metadata from context"""
    try:
        return request_meta_context.get()
    except LookupError:
        return None

def set_current_user(user: dict):
    """Set the current user in context after authentication"""
    user_context.set(user)

def get_current_user() -> Optional[dict]:
    """Get the current user from context"""
    try:
        return user_context.get()
    except LookupError:
        return None

def create_request_meta_from_context(
    override_request_id: Optional[str] = None,
    additional_info: Optional[dict] = None
) -> RequestMeta:
    """
    Create RequestMeta object from current context or provided overrides.
    Useful for background jobs or system operations.
    """
    current_meta = get_current_request_meta()
    
    if current_meta:
        # Use existing metadata but allow overrides
        return RequestMeta(
            request_id=override_request_id or current_meta.request_id,
            ip=current_meta.ip,
            user_agent=current_meta.user_agent,
            origin=current_meta.origin,
            trace_id=current_meta.trace_id,
            session_id=current_meta.session_id
        )
    else:
        # Create new metadata for system operations
        return RequestMeta(
            request_id=override_request_id or str(uuid.uuid4()),
            ip="system",
            user_agent="system-process",
            origin="internal",
            trace_id=additional_info.get("trace_id") if additional_info else None
        )

# Utility functions for common audit scenarios
def audit_context_wrapper(func):
    """
    Decorator to ensure audit context is available for background jobs or system operations.
    """
    def wrapper(*args, **kwargs):
        # Ensure we have a request context for audit logging
        if not get_current_request_id():
            request_id = str(uuid.uuid4())
            request_meta = RequestMeta(
                request_id=request_id,
                ip="system",
                user_agent="background-job",
                origin="internal"
            )
            request_id_context.set(request_id)
            request_meta_context.set(request_meta)
        
        return func(*args, **kwargs)
    
    return wrapper

class AuditContextManager:
    """
    Context manager for creating audit context in background jobs or scripts.
    """
    
    def __init__(self, operation_name: str, operator_id: Optional[str] = None):
        self.operation_name = operation_name
        self.operator_id = operator_id
        self.request_id = str(uuid.uuid4())
        self.original_request_id = None
        self.original_request_meta = None
    
    def __enter__(self):
        # Save original context if it exists
        self.original_request_id = get_current_request_id()
        self.original_request_meta = get_current_request_meta()
        
        # Set new context for this operation
        request_meta = RequestMeta(
            request_id=self.request_id,
            ip="system",
            user_agent=f"system-operation-{self.operation_name}",
            origin="internal"
        )
        
        request_id_context.set(self.request_id)
        request_meta_context.set(request_meta)
        
        if self.operator_id:
            # Set a system user context
            user_context.set({
                "_id": self.operator_id,
                "email": f"system-{self.operator_id}",
                "role": "system"
            })
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original context
        if self.original_request_id:
            request_id_context.set(self.original_request_id)
        if self.original_request_meta:
            request_meta_context.set(self.original_request_meta)

# Rate limiting support for audit logging
class RateLimiter:
    """
    Simple rate limiter to prevent audit log spam from excessive events.
    """
    
    def __init__(self):
        self.request_counts = {}
        self.last_reset = time.time()
        self.reset_interval = 60  # Reset every minute
        self.max_requests_per_minute = 100
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed based on rate limit"""
        now = time.time()
        
        # Reset counters if interval has passed
        if now - self.last_reset > self.reset_interval:
            self.request_counts.clear()
            self.last_reset = now
        
        # Check current count
        current_count = self.request_counts.get(key, 0)
        if current_count >= self.max_requests_per_minute:
            return False
        
        # Increment counter
        self.request_counts[key] = current_count + 1
        return True
    
    def get_rate_limit_key(self, request_meta: RequestMeta, event_type: str) -> str:
        """Generate rate limit key from request metadata and event type"""
        return f"{request_meta.ip}:{event_type}"

# Global rate limiter instance
audit_rate_limiter = RateLimiter()

def should_log_audit_event(event_type: str, request_meta: RequestMeta) -> bool:
    """
    Determine if an audit event should be logged based on rate limiting.
    Security-critical events are never rate-limited.
    """
    # Never rate-limit security events
    security_events = [
        "user.login.failed", "security.failed_login_attempt",
        "security.privilege_escalation", "admin.", "audit."
    ]
    
    if any(event_type.startswith(se) for se in security_events):
        return True
    
    # Apply rate limiting to other events
    rate_limit_key = audit_rate_limiter.get_rate_limit_key(request_meta, event_type)
    return audit_rate_limiter.is_allowed(rate_limit_key)

# Export key functions and classes
__all__ = [
    'AuditMiddleware',
    'get_current_request_id',
    'get_current_request_meta', 
    'set_current_user',
    'get_current_user',
    'create_request_meta_from_context',
    'audit_context_wrapper',
    'AuditContextManager',
    'should_log_audit_event'
]
