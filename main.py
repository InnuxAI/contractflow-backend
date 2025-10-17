from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from datetime import timedelta
import uuid
from typing import List
import os
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import Optional
import json
import logging

from models import User, Document, DocumentStatus, DocumentUpdate, AddApproversRequest
from database import (
    get_user_by_email, create_user, create_document,
    get_document_by_id, update_document, get_documents_for_user,
    get_user_by_id
)
from auth import (
    verify_password, get_password_hash, create_access_token,
    get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES, authenticate_user,
    create_and_log_token, logout_user
)

# Import audit logging components
from audit_logger import (
    log_audit, EventType, Actor, Target, Outcome, ObjectType,
    ActorType, OutcomeStatus, log_document_access, log_document_update,
    log_ai_interaction, log_document_access_session, log_document_update_session,
    log_ai_interaction_session, log_session_event
)
from audit_middleware import (
    AuditMiddleware, get_current_request_meta, get_current_user as get_context_user,
    create_request_meta_from_context, should_log_audit_event
)

import clauses
import ai_chat

from fastapi import WebSocket, WebSocketDisconnect
from typing import List


# Load environment variables
load_dotenv()

# Suppress PyMongo heartbeat and connection logs
logging.getLogger("pymongo").setLevel(logging.WARNING)
logging.getLogger("pymongo.server").setLevel(logging.WARNING)
logging.getLogger("pymongo.pool").setLevel(logging.WARNING)

app = FastAPI()

# Add audit middleware BEFORE CORS middleware
app.add_middleware(AuditMiddleware)

# Updated CORS middleware to use allow_origin_regex for dynamic origin matching
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*\.vercel\.app",  # Allow all Vercel frontend deployments
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(clauses.router, prefix="/api", tags=["clauses"])
app.include_router(ai_chat.router, prefix="/api", tags=["ai_chat"])

class EmailRequest(BaseModel):
    document_id: str
    recipient_email: str
    subject: str
    message: str


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # optionally handle incoming client messages
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Enhanced login endpoint with session-based audit logging"""
    user, session_id = await authenticate_user(form_data.username, form_data.password)
    
    if not user or not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_and_log_token(user, session_id, access_token_expires)
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "session_id": session_id  # Return session_id to frontend
    }

@app.post("/logout")
async def logout(
    current_user: dict = Depends(get_current_user)
):
    """Logout endpoint with session-based audit logging"""
    session_id = current_user.get("session_id")
    print(f"🚪 LOGOUT: User {current_user.get('email')} | Session: {session_id}")
    
    # Extract token from the current request (this would be better handled in middleware)
    # For now, we'll use a placeholder token
    token = "current_token_placeholder"
    
    await logout_user(current_user, token, session_id)
    
    return {"message": "Successfully logged out"}

@app.post("/users/")
async def create_new_user(user: User):
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    user_dict["_id"] = str(uuid.uuid4())
    create_user(user_dict)
    return {"message": "User created successfully"}

@app.get("/documents/")
async def get_my_documents(
    status: DocumentStatus = None,
    current_user: dict = Depends(get_current_user)
):
    """Get all documents assigned to current user, optionally filtered by status"""
    documents = get_documents_for_user(str(current_user["_id"]), current_user["role"])
    
    # Convert binary content to base64 for each document
    for doc in documents:
        if doc.get("content"):
            try:
                # If content is bytes, encode to base64
                if isinstance(doc["content"], bytes):
                    doc["content"] = base64.b64encode(doc["content"]).decode('utf-8')
            except Exception as e:
                print(f"Error encoding document content: {e}")
                doc["content"] = None
    
    if status:
        documents = [doc for doc in documents if doc["status"] == status]
    return documents

@app.post("/documents/{document_id}/approvers")
async def add_approvers(
    document_id: str,
    request: AddApproversRequest,
    current_user: dict = Depends(get_current_user)
):
    """Add approvers to a document with enhanced error handling"""
    document = get_document_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    if current_user["role"] != "reviewer" or str(current_user["_id"]) != document["reviewer_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the assigned reviewer can add approvers"
        )
    
    # Get session_id for audit logging
    session_id = current_user.get("session_id")
    request_meta = create_request_meta_from_context()
    
    # Enhanced approver validation with better error messages
    valid_approvers = []
    invalid_approvers = []
    
    for approver_id in request.approver_ids:
        try:
            # Clean the approver_id (remove any extra whitespace)
            clean_approver_id = str(approver_id).strip()
            
            approver = get_user_by_id(clean_approver_id)
            if not approver:
                invalid_approvers.append(f"User not found: {clean_approver_id}")
                continue
                
            if approver.get("role") != "approver":
                invalid_approvers.append(f"User {clean_approver_id} is not an approver (role: {approver.get('role', 'unknown')})")
                continue
                
            valid_approvers.append(clean_approver_id)
            
        except Exception as e:
            invalid_approvers.append(f"Error validating {approver_id}: {str(e)}")
    
    # If there are invalid approvers, return detailed error
    if invalid_approvers:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Some approvers are invalid",
                "invalid_approvers": invalid_approvers,
                "valid_approvers": valid_approvers
            }
        )
    
    # Get current approvers and add new ones (avoid duplicates)
    current_approvers = document.get("approvers", [])
    updated_approvers = list(set(current_approvers + valid_approvers))
    
    update_document(document_id, {"approvers": updated_approvers})
    await manager.broadcast(json.dumps({
        "event": "document_updated",
        "document_id": document_id,
    }))
    return {"message": "Approvers added successfully", "approvers": updated_approvers}


@app.post("/documents/{document_id}/save")
async def save_document_only(
    document_id: str,
    update: DocumentUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Save document changes without changing status with audit logging.
    Only reviewer or approver assigned to the document can perform this action.
    Status field in update is ignored.
    """
    document = get_document_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    # Permission check
    is_reviewer = (current_user["role"] == "reviewer" and str(current_user["_id"]) == document["reviewer_id"])
    is_approver = (current_user["role"] == "approver" and str(current_user["_id"]) in document["approvers"])
    if not (is_reviewer or is_approver):
        raise HTTPException(status_code=403, detail="Not authorized to update this document")

    update_data = update.dict(exclude_unset=True)
    if "status" in update_data:
        del update_data["status"]
    
    session_id = current_user.get("session_id")
    
    print(f"🔑 Save Document: User {current_user.get('email')} | Document {document_id} | Session: {session_id}")
    
    # Log document update with session-based audit trail
    if session_id:
        request_meta_dict = {
            "request_id": f"doc_update_{document_id}",
            "session_id": session_id,
            "ip": getattr(get_current_request_meta(), 'ip', None) if get_current_request_meta() else None
        }
        log_document_update_session(
            session_id=session_id,
            user_id=str(current_user["_id"]),
            document_id=document_id,
            changes=update_data,
            request_meta=request_meta_dict
        )
    else:
        # Fallback to legacy logging if no session
        request_meta = get_current_request_meta() or create_request_meta_from_context()
        log_document_update(
            user_id=str(current_user["_id"]),
            document_id=document_id,
            changes=update_data,
            request_meta=request_meta
        )
    
    update_document(document_id, update_data)
    await manager.broadcast(json.dumps({
        "event": "document_updated",
        "document_id": document_id,
    }))
    return {"message": "Document saved successfully."}

@app.get("/documents/{document_id}")
async def get_document(
    document_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get document with session-based audit logging for access"""
    document = get_document_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    session_id = current_user.get("session_id")
    print(f"🔑 Document Access: User {current_user.get('email')} | Document {document_id} | Session: {session_id}")
    
    if (str(current_user["_id"]) != document["reviewer_id"] and 
        str(current_user["_id"]) not in document["approvers"]):
        
        # Log unauthorized access attempt (still use legacy for security events)
        request_meta = get_current_request_meta() or create_request_meta_from_context()
        log_audit(
            event_type=EventType.SECURITY_PRIVILEGE_ESCALATION,
            actor=Actor(
                user_id=str(current_user["_id"]),
                user_email=current_user.get("email"),
                actor_type=ActorType.USER
            ),
            target=Target(object_type=ObjectType.DOCUMENT, object_id=document_id),
            outcome=Outcome(
                status=OutcomeStatus.FAILURE,
                code="UNAUTHORIZED_DOCUMENT_ACCESS",
                message="User attempted to access document without permission"
            ),
            details={
                "document_title": document.get("title"),
                "user_role": current_user.get("role"),
                "authorized_users": {
                    "reviewer_id": document["reviewer_id"],
                    "approvers": document["approvers"]
                }
            },
            request_meta=request_meta,
            retention_tag="retention_7y"
        )
        
        raise HTTPException(status_code=403, detail="Not authorized to access this document")
    
    # Log successful document access in session
    if session_id:
        request_meta_dict = {
            "request_id": f"doc_access_{document_id}",
            "session_id": session_id,
            "ip": getattr(get_current_request_meta(), 'ip', None) if get_current_request_meta() else None
        }
        log_document_access_session(
            session_id=session_id,
            user_id=str(current_user["_id"]),
            document_id=document_id,
            title=document.get("title", "Untitled"),
            request_meta=request_meta_dict
        )
    else:
        # Fallback to legacy logging if no session
        request_meta = get_current_request_meta() or create_request_meta_from_context()
        log_document_access(
            user_id=str(current_user["_id"]),
            document_id=document_id,
            title=document.get("title", "Untitled"),
            request_meta=request_meta
        )
    
    # Convert binary content to base64
    if document.get("content"):
        try:
            if isinstance(document["content"], bytes):
                document["content"] = base64.b64encode(document["content"]).decode('utf-8')
        except Exception as e:
            print(f"Error encoding document content: {e}")
            document["content"] = None
    
    # Update status to WITH_REVIEWER if it's NEW or PENDING
    if document["status"] in [DocumentStatus.NEW, DocumentStatus.PENDING]:
        update_document(document_id, {"status": DocumentStatus.WITH_REVIEWER})
        
        # Log status change
        log_session_event(
            session_id=session_id,
            event_type=EventType.DOCUMENT_STATUS_CHANGE,
            actor=Actor(
                user_id=str(current_user["_id"]),
                user_email=current_user.get("email"),
                actor_type=ActorType.USER
            ).dict(),
            target=Target(object_type=ObjectType.DOCUMENT, object_id=document_id).dict(),
            outcome=Outcome(status=OutcomeStatus.SUCCESS, code="STATUS_UPDATED").dict(),
            details={
                "status_from": document["status"],
                "status_to": DocumentStatus.WITH_REVIEWER,
                "reason": "automatic_update_on_first_access"
            }
        )
    
    return document

@app.put("/documents/{document_id}")
async def update_document_status(
    document_id: str,
    update: DocumentUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update document status with comprehensive audit logging"""
    document = get_document_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Get session_id for audit logging
    session_id = current_user.get("session_id")
    print(f"🔑 Status Update: User {current_user.get('email')} | Document {document_id} | Session: {session_id}")
    request_meta = get_current_request_meta() or create_request_meta_from_context()
    previous_status = document.get("status")
    
    if current_user["role"] == "reviewer":
        if str(current_user["_id"]) != document["reviewer_id"]:
            raise HTTPException(status_code=403, detail="Not authorized to update this document")
        
        # If reviewer is marking changes as complete
        if update.status == DocumentStatus.WITH_APPROVER:
            # Check if document has approvers
            if not document.get("approvers") or len(document["approvers"]) == 0:
                raise HTTPException(
                    status_code=400, 
                    detail="Cannot send to approver: No approvers assigned to this document. Please assign at least one approver first."
                )
            
            update_data = {
                "status": DocumentStatus.WITH_APPROVER,
                "changes_summary": update.changes_summary or "Document ready for approval",
                "notes": update.notes or "Document sent to approver"
            }
            
            # Log document approval assignment
            log_session_event(
                session_id=session_id,
                event_type=EventType.DOCUMENT_ASSIGN_APPROVER,
                actor=Actor(
                    user_id=str(current_user["_id"]),
                    user_email=current_user.get("email"),
                    actor_type=ActorType.USER
                ).dict(),
                target=Target(object_type=ObjectType.DOCUMENT, object_id=document_id).dict(),
                outcome=Outcome(status=OutcomeStatus.SUCCESS, code="ASSIGNED_TO_APPROVERS").dict(),
                details={
                    "changes_summary": update.changes_summary,
                    "notes": update.notes,
                    "approvers_count": len(document["approvers"])
                },
                request_meta=request_meta
            )
            
            # Notify approvers (in a real system, this would send emails/notifications)
            for approver_id in document["approvers"]:
                approver = get_user_by_id(approver_id)
                if approver:
                    print(f"Notifying approver {approver['email']} that changes are ready for review")
                    
                    # Log notification sent
                    log_session_event(
                        session_id=session_id,
                        event_type=EventType.EMAIL_SENT,
                        actor=Actor(actor_type=ActorType.SYSTEM).dict(),
                        target=Target(object_type=ObjectType.EMAIL, object_id=f"notify_{approver_id}").dict(),
                        outcome=Outcome(status=OutcomeStatus.SUCCESS, code="APPROVAL_NOTIFICATION_SENT").dict(),
                        details={
                            "recipient_id": approver_id,
                            "recipient_email": approver["email"],
                            "document_id": document_id,
                            "notification_type": "approval_required"
                        },
                        request_meta=request_meta
                    )
        else:
            update_data = update.dict(exclude_unset=True)
    else:  # approver
        if str(current_user["_id"]) not in document["approvers"]:
            raise HTTPException(status_code=403, detail="Not authorized to update this document")
        
        if update.status == DocumentStatus.APPROVED:
            # Log document approval
            log_session_event(
                session_id=session_id,
                event_type=EventType.DOCUMENT_APPROVE,
                actor=Actor(
                    user_id=str(current_user["_id"]),
                    user_email=current_user.get("email"),
                    actor_type=ActorType.USER
                ).dict(),
                target=Target(
                    object_type=ObjectType.DOCUMENT, 
                    object_id=document_id,
                    object_name=document.get("title")
                ).dict(),
                outcome=Outcome(status=OutcomeStatus.SUCCESS, code="DOCUMENT_APPROVED").dict(),
                details={
                    "document_title": document.get("title"),
                    "final_approval": True
                },
                request_meta=request_meta
            )
            
            # Mock email sending
            print(f"Document {document_id} approved and sent via email")
            update_data = {"status": update.status, "notes": update.notes}
        else:
            # Document rejected - send back to reviewer
            # Document rejected - send back to reviewer
            log_session_event(
                session_id=session_id,
                event_type=EventType.DOCUMENT_REJECT,
                actor=Actor(
                    user_id=str(current_user["_id"]),
                    user_email=current_user.get("email"),
                    actor_type=ActorType.USER
                ).dict(),
                target=Target(
                    object_type=ObjectType.DOCUMENT,
                    object_id=document_id,
                    object_name=document.get("title")
                ).dict(),
                outcome=Outcome(status=OutcomeStatus.SUCCESS, code="DOCUMENT_REJECTED").dict(),
                details={
                    "reason": update.notes,
                    "rejection_notes": update.notes
                },
                request_meta=request_meta
            )
            
            # Send back to reviewer with notes
            update_data = {
                "status": DocumentStatus.WITH_REVIEWER,
                "notes": update.notes,
                "last_reviewed_by": str(current_user["_id"])
            }
            # Include content if it's being updated
            if update.content:
                update_data["content"] = update.content
    
    # Ensure status is always included in update
    if "status" not in update_data:
        update_data["status"] = document["status"]
    
    # Log status change if status actually changed
    if update_data["status"] != previous_status:
        log_session_event(
            session_id=session_id,
            event_type=EventType.DOCUMENT_STATUS_CHANGE,
            actor=Actor(
                user_id=str(current_user["_id"]),
                user_email=current_user.get("email"),
                actor_type=ActorType.USER
            ).dict(),
            target=Target(object_type=ObjectType.DOCUMENT, object_id=document_id).dict(),
            outcome=Outcome(status=OutcomeStatus.SUCCESS, code="STATUS_CHANGED").dict(),
            details={
                "status_from": previous_status,
                "status_to": update_data["status"],
                "user_role": current_user["role"]
            },
            request_meta=request_meta
        )
    
    update_document(document_id, update_data)
    await manager.broadcast(json.dumps({
        "event": "document_updated",
        "document_id": document_id,
    }))
    return {"message": "Document updated successfully"}

@app.get("/users/email/{email}")
async def get_user_by_email_endpoint(email: str):
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/api/documents/send-email")
async def send_email(request: EmailRequest):
    try:
        # Get document from database
        document = await get_document_by_id(request.document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        # Create message
        msg = MIMEMultipart()
        msg['From'] = os.getenv('SMTP_EMAIL', 'aksshainair.work@gmail.com')
        msg['To'] = request.recipient_email
        msg['Subject'] = request.subject

        # Add message body
        msg.attach(MIMEText(request.message, 'plain'))

        # Add document as attachment
        if document.get('content'):
            attachment = MIMEApplication(document['content'].encode())
            attachment.add_header(
                'Content-Disposition',
                'attachment',
                filename=f"{document['title']}.docx"
            )
            msg.attach(attachment)

        # Send email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(
                os.getenv('SMTP_EMAIL', 'your-email@gmail.com'),
                os.getenv('SMTP_PASSWORD', 'your-app-password')
            )
            smtp.send_message(msg)

        return {"message": "Email sent successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users/{user_id}")
async def get_user_by_id_endpoint(user_id: str):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
