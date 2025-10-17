from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr
from enum import Enum

class UserRole(str, Enum):
    REVIEWER = "reviewer"
    APPROVER = "approver"

class DocumentStatus(str, Enum):
    NEW = "new"
    PENDING = "pending"
    WITH_REVIEWER = "with_reviewer"
    WITH_APPROVER = "with_approver"
    APPROVED = "approved"

class Priority(str, Enum):
    URGENT = "urgent"
    NORMAL = "normal"

class User(BaseModel):
    id: str
    email: EmailStr
    password: str
    role: UserRole
    created_at: datetime = datetime.now()

class Document(BaseModel):
    id: str
    title: str
    content: Optional[str] = None  # Base64 encoded PDF content
    reviewer_id: str
    approvers: List[str] = []
    status: DocumentStatus = DocumentStatus.NEW
    priority: Priority = Priority.NORMAL
    date_received: datetime = datetime.now()
    date_review_due: Optional[datetime] = None
    created_at: datetime = datetime.now()
    last_modified: datetime = datetime.now()
    notes: Optional[str] = None
    last_reviewed_by: Optional[str] = None
    changes_summary: Optional[str] = None
    
    def __init__(self, **data):
        super().__init__(**data)
        # Auto-calculate review due date if not provided (7 days for normal, 3 days for urgent)
        if self.date_review_due is None:
            days_to_add = 3 if self.priority == Priority.URGENT else 7
            self.date_review_due = self.date_received + timedelta(days=days_to_add)

class DocumentUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    status: Optional[DocumentStatus] = None
    priority: Optional[Priority] = None
    approvers: Optional[List[str]] = None
    notes: Optional[str] = None
    changes_summary: Optional[str] = None

class AddApproversRequest(BaseModel):
    approver_ids: List[str]
