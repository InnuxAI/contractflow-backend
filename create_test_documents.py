import os
import sys
from pathlib import Path
import uuid
from datetime import datetime, timedelta
import base64

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from database import create_document
from models import Priority

def create_test_documents():
    reviewer_id = "940d53e2-97f5-41c0-8b16-f3e565190041"
    
    # Document 1: Urgent, New (just received)
    date_received = datetime.now()
    document1 = {
        "_id": str(uuid.uuid4()),
        "title": "Contract Agreement - Vendor A.docx",
        "content": "",  # Empty content for testing
        "reviewer_id": reviewer_id,
        "approvers": [],
        "status": "new",
        "priority": Priority.URGENT.value,
        "date_received": date_received,
        "date_review_due": date_received + timedelta(days=3),
        "created_at": datetime.now(),
        "last_modified": datetime.now()
    }
    create_document(document1)
    print(f"Created: {document1['title']} - Urgent, New")
    
    # Document 2: Normal, With Reviewer
    date_received = datetime.now() - timedelta(days=2)
    document2 = {
        "_id": str(uuid.uuid4()),
        "title": "Service Level Agreement - Client B.docx",
        "content": "",
        "reviewer_id": reviewer_id,
        "approvers": [],
        "status": "with_reviewer",
        "priority": Priority.NORMAL.value,
        "date_received": date_received,
        "date_review_due": date_received + timedelta(days=7),
        "created_at": datetime.now() - timedelta(days=2),
        "last_modified": datetime.now()
    }
    create_document(document2)
    print(f"Created: {document2['title']} - Normal, With Reviewer")
    
    # Document 3: Urgent, With Approver
    date_received = datetime.now() - timedelta(days=1)
    document3 = {
        "_id": str(uuid.uuid4()),
        "title": "Emergency Procurement Contract.docx",
        "content": "",
        "reviewer_id": reviewer_id,
        "approvers": ["approver1"],
        "status": "with_approver",
        "priority": Priority.URGENT.value,
        "date_received": date_received,
        "date_review_due": date_received + timedelta(days=3),
        "created_at": datetime.now() - timedelta(days=1),
        "last_modified": datetime.now()
    }
    create_document(document3)
    print(f"Created: {document3['title']} - Urgent, With Approver")
    
    # Document 4: Normal, Overdue (simulate overdue document)
    date_received = datetime.now() - timedelta(days=10)
    document4 = {
        "_id": str(uuid.uuid4()),
        "title": "Standard Terms and Conditions.docx",
        "content": "",
        "reviewer_id": reviewer_id,
        "approvers": [],
        "status": "pending",
        "priority": Priority.NORMAL.value,
        "date_received": date_received,
        "date_review_due": date_received + timedelta(days=7),  # This will be overdue
        "created_at": datetime.now() - timedelta(days=10),
        "last_modified": datetime.now()
    }
    create_document(document4)
    print(f"Created: {document4['title']} - Normal, Overdue")
    
    # Document 5: Urgent, Approved
    date_received = datetime.now() - timedelta(days=5)
    document5 = {
        "_id": str(uuid.uuid4()),
        "title": "Critical Infrastructure Agreement.docx",
        "content": "",
        "reviewer_id": reviewer_id,
        "approvers": ["approver1"],
        "status": "approved",
        "priority": Priority.URGENT.value,
        "date_received": date_received,
        "date_review_due": date_received + timedelta(days=3),
        "created_at": datetime.now() - timedelta(days=5),
        "last_modified": datetime.now()
    }
    create_document(document5)
    print(f"Created: {document5['title']} - Urgent, Approved")

if __name__ == "__main__":
    create_test_documents()
    print("Test documents created successfully!")
