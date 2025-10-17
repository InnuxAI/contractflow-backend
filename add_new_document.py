import os
import sys
from pathlib import Path
import uuid
from datetime import datetime, timedelta
import base64

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from database import create_user, create_document
from auth import get_password_hash
from models import UserRole, Priority

def create_sample_users():
    pass

def create_sample_documents(reviewer_id, approvers):
    sample_docs_dir = Path(__file__).parent / "sampledocs"
    
    if not sample_docs_dir.exists():
        print("Sample documents directory not found")
        return
    
    # Look for .docx files instead of .sfdt
    doc_files = list(sample_docs_dir.glob("*.docx"))
    if not doc_files:
        print("No .docx files found in sampledocs directory")
        return
    
    for i, doc_file in enumerate(doc_files):
        with open(doc_file, "rb") as f:
            content = base64.b64encode(f.read()).decode('utf-8')  # Base64 encode the binary content
        
        # Alternate between urgent and normal priority
        priority = Priority.URGENT if i % 2 == 0 else Priority.NORMAL
        date_received = datetime.now()
        
        # Calculate review due date based on priority
        days_to_add = 3 if priority == Priority.URGENT else 7
        date_review_due = date_received + timedelta(days=days_to_add)
        
        document = {
            "_id": str(uuid.uuid4()),
            "title": doc_file.name,
            "content": content,
            "reviewer_id": reviewer_id,
            "approvers": [],  # Empty approvers array initially
            "status": "new",
            "priority": priority.value,
            "date_received": date_received,
            "date_review_due": date_review_due,
            "created_at": datetime.now(),
            "last_modified": datetime.now()
        }
        create_document(document)
        print(f"Created document: {doc_file.name} with priority: {priority.value}")
        print(f"  Date received: {date_received.strftime('%Y-%m-%d')}")
        print(f"  Due date: {date_review_due.strftime('%Y-%m-%d')}")

if __name__ == "__main__":
    # reviewer_id, approvers = create_sample_users()
    create_sample_documents("940d53e2-97f5-41c0-8b16-f3e565190041", [])
    print("Database population completed successfully") 