#!/usr/bin/env python3
"""
Script to fix approvers data in documents collection.
This script will:
1. Find all documents that have approver names/emails in the approvers array
2. Convert those names/emails back to user IDs
3. Update the documents with the correct approver IDs
"""

from pymongo import MongoClient
from bson import ObjectId
import re
import sys
import os

# Add the current directory to the path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import db

def get_user_id_by_email(email):
    """Get user ID by email address"""
    try:
        user = db.users.find_one({"email": email})
        return str(user["_id"]) if user else None
    except Exception as e:
        print(f"Error finding user by email {email}: {e}")
        return None

def get_user_id_by_name(name):
    """Get user ID by name (assuming name is part of email before @)"""
    try:
        # Try to find user where email starts with the name
        user = db.users.find_one({"email": {"$regex": f"^{re.escape(name)}@"}})
        return str(user["_id"]) if user else None
    except Exception as e:
        print(f"Error finding user by name {name}: {e}")
        return None

def is_valid_uuid(uuid_string):
    """Check if a string is a valid UUID format"""
    import uuid
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def is_valid_user_id(id_string):
    """Check if a string is a valid user ID (UUID format)"""
    return is_valid_uuid(id_string)

def fix_approvers_data():
    """Main function to fix approvers data"""
    
    print("Starting approvers data fix...")
    
    # Get all documents
    documents = list(db.documents.find({}))
    print(f"Found {len(documents)} documents to check")
    
    fixed_count = 0
    error_count = 0
    
    for doc in documents:
        doc_id = doc["_id"]
        approvers = doc.get("approvers", [])
        
        if not approvers:
            continue
            
        print(f"\nProcessing document: {doc.get('title', 'Unknown')} (ID: {doc_id})")
        print(f"Current approvers: {approvers}")
        
        new_approvers = []
        needs_update = False
        
        for approver in approvers:
            if not approver:  # Skip empty values
                continue
                
            # Check if it's already a valid user ID (UUID)
            if is_valid_user_id(approver):
                print(f"  ✓ '{approver}' is already a valid user ID")
                new_approvers.append(approver)
                continue
            
            needs_update = True
            
            # Try to convert to user ID
            user_id = None
            
            # Handle special placeholder names
            if approver.lower() in ['approver1', 'approver']:
                print(f"  → Converting placeholder '{approver}' to approver1@example.com...")
                user_id = get_user_id_by_email("approver1@example.com")
            elif approver.lower() == 'approver2':
                print(f"  → Converting placeholder '{approver}' to approver2@example.com...")
                user_id = get_user_id_by_email("approver2@example.com")
            elif approver.lower() == 'approver3':
                print(f"  → Converting placeholder '{approver}' to approver3@example.com...")
                user_id = get_user_id_by_email("approver3@example.com")
            # Check if it's an email
            elif "@" in approver:
                print(f"  → Converting email '{approver}' to user ID...")
                user_id = get_user_id_by_email(approver)
            else:
                # Assume it's a name (part before @ in email)
                print(f"  → Converting name '{approver}' to user ID...")
                user_id = get_user_id_by_name(approver)
            
            if user_id:
                print(f"  ✓ Found user ID: {user_id}")
                new_approvers.append(user_id)
            else:
                print(f"  ✗ Could not find user for: {approver}")
                error_count += 1
                # Keep the original value if we can't convert it
                new_approvers.append(approver)
        
        # Update the document if needed
        if needs_update and new_approvers:
            try:
                result = db.documents.update_one(
                    {"_id": doc_id},
                    {"$set": {"approvers": new_approvers}}
                )
                
                if result.modified_count > 0:
                    print(f"  ✓ Updated document with new approvers: {new_approvers}")
                    fixed_count += 1
                else:
                    print(f"  ⚠ Document was not updated (no changes detected)")
            except Exception as e:
                print(f"  ✗ Error updating document: {e}")
                error_count += 1
        else:
            print(f"  - No changes needed for this document")
    
    print(f"\n" + "="*50)
    print(f"Fix completed!")
    print(f"Documents fixed: {fixed_count}")
    print(f"Errors encountered: {error_count}")
    print(f"Total documents processed: {len(documents)}")

def show_users():
    """Helper function to show all users in the system"""
    users = list(db.users.find({}))
    
    print("\nAll users in the system:")
    print("-" * 40)
    for user in users:
        print(f"ID: {user['_id']} | Email: {user.get('email', 'N/A')} | Role: {user.get('role', 'N/A')}")

def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == "--show-users":
        show_users()
        return
    
    try:
        fix_approvers_data()
    except Exception as e:
        print(f"Error running fix: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("Approvers Data Fix Script")
    print("========================")
    print("This script will convert approver names/emails to user IDs in the documents collection.")
    print("Use --show-users to see all users in the system first.")
    print()
    
    main()
