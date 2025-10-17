#!/usr/bin/env python3
"""
Quick test script to check current approvers data in documents
"""

from pymongo import MongoClient
from bson import ObjectId
import sys
import os

# Add the current directory to the path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import db

def check_approvers_data():
    """Check current state of approvers data"""
    
    print("Checking current approvers data...")
    
    # Get all documents with approvers
    documents = list(db.documents.find({"approvers": {"$exists": True, "$ne": []}}))
    
    print(f"Found {len(documents)} documents with approvers")
    print("=" * 60)
    
    for doc in documents:
        print(f"Document: {doc.get('title', 'Unknown')}")
        print(f"ID: {doc['_id']}")
        approvers = doc.get('approvers', [])
        print(f"Approvers: {approvers}")
        
        # Check if approvers are IDs or names/emails
        for i, approver in enumerate(approvers):
            try:
                import uuid
                uuid.UUID(approver)
                print(f"  Approver {i+1}: {approver} (Valid UUID)")
            except (ValueError, TypeError):
                print(f"  Approver {i+1}: {approver} (NOT a valid UUID - needs fixing)")
        
        print("-" * 40)

def main():
    check_approvers_data()

if __name__ == "__main__":
    main()
