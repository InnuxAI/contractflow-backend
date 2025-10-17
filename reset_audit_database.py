#!/usr/bin/env python3
"""
Reset Audit Database Script
Clears all audit entries to start fresh with the fixed serialization.
"""

import sys
import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def reset_audit_database():
    """Clear all audit entries from the database"""
    try:
        # Connect to MongoDB
        MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017") 
        AUDIT_COLLECTION_NAME = os.getenv("AUDIT_COLLECTION_NAME", "audit_logs")
        
        client = MongoClient(MONGODB_URL)
        db = client["document_review_db"]
        audit_collection = db[AUDIT_COLLECTION_NAME]
        
        # Count existing entries
        count_before = audit_collection.count_documents({})
        print(f"Found {count_before} audit entries in database")
        
        if count_before > 0:
            # Clear all audit entries
            result = audit_collection.delete_many({})
            print(f"Deleted {result.deleted_count} audit entries")
        else:
            print("No audit entries to delete")
        
        # Verify deletion
        count_after = audit_collection.count_documents({})
        print(f"Audit entries remaining: {count_after}")
        
        if count_after == 0:
            print("✓ Audit database successfully reset")
            return True
        else:
            print("✗ Some entries could not be deleted")
            return False
            
    except Exception as e:
        print(f"✗ Error resetting audit database: {e}")
        return False

if __name__ == "__main__":
    print("🗑️  Resetting Audit Database")
    print("=" * 40)
    
    if reset_audit_database():
        print("\n✓ Database reset complete!")
        print("You can now run setup_audit_system.py again")
        sys.exit(0)
    else:
        print("\n✗ Database reset failed")
        sys.exit(1)
