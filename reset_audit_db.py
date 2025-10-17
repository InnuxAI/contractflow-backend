#!/usr/bin/env python3
"""
Reset audit database - clears all audit entries to start fresh.
Use this when there are integrity issues due to schema changes.
"""

import os
import sys
from database import db, audit_collection

def reset_audit_database():
    """Clear all audit entries and reset the collection"""
    try:
        # Drop the entire audit collection
        audit_collection.drop()
        print("[SUCCESS] Audit collection cleared")
        
        # Recreate indexes
        audit_collection.create_index("id", unique=True)
        audit_collection.create_index("timestamp")
        audit_collection.create_index("event_type")
        audit_collection.create_index("actor.user_id")
        audit_collection.create_index("target.object_id")
        audit_collection.create_index("request_meta.request_id")
        print("[SUCCESS] Audit collection indexes recreated")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to reset audit database: {e}")
        return False

if __name__ == "__main__":
    print("🗑️  Resetting audit database...")
    print("⚠️  This will delete ALL audit entries!")
    
    # Ask for confirmation
    response = input("Are you sure you want to continue? (yes/no): ")
    if response.lower() in ['yes', 'y']:
        if reset_audit_database():
            print("\n[SUCCESS] Audit database reset complete!")
            print("You can now run setup_audit_system.py to create fresh entries.")
        else:
            print("\n[ERROR] Failed to reset audit database")
            sys.exit(1)
    else:
        print("Operation cancelled")
        sys.exit(0)
