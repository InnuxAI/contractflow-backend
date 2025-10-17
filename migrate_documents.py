import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent))

from database import documents_collection
from models import Priority

# Import audit logging
from audit_logger import log_admin_operation
from audit_middleware import AuditContextManager, create_request_meta_from_context

def migrate_existing_documents(operator_id: str = "system-migrator"):
    """
    Update existing documents to include the new priority and date fields
    with comprehensive audit logging.
    """
    
    with AuditContextManager("migrate_documents", operator_id) as audit_ctx:
        print("Starting migration of existing documents...")
        
        # Find all documents that don't have the new fields
        documents_to_update = documents_collection.find({
            "$or": [
                {"priority": {"$exists": False}},
                {"date_received": {"$exists": False}},
                {"date_review_due": {"$exists": False}}
            ]
        })
        
        count = 0
        updated_documents = []
        
        for doc in documents_to_update:
            # Set default values for missing fields
            update_data = {}
            
            if "priority" not in doc:
                update_data["priority"] = Priority.NORMAL.value
            
            if "date_received" not in doc:
                # Use created_at if available, otherwise use current time
                update_data["date_received"] = doc.get("created_at", datetime.now())
            
            if "date_review_due" not in doc:
                # Calculate due date based on priority and date_received
                priority = update_data.get("priority", doc.get("priority", Priority.NORMAL.value))
                date_received = update_data.get("date_received", doc.get("date_received", datetime.now()))
                
                days_to_add = 3 if priority == Priority.URGENT.value else 7
                update_data["date_review_due"] = date_received + timedelta(days=days_to_add)
            
            if update_data:
                update_data["last_modified"] = datetime.now()
                
                # Track document details for audit
                document_info = {
                    "document_id": str(doc["_id"]),
                    "title": doc.get("title", "Untitled"),
                    "fields_updated": list(update_data.keys())
                }
                updated_documents.append(document_info)
                
                documents_collection.update_one(
                    {"_id": doc["_id"]}, 
                    {"$set": update_data}
                )
                count += 1
                print(f"Updated document: {doc.get('title', doc['_id'])}")
        
        print(f"Migration completed! Updated {count} documents.")
        
        # Log the migration operation
        request_meta = create_request_meta_from_context(audit_ctx.request_id)
        log_admin_operation(
            operator_id=operator_id,
            operation="migrate_document_schema",
            target_info={
                "collection_name": "documents",
                "operation_type": "schema_migration",
                "documents_updated": count,
                "updated_documents": updated_documents[:100],  # Limit to first 100 for audit log size
                "migration_fields": ["priority", "date_received", "date_review_due"],
                "total_found": len(updated_documents)
            },
            request_meta=request_meta
        )
        
        return {
            "success": True,
            "documents_updated": count,
            "updated_documents": updated_documents
        }

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Migrate document schema with audit logging")
    parser.add_argument("--operator", "-o", default="system-migrator",
                       help="ID of the operator performing this migration")
    parser.add_argument("--dry-run", "-d", action="store_true",
                       help="Show what would be updated without making changes")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("🔍 DRY RUN MODE - No changes will be made")
        # In dry run mode, we'd query and show what would be updated
        # Implementation omitted for brevity
        print("Run without --dry-run to execute the migration")
    else:
        print(f"🔐 Migration initiated by: {args.operator}")
        result = migrate_existing_documents(args.operator)
        
        if result["success"]:
            print(f"✅ Migration completed successfully")
            print(f"   Documents updated: {result['documents_updated']}")
        else:
            print(f"❌ Migration failed")
            sys.exit(1)
