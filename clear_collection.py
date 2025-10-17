#!/usr/bin/env python3
"""
Script to clear the ChromaDB collection before re-ingesting documents.
Enhanced with comprehensive audit logging.
"""

import os
import sys
from dotenv import load_dotenv
import chromadb

# Add current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from audit_logger import log_admin_operation
from audit_middleware import AuditContextManager, create_request_meta_from_context

# Load environment variables
load_dotenv()
CHROMA_API_KEY = os.getenv("CHROMA_API_KEY")
CHROMA_TENANT = os.getenv("CHROMA_TENANT")
CHROMA_DATABASE = os.getenv("CHROMA_DATABASE", 'contract_documents')
COLLECTION_NAME = "contract-gemini"

def clear_collection(operator_id: str = "system-admin"):
    """Clear the ChromaDB collection with comprehensive audit logging."""
    
    with AuditContextManager("clear_collection", operator_id) as audit_ctx:
        try:
            # Initialize ChromaDB client
            chroma_client = chromadb.CloudClient(
                api_key=CHROMA_API_KEY,
                tenant=CHROMA_TENANT,
                database=CHROMA_DATABASE
            )
            
            # Check if collection exists
            collections = chroma_client.list_collections()
            collection_names = [collection.name for collection in collections]
            
            records_deleted = 0
            
            if COLLECTION_NAME in collection_names:
                # Get count before deletion for audit
                collection = chroma_client.get_collection(name=COLLECTION_NAME)
                records_deleted = collection.count()
                
                print(f"🗑️  Deleting collection '{COLLECTION_NAME}' with {records_deleted} records...")
                
                # Log the collection clear operation
                request_meta = create_request_meta_from_context(audit_ctx.request_id)
                log_admin_operation(
                    operator_id=operator_id,
                    operation="clear_chroma_collection",
                    target_info={
                        "collection_name": COLLECTION_NAME,
                        "database": CHROMA_DATABASE,
                        "records_deleted": records_deleted,
                        "operation_type": "collection_clear"
                    },
                    request_meta=request_meta
                )
                
                chroma_client.delete_collection(name=COLLECTION_NAME)
                print(f"✅ Collection '{COLLECTION_NAME}' deleted successfully!")
            else:
                print(f"ℹ️  Collection '{COLLECTION_NAME}' doesn't exist, nothing to delete.")
                
                # Log no-op operation
                request_meta = create_request_meta_from_context(audit_ctx.request_id)
                log_admin_operation(
                    operator_id=operator_id,
                    operation="clear_chroma_collection_noop",
                    target_info={
                        "collection_name": COLLECTION_NAME,
                        "database": CHROMA_DATABASE,
                        "records_deleted": 0,
                        "operation_type": "collection_clear_noop",
                        "reason": "collection_does_not_exist"
                    },
                    request_meta=request_meta
                )
                
            # Create a fresh collection
            print(f"🆕 Creating fresh collection '{COLLECTION_NAME}'...")
            collection = chroma_client.create_collection(name=COLLECTION_NAME)
            print(f"✅ Fresh collection '{COLLECTION_NAME}' created successfully!")
            
            # Verify it's empty
            count = collection.count()
            print(f"📊 New collection has {count} vectors (should be 0)")
            
            # Log collection creation
            request_meta = create_request_meta_from_context(audit_ctx.request_id)
            log_admin_operation(
                operator_id=operator_id,
                operation="create_chroma_collection",
                target_info={
                    "collection_name": COLLECTION_NAME,
                    "database": CHROMA_DATABASE,
                    "initial_count": count,
                    "operation_type": "collection_create"
                },
                request_meta=request_meta
            )
            
            return {
                "success": True,
                "records_deleted": records_deleted,
                "collection_recreated": True,
                "final_count": count
            }
            
        except Exception as e:
            print(f"❌ Error clearing collection: {e}")
            
            # Log the error
            request_meta = create_request_meta_from_context(audit_ctx.request_id)
            log_admin_operation(
                operator_id=operator_id,
                operation="clear_chroma_collection_error",
                target_info={
                    "collection_name": COLLECTION_NAME,
                    "database": CHROMA_DATABASE,
                    "operation_type": "collection_clear_error",
                    "error": str(e)
                },
                request_meta=request_meta
            )
            
            import traceback
            traceback.print_exc()
            return {
                "success": False,
                "error": str(e)
            }

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Clear ChromaDB collection with audit logging")
    parser.add_argument("--operator", "-o", default="system-admin", 
                       help="ID of the operator performing this action")
    parser.add_argument("--confirm", "-c", action="store_true",
                       help="Confirm the operation (required for safety)")
    
    args = parser.parse_args()
    
    if not args.confirm:
        print("⚠️  This operation will delete all vectors in the collection!")
        print("   Use --confirm flag to proceed.")
        sys.exit(1)
    
    print(f"🔐 Operation initiated by: {args.operator}")
    result = clear_collection(args.operator)
    
    if result["success"]:
        print(f"✅ Operation completed successfully")
        print(f"   Records deleted: {result['records_deleted']}")
        print(f"   Collection recreated: {result['collection_recreated']}")
        print(f"   Final count: {result['final_count']}")
    else:
        print(f"❌ Operation failed: {result['error']}")
        sys.exit(1)
