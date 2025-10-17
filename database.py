from pymongo import MongoClient
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
client = MongoClient(MONGODB_URL)
db = client["document_review_db"]

users_collection = db["users"]
documents_collection = db["documents"]
clauses_collection = db["clauses"]

def update_document_status():
    """Update document status based on time and conditions"""
    # Update NEW to PENDING if more than 1 day has passed
    one_day_ago = datetime.now() - timedelta(days=1)
    documents_collection.update_many(
        {
            "status": "new",
            "created_at": {"$lt": one_day_ago}
        },
        {"$set": {"status": "pending"}}
    )

def get_user_by_email(email: str):
    return users_collection.find_one({"email": email})

def get_user_by_id(user_id: str):
    return users_collection.find_one({"_id": user_id})

def create_user(user_data: dict):
    return users_collection.insert_one(user_data)

def create_document(document_data: dict):
    return documents_collection.insert_one(document_data)

def get_document_by_id(doc_id: str):
    return documents_collection.find_one({"_id": doc_id})

def update_document(doc_id: str, update_data: dict):
    update_data["last_modified"] = datetime.now()
    return documents_collection.update_one(
        {"_id": doc_id},
        {"$set": update_data}
    )

def get_documents_for_user(user_id: str, role: str):
    if role == "reviewer":
        return list(documents_collection.find({"reviewer_id": user_id}))
    else:  # approver
        return list(documents_collection.find({"approvers": user_id}))

def get_clauses(domain: str = None):
    query = {"domain": domain} if domain else {}
    return list(clauses_collection.find(query))

def create_clause(clause_data: dict):
    clause_data["created_at"] = datetime.utcnow()
    clause_data["last_modified"] = datetime.utcnow()
    return clauses_collection.insert_one(clause_data)
