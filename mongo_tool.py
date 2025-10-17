import argparse
import os
from datetime import datetime, timedelta
from bson import ObjectId
from pymongo import MongoClient
from dotenv import load_dotenv

# Load env variables
load_dotenv()
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")

# Setup Mongo
client = MongoClient(MONGODB_URL)
db = client["document_review_db"]
users = db["users"]
documents = db["documents"]
clauses = db["clauses"]

# === Operations ===
def list_users():
    print("📋 Users:")
    for u in users.find():
        print(f" - {u.get('email')} ({u.get('_id')})")

def list_documents():
    print("📄 Documents:")
    for doc in documents.find():
        print(f" - {doc.get('title')} | Status: {doc.get('status')} | ID: {doc['_id']}")

def get_user(email):
    user = users.find_one({"email": email})
    print(user or "❌ No user found.")

def create_user(email, role):
    new_user = {
        "email": email,
        "role": role,
        "created_at": datetime.utcnow()
    }
    result = users.insert_one(new_user)
    print(f"✅ User created with ID: {result.inserted_id}")

def create_document(title, user_id):
    new_doc = {
        "title": title,
        "status": "new",
        "created_at": datetime.utcnow(),
        "owner_id": user_id
    }
    result = documents.insert_one(new_doc)
    print(f"✅ Document created with ID: {result.inserted_id}")

def update_statuses():
    one_day_ago = datetime.utcnow() - timedelta(days=1)
    result = documents.update_many(
        {"status": "new", "created_at": {"$lt": one_day_ago}},
        {"$set": {"status": "pending", "last_modified": datetime.utcnow()}}
    )
    print(f"🔄 {result.modified_count} documents updated from 'new' to 'pending'.")

def update_document(doc_id, title=None, status=None):
    update_fields = {}
    if title:
        update_fields["title"] = title
    if status:
        update_fields["status"] = status
    update_fields["last_modified"] = datetime.utcnow()

    result = documents.update_one({"_id": ObjectId(doc_id)}, {"$set": update_fields})
    print(f"✅ Document updated: {result.modified_count} modified.")

# === CLI ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MongoDB CLI for Document Review DB")
    parser.add_argument("--list-users", action="store_true")
    parser.add_argument("--list-docs", action="store_true")
    parser.add_argument("--get-user", help="Email of user to find")
    parser.add_argument("--create-user", nargs=2, metavar=('email', 'role'), help="Create user with email and role")
    parser.add_argument("--create-doc", nargs=2, metavar=('title', 'user_id'), help="Create document for user")
    parser.add_argument("--update-statuses", action="store_true", help="Update 'new' docs to 'pending' if >1 day old")
    parser.add_argument("--update-doc-id", help="Document ID to update")
    parser.add_argument("--title", help="New title for the document")
    parser.add_argument("--status", help="New status for the document")

    args = parser.parse_args()

    if args.list_users:
        list_users()
    elif args.list_docs:
        list_documents()
    elif args.get_user:
        get_user(args.get_user)
    elif args.create_user:
        create_user(*args.create_user)
    elif args.create_doc:
        create_document(*args.create_doc)
    elif args.update_statuses:
        update_statuses()
    elif args.update_doc:
        from argparse import ArgumentParser
        update_parser = ArgumentParser()
        update_parser.add_argument("doc_id")
        update_parser.add_argument("--title")
        update_parser.add_argument("--status")
        parsed, _ = update_parser.parse_known_args(args.update_doc)
        update_document(parsed.doc_id, parsed.title, parsed.status)
    else:
        parser.print_help()
