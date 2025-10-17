import argparse
import os
import logging
from dotenv import load_dotenv
import chromadb

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Read credentials
CHROMA_API_KEY = os.getenv("CHROMA_API_KEY")
CHROMA_TENANT = os.getenv("CHROMA_TENANT")
CHROMA_DATABASE = os.getenv("CHROMA_DATABASE", 'contract_documents')


if not CHROMA_API_KEY or not CHROMA_TENANT:
    raise EnvironmentError("❌ CHROMA_API_KEY and CHROMA_TENANT must be set in the environment variables.")

# Connect to Chroma
client = chromadb.CloudClient(
    api_key=CHROMA_API_KEY,
    tenant=CHROMA_TENANT,
    database=CHROMA_DATABASE
)

def list_collections():
    try:
        collections = client.list_collections()
        logging.info("📦 Available collections in ChromaDB:")
        for col in collections:
            logging.info(f" - {col.name}")
    except Exception as e:
        logging.error(f"❌ Failed to list collections: {e}")

def collection_info(name):
    try:
        collection = client.get_collection(name)
        count = collection.count()
        logging.info(f"ℹ️ Collection: {name}")
        logging.info(f" - Vectors count: {count}")
    except Exception as e:
        logging.error(f"❌ Failed to fetch info for '{name}': {e}")

def clear_collection(name):
    try:
        logging.info(f"🧹 Clearing all points from collection '{name}'...")
        collection = client.get_collection(name)
        # To clear a collection, we delete it and recreate it.
        client.delete_collection(name=name)
        client.create_collection(name=name)
        logging.info("✅ All points deleted.")
    except Exception as e:
        logging.error(f"❌ Error clearing points in '{name}': {e}")

def delete_collection(name):
    try:
        client.delete_collection(name=name)
        logging.info(f"🗑️ Collection '{name}' deleted successfully.")
    except Exception as e:
        logging.error(f"❌ Failed to delete collection '{name}': {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🧰 ChromaDB CLI Tool")
    parser.add_argument("--list", action="store_true", help="List all collections")
    parser.add_argument("--info", metavar="COLLECTION", help="Get info about a collection")
    parser.add_argument("--clear", metavar="COLLECTION", help="Clear all points from a collection")
    parser.add_argument("--delete", metavar="COLLECTION", help="Delete a collection completely")

    args = parser.parse_args()

    if args.list:
        list_collections()
    elif args.info:
        collection_info(args.info)
    elif args.clear:
        clear_collection(args.clear)
    elif args.delete:
        delete_collection(args.delete)
    else:
        parser.print_help()
