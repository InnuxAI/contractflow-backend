"""
Script to rebuild the vector database with Gemini embeddings.

This script extracts documents from an existing ChromaDB collection,
re-embeds them using a specified model, and creates a new collection.
"""

import os
import logging
from dotenv import load_dotenv
import chromadb
import google.generativeai as genai
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Get environment variables
CHROMA_API_KEY = os.getenv("CHROMA_API_KEY")
CHROMA_TENANT = os.getenv("CHROMA_TENANT")
CHROMA_DATABASE = os.getenv("CHROMA_DATABASE", 'contract_documents')
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Collection names
OLD_COLLECTION_NAME = "contract-openai"  # Or whatever the old collection is
NEW_COLLECTION_NAME = "contract-gemini"

if not CHROMA_API_KEY or not GEMINI_API_KEY or not CHROMA_TENANT:
    raise EnvironmentError("❌ CHROMA_API_KEY, CHROMA_TENANT and GEMINI_API_KEY must be set.")

# Initialize Gemini client
genai.configure(api_key=GEMINI_API_KEY)

# Initialize ChromaDB client
client = chromadb.CloudClient(
    api_key=CHROMA_API_KEY,
    tenant=CHROMA_TENANT,
    database=CHROMA_DATABASE
)

def embed_text(text):
    """Generate embeddings using Gemini model."""
    try:
        embedding_model = "models/embedding-001"
        response = genai.embed_content(
            model=embedding_model,
            content=text,
            task_type="RETRIEVAL_DOCUMENT"
        )
        return response["embedding"]
    except Exception as e:
        logger.error(f"Error generating embeddings: {e}")
        raise

def rebuild_collection():
    """Rebuild the vector database with Gemini embeddings."""
    try:
        logger.info(f"Accessing old collection: {OLD_COLLECTION_NAME}")
        old_collection = client.get_collection(name=OLD_COLLECTION_NAME)
        
        logger.info(f"Creating new collection: {NEW_COLLECTION_NAME}")
        new_collection = client.get_or_create_collection(name=NEW_COLLECTION_NAME)

        # Get all documents from the old collection
        results = old_collection.get() # This gets all data
        
        documents = results['documents']
        metadatas = results['metadatas']
        ids = results['ids']

        logger.info(f"Retrieved {len(documents)} points from old collection")
        
        # Process points in batches
        batch_size = 100
        for i in tqdm(range(0, len(documents), batch_size), desc="Processing and embedding documents"):
            batch_docs = documents[i:i+batch_size]
            batch_metadatas = metadatas[i:i+batch_size]
            batch_ids = ids[i:i+batch_size]
            
            new_embeddings = [embed_text(doc) for doc in batch_docs]
            
            new_collection.add(
                ids=batch_ids,
                embeddings=new_embeddings,
                metadatas=batch_metadatas,
                documents=batch_docs
            )
            logger.info(f"Upserted batch {i//batch_size + 1}")

        logger.info(f"Successfully rebuilt collection with {new_collection.count()} points")
        
    except Exception as e:
        logger.error(f"Error rebuilding collection: {e}")
        raise

if __name__ == "__main__":
    rebuild_collection()