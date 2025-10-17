#!/usr/bin/env python3
"""
Quick test script to verify ChromaDB is working correctly with the new chunked data.
"""

import os
from dotenv import load_dotenv
import chromadb
from embedding_utils import embed_text

# Load environment variables
load_dotenv()
CHROMA_API_KEY = os.getenv("CHROMA_API_KEY")
CHROMA_TENANT = os.getenv("CHROMA_TENANT")
CHROMA_DATABASE = os.getenv("CHROMA_DATABASE", 'contract_documents')
COLLECTION_NAME = "contract-gemini"

# Initialize ChromaDB client
chroma_client = chromadb.CloudClient(
    api_key=CHROMA_API_KEY,
    tenant=CHROMA_TENANT,
    database=CHROMA_DATABASE
)

def test_chroma_search():
    """Test basic ChromaDB functionality."""
    
    try:
        # Get collection
        collection = chroma_client.get_collection(name=COLLECTION_NAME)
        
        # Check collection stats
        count = collection.count()
        print(f"✅ Collection '{COLLECTION_NAME}' has {count} vectors")
        
        # Test a basic query
        test_query = "contract terms"
        query_embedding = embed_text(test_query)
        
        # Search without document filter
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=5
        )
        
        print(f"\n🔍 Search results for '{test_query}':")
        if results and results['ids'] and results['ids'][0]:
            for i, (chunk_id, distance, metadata, document) in enumerate(zip(
                results['ids'][0],
                results['distances'][0],
                results['metadatas'][0],
                results['documents'][0] if results.get('documents') else [None] * len(results['ids'][0])
            )):
                print(f"\n  Result {i+1}:")
                print(f"    ID: {chunk_id}")
                print(f"    Distance: {distance:.4f}")
                print(f"    Score: {1-distance:.4f}")
                print(f"    Metadata: {metadata}")
                if document:
                    print(f"    Content: {document[:200]}...")
                else:
                    print("    Content: [No content stored]")
        else:
            print("  No results found")
            
        # Test document-specific query
        print(f"\n🔍 Testing document-specific search...")
        
        # Get a list of unique mongo_ids
        all_data = collection.get()
        mongo_ids = set()
        if all_data and all_data.get('metadatas'):
            for metadata in all_data['metadatas']:
                if 'mongo_id' in metadata:
                    mongo_ids.add(metadata['mongo_id'])
        
        print(f"Found documents: {list(mongo_ids)[:3]}...")  # Show first 3
        
        if mongo_ids:
            test_doc_id = list(mongo_ids)[0]  # Use first document
            doc_results = collection.query(
                query_embeddings=[query_embedding],
                n_results=3,
                where={"mongo_id": test_doc_id}
            )
            
            print(f"\n🔍 Document-specific search for doc '{test_doc_id}':")
            if doc_results and doc_results['ids'] and doc_results['ids'][0]:
                for i, (chunk_id, distance, document) in enumerate(zip(
                    doc_results['ids'][0],
                    doc_results['distances'][0],
                    doc_results['documents'][0] if doc_results.get('documents') else [None] * len(doc_results['ids'][0])
                )):
                    print(f"\n  Chunk {i+1}:")
                    print(f"    ID: {chunk_id}")
                    print(f"    Score: {1-distance:.4f}")
                    if document:
                        print(f"    Content: {document[:150]}...")
                    else:
                        print("    Content: [No content stored]")
            else:
                print("  No chunks found for this document")
        
        print("\n✅ ChromaDB test completed successfully!")
        
    except Exception as e:
        print(f"❌ Error testing ChromaDB: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_chroma_search()
