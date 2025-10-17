import google.generativeai as genai
import os
from dotenv import load_dotenv
import numpy as np

# Load environment variables
load_dotenv()

# Initialize Gemini client
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

def embed_text(text: str) -> list:
    """
    Generate embeddings for the given text using Google's embedding model.
    
    Returns native 768-dimensional Gemini embeddings.
    """
    try:
        # Use Google's embedding model
        embedding_model = "models/embedding-001"
        response = genai.embed_content(
            model=embedding_model,
            content=text,
            task_type="RETRIEVAL_QUERY"
        )
        
        embedding = response["embedding"]
        
        # Normalize the embedding to unit length (cosine similarity)
        embedding = np.array(embedding)
        embedding = embedding / np.linalg.norm(embedding)
        
        return embedding.tolist()
    except Exception as e:
        raise Exception(f"Error generating embeddings: {str(e)}") 