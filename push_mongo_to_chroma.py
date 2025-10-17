import os
import uuid
from dotenv import load_dotenv
from pymongo import MongoClient
import chromadb
from sentence_transformers import SentenceTransformer
import logging
import base64
import zipfile
import io
import json
import re
from typing import List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
load_dotenv()
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
CHROMA_API_KEY = os.getenv("CHROMA_API_KEY")
CHROMA_TENANT = os.getenv("CHROMA_TENANT")
CHROMA_DATABASE = os.getenv("CHROMA_DATABASE", 'contract_documents')

if not CHROMA_API_KEY or not CHROMA_TENANT:
    raise EnvironmentError("❌ CHROMA_API_KEY and CHROMA_TENANT must be set in the environment variables.")

# MongoDB Setup
logging.info("Connecting to MongoDB...")
mongo_client = MongoClient(MONGODB_URL)
db = mongo_client["document_review_db"]
documents_collection = db["documents"]
logging.info("✅ Connected to MongoDB.")

# ChromaDB Setup
logging.info("Connecting to ChromaDB...")
chroma_client = chromadb.CloudClient(
    api_key=CHROMA_API_KEY,
    tenant=CHROMA_TENANT,
    database=CHROMA_DATABASE
)
COLLECTION_NAME = "contract-gemini"
logging.info("✅ Connected to ChromaDB.")


# Load embedding model
# Using a model compatible with Gemini's expected dimensions.
# For high-quality embeddings, a model like "text-embedding-3-large" from OpenAI is good,
# but for open-source, "all-mpnet-base-v2" is a strong baseline with 768 dimensions.
# Google's models are often used via their own APIs. Let's stick to a sentence-transformer.
logging.info("Loading sentence transformer model...")
model = SentenceTransformer("all-mpnet-base-v2")
logging.info("✅ Model loaded.")

# Ensure Chroma collection exists
def ensure_collection():
    logging.info(f"Ensuring collection '{COLLECTION_NAME}' exists...")
    try:
        collection = chroma_client.get_or_create_collection(name=COLLECTION_NAME)
        logging.info(f"✅ Collection '{COLLECTION_NAME}' is ready.")
        return collection
    except Exception as e:
        logging.error(f"❌ Failed to create or get collection: {e}")
        raise

def convert_extension(filename):
    """Convert file extension from .sfdt to .docx while preserving the original name."""
    if not filename or filename == "unnamed.docx":
        return filename
    if filename.endswith(".sfdt"):
        return filename.replace(".sfdt", ".docx")
    return filename

def chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    """
    Split text into overlapping chunks for better semantic search.
    """
    if not text or len(text) <= chunk_size:
        return [text] if text else []
    
    chunks = []
    start = 0
    
    while start < len(text):
        end = start + chunk_size
        
        # If we're not at the end, try to break at a sentence or word boundary
        if end < len(text):
            # Look for sentence boundaries (. ! ?) within the last 200 characters
            sentence_end = text.rfind('.', start, end)
            if sentence_end == -1:
                sentence_end = text.rfind('!', start, end)
            if sentence_end == -1:
                sentence_end = text.rfind('?', start, end)
            
            # If no sentence boundary found, look for word boundary
            if sentence_end == -1 or sentence_end < start + chunk_size // 2:
                word_end = text.rfind(' ', start, end)
                if word_end > start + chunk_size // 2:
                    end = word_end
            else:
                end = sentence_end + 1
        
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        
        # Move start position with overlap
        start = max(start + chunk_size - overlap, end - overlap)
        
        # Avoid infinite loop
        if start >= end:
            start = end
    
    return chunks

def clean_text(text: str) -> str:
    """
    Clean extracted text by removing excessive whitespace and formatting artifacts.
    """
    if not text:
        return ""
    
    # Replace multiple whitespace characters with single space
    text = re.sub(r'\s+', ' ', text)
    
    # Remove excessive newlines but preserve paragraph breaks
    text = re.sub(r'\n\s*\n\s*\n+', '\n\n', text)
    
    # Remove leading/trailing whitespace
    text = text.strip()
    
    return text

# Ingest documents into ChromaDB with proper chunking
def ingest_documents():
    collection = ensure_collection()
    
    # Clear existing data if any
    try:
        existing_count = collection.count()
        if existing_count > 0:
            logging.info(f"Found {existing_count} existing vectors. Clearing collection...")
            chroma_client.delete_collection(name=COLLECTION_NAME)
            collection = chroma_client.create_collection(name=COLLECTION_NAME)
            logging.info("✅ Collection cleared and recreated.")
    except Exception as e:
        logging.warning(f"Could not clear collection: {e}")
    
    docs = list(documents_collection.find({}))
    
    logging.info(f"Found {len(docs)} documents to ingest.")

    total_chunks = 0
    successful_docs = 0

    for doc in docs:
        doc_id = str(doc.get("_id"))
        title = doc.get("title", "Untitled")
        status = doc.get("status", "unknown")
        
        # Better filename handling - use title if filename is missing or generic
        raw_filename = doc.get("filename", "")
        if not raw_filename or raw_filename in ["unnamed.docx", ""]:
            # Use title as filename if available
            if title and title != "Untitled":
                raw_filename = f"{title}.sfdt" if not title.endswith(('.sfdt', '.docx')) else title
            else:
                raw_filename = f"document_{doc_id[:8]}.docx"
        
        filename = convert_extension(raw_filename)
        encoded_content = doc.get("content", "")

        if not encoded_content:
            logging.warning(f"Skipping document with empty content: {filename} (ID: {doc_id})")
            continue

        try:
            # Extract text content with improved logic
            text_content = extract_document_content(encoded_content, filename, doc_id)
            
            if not text_content or len(text_content.strip()) < 10:
                logging.warning(f"Extracted content is too short for: {filename} (ID: {doc_id})")
                # Still create a minimal entry for metadata
                text_content = f"Document: {title}\nFilename: {filename}\nStatus: {status}\nNo readable content could be extracted from this document."

            # Clean the extracted text
            text_content = clean_text(text_content)
            
            # Additional quality check for meaningful content
            if not is_meaningful_text(text_content):
                logging.warning(f"Extracted content appears to be formatting noise for: {filename} (ID: {doc_id})")
                # Create a basic entry with just metadata
                text_content = f"Document: {title}\nFilename: {filename}\nStatus: {status}\nContent could not be extracted or contains only formatting data."
            
            # Final check - if content is still too short after cleaning
            if len(text_content.strip()) < 20:
                logging.warning(f"Final content check - content too short for: {filename} (ID: {doc_id})")
                # Still create a minimal entry for metadata
                text_content = f"Document: {title}\nFilename: {filename}\nStatus: {status}\nMinimal content available - document may need re-processing."
            
            # Chunk the document for better semantic search
            chunks = chunk_text(text_content, chunk_size=800, overlap=150)
            
            logging.info(f"Processing {filename}: {len(text_content)} chars -> {len(chunks)} chunks")

            # Process each chunk
            chunk_ids = []
            chunk_embeddings = []
            chunk_metadatas = []
            chunk_documents = []

            for i, chunk in enumerate(chunks):
                if not chunk.strip():
                    continue
                    
                try:
                    # Generate embedding for this chunk
                    embedding = model.encode(chunk).tolist()
                    
                    # Create unique ID for this chunk
                    chunk_id = f"{doc_id}_chunk_{i}"
                    
                    # Create metadata for this chunk
                    metadata = {
                        "title": title,
                        "status": status,
                        "filename": filename,
                        "mongo_id": doc_id,
                        "chunk_index": i,
                        "total_chunks": len(chunks),
                        "chunk_length": len(chunk)
                    }
                    
                    chunk_ids.append(chunk_id)
                    chunk_embeddings.append(embedding)
                    chunk_metadatas.append(metadata)
                    chunk_documents.append(chunk)  # Store the actual text content
                    
                except Exception as e:
                    logging.error(f"Error processing chunk {i} for {filename}: {e}")
                    continue

            # Add all chunks for this document to ChromaDB in batch
            if chunk_ids:
                try:
                    collection.add(
                        ids=chunk_ids,
                        embeddings=chunk_embeddings,
                        metadatas=chunk_metadatas,
                        documents=chunk_documents  # This is crucial - stores the actual text
                    )
                    
                    total_chunks += len(chunk_ids)
                    successful_docs += 1
                    
                    logging.info(f"✅ Ingested {filename}: {len(chunk_ids)} chunks")
                except Exception as e:
                    logging.error(f"❌ Failed to ingest chunks for {filename}: {e}")
            else:
                logging.warning(f"No valid chunks created for {filename}")

        except Exception as e:
            logging.error(f"Error processing document {filename} (ID: {doc_id}): {e}")
            continue

    # Final summary
    final_count = collection.count()
    logging.info(f"🎉 Ingestion complete!")
    logging.info(f"📊 Documents processed: {successful_docs}/{len(docs)}")
    logging.info(f"📊 Total chunks created: {total_chunks}")
    logging.info(f"📊 Final vector count in ChromaDB: {final_count}")

def extract_document_content(encoded_content: str, filename: str, doc_id: str) -> str:
    """
    Extract text content from various document formats with improved logic.
    """
    if not encoded_content:
        return ""

    try:
        # First determine if the content is likely base64 encoded
        is_likely_base64 = True
        
        # Ensure we have content and it's a string
        if not isinstance(encoded_content, str):
            logging.warning(f"Content for {filename} (ID: {doc_id}) is not a string: {type(encoded_content)}")
            return f"Document {filename} (ID: {doc_id}) - Content is not in string format"
            
        # Check if the content looks like base64 (only contains base64 characters)
        if len(encoded_content) < 100:
            is_likely_base64 = False
            logging.info(f"Content for {filename} (ID: {doc_id}) is too short to be base64, treating as raw text")
        else:
            # Check first 100 characters for base64 pattern
            sample_content = encoded_content[:100]
            base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            if not all(c in base64_chars for c in sample_content):
                is_likely_base64 = False
                logging.info(f"Content for {filename} (ID: {doc_id}) doesn't appear to be base64 encoded, treating as raw text")
        
        if is_likely_base64:
            # Attempt to decode the base64 content with error handling
            try:
                # Normalize the base64 string by removing whitespace and ensuring proper padding
                cleaned_content = ''.join(encoded_content.split())
                # Add padding if needed
                padding_needed = len(cleaned_content) % 4
                if padding_needed:
                    cleaned_content += '=' * (4 - padding_needed)
                
                decoded_content = base64.b64decode(cleaned_content, validate=False)
                logging.info(f"Successfully decoded base64 content for {filename} (ID: {doc_id})")
            except Exception as e:
                logging.warning(f"Base64 decoding failed for {filename} (ID: {doc_id}): {e}")
                # If base64 decoding fails, treat the content as raw text
                decoded_content = encoded_content.encode('utf-8', errors='replace')
                logging.info(f"Treating content as raw text for {filename} (ID: {doc_id})")
        else:
            # Treat as raw text if not likely base64
            decoded_content = encoded_content.encode('utf-8', errors='replace')
        
        # Determine document type and extract content accordingly
        text_content = ""
        
        # Check if it might be a zip file (SFDT)
        try:
            with zipfile.ZipFile(io.BytesIO(decoded_content), 'r') as zip_ref:
                # The actual content is in 'sfdt-content.json' inside the archive
                if 'sfdt-content.json' in zip_ref.namelist():
                    with zip_ref.open('sfdt-content.json') as json_file:
                        sfdt_json = json.load(json_file)
                        # The text is typically found in sections -> blocks -> inlines -> text
                        text_content = extract_sfdt_text(sfdt_json)
                elif len(zip_ref.namelist()) > 0:
                    # Try to extract text from any text files in the zip
                    for file_name in zip_ref.namelist():
                        if file_name.endswith('.txt') or file_name.endswith('.json') or file_name.endswith('.xml'):
                            with zip_ref.open(file_name) as file:
                                text_content += file.read().decode('utf-8', errors='replace') + '\n'
        except zipfile.BadZipFile:
            logging.info(f"Not a zip file for {filename} (ID: {doc_id}), trying other formats")
            # Not a zip file, try to interpret as plain text or JSON
            try:
                # Try to decode as JSON
                decoded_str = decoded_content.decode('utf-8', errors='replace')
                try:
                    json_content = json.loads(decoded_str)
                    if isinstance(json_content, dict):
                        text_content = extract_json_text(json_content)
                    elif isinstance(json_content, list):
                        # Handle arrays of objects
                        for item in json_content:
                            if isinstance(item, dict):
                                text_content += extract_json_text(item) + '\n'
                except json.JSONDecodeError:
                    # Not valid JSON, use the plain text
                    text_content = decoded_str
            except UnicodeDecodeError:
                # Try various encodings if UTF-8 fails
                for encoding in ['latin-1', 'windows-1252', 'ascii']:
                    try:
                        text_content = decoded_content.decode(encoding, errors='replace')
                        break
                    except:
                        continue
        
        return text_content.strip()

    except Exception as e:
        logging.error(f"Error extracting content for {filename} (ID: {doc_id}): {e}")
        return f"Error extracting content: {str(e)}"

def extract_sfdt_text(sfdt_json: dict) -> str:
    """
    Extract meaningful text from SFDT JSON structure, filtering out formatting noise.
    """
    text_parts = []
    
    try:
        # Navigate through the SFDT structure to find actual text content
        for section in sfdt_json.get('sections', []):
            for block in section.get('blocks', []):
                if 'inlines' in block:
                    for inline in block.get('inlines', []):
                        if 'text' in inline:
                            text_content = inline['text']
                            if is_meaningful_text(text_content):
                                text_parts.append(text_content)
                elif 'text' in block:
                    text_content = block['text']
                    if is_meaningful_text(text_content):
                        text_parts.append(text_content)
                        
                # Also check for paragraph-level text
                if 'paragraphFormat' in block:
                    para_format = block['paragraphFormat']
                    if isinstance(para_format, dict) and 'text' in para_format:
                        text_content = para_format['text']
                        if is_meaningful_text(text_content):
                            text_parts.append(text_content)
                            
    except Exception as e:
        logging.warning(f"Error extracting SFDT text: {e}")
    
    # Clean and deduplicate text parts
    clean_parts = []
    seen = set()
    for part in text_parts:
        clean_part = part.strip()
        if clean_part and clean_part not in seen and is_meaningful_text(clean_part):
            seen.add(clean_part)
            clean_parts.append(clean_part)
    
    return ' '.join(clean_parts)

def is_meaningful_text(text: str) -> bool:
    """
    Determine if a text string contains meaningful content rather than formatting data.
    Preserves important numerical data like monetary amounts, percentages, dates, etc.
    """
    if not text or len(text.strip()) < 3:
        return False
    
    text = text.strip()
    
    # Check for important numerical patterns that should be preserved
    important_patterns = [
        # Currency amounts
        r'[\$€£¥₹]\s*[\d,]+\.?\d*',  # Currency symbols with numbers
        r'\d+\.\d+\s*(USD|EUR|GBP|INR|dollars?|euros?|pounds?|rupees?)',  # Numbers with currency words
        
        # Percentages
        r'\d+\.?\d*\s*%',  # Percentage values
        r'\d+\.?\d*\s*percent',  # Percentage in words
        
        # Business dates (contextual dates, not metadata timestamps)
        r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}',  # Date formats
        r'\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}',  # Month names
        r'(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{2,4}',
        r'(due|effective|start|end|expiry|expires?|valid|from|to|until|by)\s+date:?\s*\d+',  # Contextual dates
        
        # Time periods
        r'\d+\s+(days?|weeks?|months?|years?)',  # Time durations
        r'\d+\s+(hours?|minutes?|seconds?)',  # Time units
        
        # Business numbers with context
        r'\d+\.?\d*\s*(million|billion|thousand|k|M|B)',  # Large numbers
        r'\d+\s*(employees?|staff|people)',  # Headcount
        r'\d+\s*(units?|items?|pieces?)',  # Quantities
        
        # Legal/contract references
        r'(section|clause|article|paragraph)\s+\d+',  # Legal references
        r'\d+\.\d+\s+(states?|provides?|specifies?)',  # Numbered clauses with context
        
        # Measurements and rates
        r'\d+\.?\d*\s*(per|/)\s*(hour|day|week|month|year)',  # Rates
        r'\d+\.?\d*\s*(sq\.?\s*ft|square\s*feet|m²|meters?|km|miles?)',  # Measurements
        
        # Financial terms with context
        r'(amount|total|sum|price|cost|fee|rate|value|salary|budget|payment|penalty|interest)\s*:?\s*[\$€£¥₹]?\s*\d+',
        r'[\$€£¥₹]?\s*\d+[\d,]*\.?\d*\s*(amount|total|sum|price|cost|fee|rate|value|salary|budget|payment|penalty|interest)',
        
        # Contract terms with numbers
        r'(net|gross|within|after|before|due in|expires in|valid for)\s+\d+',  # Payment/validity terms
    ]
    
    # If text contains important numerical patterns, keep it
    for pattern in important_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    # Skip obvious formatting/metadata patterns
    formatting_patterns = [
        # Metadata timestamps (not business dates) - enhanced pattern
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$',  # ISO timestamps with optional milliseconds and timezone
        r'^[a-z0-9]{20,}$',  # Long alphanumeric IDs
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',  # UUIDs (case insensitive)
        
        # Pure coordinate/layout numbers (no context)
        r'^[\d\.\-\s]{15,}$',  # Long sequences of just numbers, decimals, spaces, hyphens (15+ chars)
        r'^(True|False)(\s+(True|False))*$',  # Repeated boolean values
        r'^(true|false)(\s+(true|false))*$',  # Repeated boolean values (lowercase)
        
        # Font and style names
        r'^[A-Z][a-z]+\s+(Paragraph|Font|Style)',  # "Default Paragraph Font"
        r'^[A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Z][a-z]+$',  # Three capitalized words
        
        # Color codes and hex values
        r'^#[0-9a-fA-F]{6}$',  # Hex colors
        r'^rgb\(\d+,\s*\d+,\s*\d+\)$',  # RGB colors
        
        # File paths and extensions
        r'\.(css|js|json|xml|sfdt|docx|pdf)$',  # File extensions
        
        # Very short repetitive content
        r'^(.)\1{5,}$',  # Same character repeated 6+ times
        
        # Repetitive word patterns
        r'^(\w+)(\s+\1){4,}$',  # Same word repeated 5+ times
    ]
    
    for pattern in formatting_patterns:
        if re.match(pattern, text, re.IGNORECASE):
            return False
    
    # Count different types of characters
    digits = sum(c.isdigit() for c in text)
    letters = sum(c.isalpha() for c in text)
    alphanumeric_chars = digits + letters
    
    # If text is mostly punctuation/symbols, skip it
    if len(text) > 10 and alphanumeric_chars / len(text) < 0.3:
        return False
    
    # More lenient with numbers if they might be business-relevant
    # Skip only if there are way more numbers than letters AND no important patterns
    if digits > 0 and letters > 0 and digits / letters > 5:
        # But keep if it has contextual words
        contextual_words = ['amount', 'total', 'sum', 'price', 'cost', 'fee', 'rate', 'value', 'number']
        if not any(word in text.lower() for word in contextual_words):
            return False
    
    # Handle standalone numbers - be more selective
    if letters == 0 and digits > 0:
        # Very long numbers (>10 digits) are likely IDs/noise
        if digits > 10:
            return False
        # If it's a year (4 digits), keep it
        if len(text) == 4 and text.isdigit() and 1900 <= int(text) <= 2100:
            return True
        # Medium numbers (4-10 digits) are ambiguous, check if they look like IDs
        if digits >= 4:
            # If it's all zeros or has repetitive patterns, likely noise
            if len(set(text)) <= 2:  # Too few unique digits
                return False
            # Otherwise, it's likely an ID or formatting noise
            return False
        # 1-3 digit numbers are usually meaningful (percentages, days, small amounts, etc.)
        return True
    
    # Must have at least some alphabetic characters for meaningful content
    # But be more lenient if numbers are present (might be financial data)
    if letters < 2 and digits == 0:
        return False
    
    # Check for repetitive patterns (like "True True True True True")
    words = text.split()
    if len(words) > 3:
        unique_words = set(words)
        if len(unique_words) == 1:  # All words are the same
            return False
        if len(unique_words) <= 2 and len(words) >= 5:  # Very limited vocabulary with repetition
            return False
    
    return True

def extract_json_text(json_obj: dict) -> str:
    """
    Extract meaningful text from JSON object, filtering out formatting noise.
    """
    text_parts = []
    
    # High-priority text fields that definitely contain content
    priority_text_fields = [
        'content', 'text', 'body', 'description', 'title', 'name', 'message',
        'summary', 'abstract', 'paragraph', 'sentence', 'word', 'phrase'
    ]
    
    # Secondary text fields that might contain content
    secondary_text_fields = [
        'value', 'label', 'caption', 'header', 'footer', 'note', 'comment'
    ]
    
    # Fields to completely skip (known formatting/metadata)
    skip_fields = [
        'id', 'timestamp', 'created', 'modified', 'updated', 'version',
        'color', 'font', 'size', 'style', 'margin', 'padding', 'width', 'height',
        'left', 'top', 'right', 'bottom', 'x', 'y', 'z', 'position',
        'format', 'type', 'class', 'css', 'html', 'xml', 'json'
    ]
    
    def extract_recursive(obj, depth=0):
        if depth > 8:  # Prevent infinite recursion
            return
            
        try:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    try:
                        # Ensure key is a string for comparison
                        key_str = str(key).lower() if not isinstance(key, str) else key.lower()
                        
                        # Skip known formatting fields
                        if any(skip_field in key_str for skip_field in skip_fields):
                            continue
                        
                        if isinstance(value, str):
                            # Only process if it looks like meaningful text
                            if is_meaningful_text(value):
                                # Prioritize known content fields
                                if any(field in key_str for field in priority_text_fields):
                                    text_parts.append(value.strip())
                                elif any(field in key_str for field in secondary_text_fields):
                                    text_parts.append(value.strip())
                                elif len(value.strip()) > 25:  # Longer strings are more likely to be content
                                    text_parts.append(value.strip())
                                    
                        elif isinstance(value, (dict, list)):
                            extract_recursive(value, depth + 1)
                            
                    except Exception as inner_e:
                        logging.warning(f"Error processing key '{key}': {inner_e}")
                        continue
                        
            elif isinstance(obj, list):
                for item in obj:
                    extract_recursive(item, depth + 1)
                    
        except Exception as e:
            logging.warning(f"Error in recursive extraction at depth {depth}: {e}")
    
    try:
        extract_recursive(json_obj)
        
        # Filter and clean the extracted text parts
        clean_text_parts = []
        for part in text_parts:
            if is_meaningful_text(part):
                clean_text_parts.append(part)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_parts = []
        for part in clean_text_parts:
            if part not in seen:
                seen.add(part)
                unique_parts.append(part)
        
        return '\n'.join(unique_parts) if unique_parts else ""
        
    except Exception as e:
        logging.error(f"Error in extract_json_text: {e}")
        return ""


if __name__ == "__main__":
    ingest_documents()
