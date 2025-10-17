"""
CSS Classes used in AI responses for styling:

Risk Level Classes:
- .risk-high { color: #dc3545; } /* Red for high risk */
- .risk-medium { color: #fd7e14; } /* Orange for medium risk */
- .risk-low { color: #28a745; } /* Green for low risk */

Compliance Status Classes:
- .compliant { color: #28a745; } /* Green for compliant */
- .non-compliant { color: #dc3545; } /* Red for non-compliant */

Structural Classes:
- .compliance-report { /* Main container */ }
- .compliance-summary { /* Summary section */ }
- .compliance-table { /* Summary table */ }
- .compliance-summary-table { /* Detailed table */ }
- .clause-item { /* Individual clause container */ }
- .status-indicator { /* Compliance status text */ }
- .risk-level { /* Risk level text */ }
- .recommendation { /* Recommendation text */ }
- .explanation { /* Explanation text */ }
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Dict, Any, AsyncGenerator
import os
import logging
import json
import asyncio
import re
from dotenv import load_dotenv
import chromadb
from google.generativeai import GenerativeModel
import google.generativeai as genai
from embedding_utils import embed_text
import json
import asyncio
from database import (
    get_user_by_email, create_user, create_document,
    get_document_by_id, update_document, get_documents_for_user,
    get_user_by_id, get_clauses
)

# Import audit logging
from audit_logger import log_ai_interaction, log_ai_interaction_session
from audit_middleware import get_current_request_meta, create_request_meta_from_context
from auth import get_current_user

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[logging.StreamHandler()]
)

# Load environment variables
load_dotenv()

# Get environment variables
CHROMA_API_KEY = os.getenv("CHROMA_API_KEY")
CHROMA_TENANT = os.getenv("CHROMA_TENANT")
CHROMA_DATABASE = os.getenv("CHROMA_DATABASE", 'contract_documents')
COLLECTION_NAME = "contract-gemini"  # Use the Gemini collection by default
EMBEDDING_MODEL = "models/embedding-001"

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
REASONING_MODEL = "gemini-2.0-flash"

if not CHROMA_API_KEY or not CHROMA_TENANT:
    raise EnvironmentError("❌ CHROMA_API_KEY and CHROMA_TENANT must be set in the environment variables.")

# Initialize Gemini client
genai.configure(api_key=GEMINI_API_KEY)

# Initialize ChromaDB client
chroma_client = chromadb.CloudClient(
    api_key=CHROMA_API_KEY,
    tenant=CHROMA_TENANT,
    database=CHROMA_DATABASE
)

router = APIRouter()

class ChatQuery(BaseModel):
    query: str
    document_id: str
    filetype: str = "contract"
    top_k: int = 3

class ChatResponse(BaseModel):
    response: str

class ComplianceQuery(BaseModel):
    document_id: str

class ComplianceResponse(BaseModel):
    score: int
    domain: str
    analysis: str
    clause_matches: List[Dict[str, Any]]
    html_content: str = ""

def get_active_collection():
    """
    Check if the collection exists and use it.
    """
    try:
        collections = chroma_client.list_collections()
        collection_names = [collection.name for collection in collections]
        
        if COLLECTION_NAME in collection_names:
            logging.info(f"Using collection: {COLLECTION_NAME}")
            return chroma_client.get_collection(name=COLLECTION_NAME)
        else:
            logging.warning(f"Collection {COLLECTION_NAME} not found! Creating it.")
            return chroma_client.create_collection(name=COLLECTION_NAME)
    except Exception as e:
        logging.error(f"Error checking collections: {e}")
        return chroma_client.get_or_create_collection(name=COLLECTION_NAME)

async def stream_llm_response(query: str, search_results: List[Dict]):
    """Stream the LLM response."""
    try:
        # Format the search results
        formatted_results = []
        for result in search_results:
            # Ensure all required keys are present
            result_dict = {
                'id': result.get('id', 'unknown_id'),
                'score': result.get('score', 0.0),
                'payload': result.get('payload', {})
            }
            
            # Add content if available
            if 'content' in result and result['content']:
                result_dict['content'] = result['content']
                
            formatted_results.append(result_dict)
        
        # Add a debug message at the beginning of the response
        # yield "Starting AI response...\n\n"

        # Get relevant clauses for context
        try:
            all_clauses = get_clauses()
            clauses_context = json.dumps(all_clauses, indent=2) if all_clauses else "No clauses available"
        except Exception as e:
            logging.warning(f"Could not fetch clauses: {e}")
            clauses_context = "No clauses available"

        # Create the system and user prompts
        system_prompt = """
You are an AI assistant specialized in contract analysis. 
Your task is to analyze the data and provide a detailed and structured response.
The data can be from an invoice, contract, purchase order, or any other legal document.

CRITICAL OUTPUT FORMAT REQUIREMENTS:
- Provide your response in clean, well-formatted plain text ONLY
- NO asterisks (*), NO hash symbols (#), NO markdown syntax whatsoever
- Use simple text formatting with proper spacing and line breaks
- Instead of **bold**, just use capital letters or clear headings
- Instead of bullet points with *, use simple dashes (-) or numbers
- Structure your response with clear sections using proper spacing
- Use indentation and line breaks for better visual organization
- Make the response professional and easy to read

EXAMPLES OF CORRECT FORMATTING:
Good: "DOCUMENT SUMMARY:"
Bad: "**Document Summary:**" or "## Document Summary"

Good: "Key aspects include:"
Bad: "**Key aspects include:**"

Good: "- Payment terms"
Bad: "* Payment terms" or "• Payment terms"

Good: "Payment Terms:
- 30% advance upon signing
- 40% upon 50% completion
- 30% upon final delivery"

Bad: "**Payment Terms:**
* 30% advance upon signing
* 40% upon 50% completion
* 30% upon final delivery"

ABSOLUTELY FORBIDDEN CHARACTERS: * # _ ` > [ ] **

Your response should look like a professional business document with clean formatting.

You have access to standard compliance clauses that you can reference when users ask about specific clauses or compliance requirements.
If users ask questions like "which clause covers X" or "what clauses apply to Y", use the provided clauses context to answer.

If no data is provided (empty results array), politely inform the user that no relevant information was found in the document for their query.
Suggest they try rephrasing their question or ask about a different aspect of the document.

If you have any conflict while decision making, don't hesitate to ask for clarification and tell what conflict or problem you are facing.
While answering questions including tables, you must look at the column names and data types of the table, also note that some cells can be empty.
You don't have to include the source of the data in your response. 
Your response shouldn't have to cite them or give any indication of the backend data or database.
As this is a client facing application, you should not include any internal information or any information about the database.
You should not include any information about the database or the data source.
"""

        # Create the user prompt with clauses context
        user_prompt = f"""Based on the following context, answer the user's query.

Document Context:
{json.dumps(formatted_results, indent=2)}

Available Compliance Clauses:
{clauses_context}

User Query: {query}

IMPORTANT: Respond in plain text format only. Do not use any asterisks (*), hash symbols (#), or other markdown formatting. Use simple text with proper spacing and line breaks for readability. Structure your response clearly but without any special formatting characters."""
        
        # Log the user prompt for debugging
        logging.info(f"User prompt: {user_prompt[:200]}...")

        # Initialize the generative model
        model = GenerativeModel(
            model_name=REASONING_MODEL,
            system_instruction=system_prompt
        )

        # Generate content and stream the response
        response_stream = await model.generate_content_async(user_prompt, stream=True)
        
        async for chunk in response_stream:
            if chunk.text:
                # Clean up any markdown formatting that might slip through
                cleaned_text = chunk.text
                
                # Remove markdown formatting - order matters!
                cleaned_text = cleaned_text.replace('**', '')      # Remove bold asterisks
                cleaned_text = cleaned_text.replace('__', '')      # Remove bold underscores
                cleaned_text = cleaned_text.replace('***', '')     # Remove bold+italic
                cleaned_text = cleaned_text.replace('###', '')     # Remove h3 headers
                cleaned_text = cleaned_text.replace('##', '')      # Remove h2 headers
                cleaned_text = cleaned_text.replace('#', '')       # Remove h1 headers
                cleaned_text = cleaned_text.replace('---', '')     # Remove horizontal rules
                cleaned_text = cleaned_text.replace('```', '')     # Remove code blocks
                cleaned_text = cleaned_text.replace('`', '')       # Remove inline code
                cleaned_text = cleaned_text.replace('>', '')       # Remove blockquotes
                
                # Clean up list formatting
                cleaned_text = re.sub(r'^\s*\*\s+', '- ', cleaned_text, flags=re.MULTILINE)  # Convert * bullets to -
                cleaned_text = re.sub(r'^\s*\*\*\s+', '- ', cleaned_text, flags=re.MULTILINE)  # Convert ** bullets to -
                cleaned_text = re.sub(r'^\s*-\s*\*\s+', '- ', cleaned_text, flags=re.MULTILINE)  # Clean up mixed bullets
                
                # Remove any remaining asterisks that are used for emphasis
                cleaned_text = re.sub(r'\*([^*]+)\*', r'\1', cleaned_text)  # Remove single asterisks around words
                cleaned_text = cleaned_text.replace('*', '')       # Remove any remaining asterisks
                cleaned_text = cleaned_text.replace('_', '')       # Remove italic underscores
                
                # Remove link brackets but preserve parentheses content
                cleaned_text = re.sub(r'\[([^\]]+)\]', r'\1', cleaned_text)  # Remove brackets but keep content
                cleaned_text = cleaned_text.replace(']', '')       # Remove any remaining brackets
                cleaned_text = cleaned_text.replace('[', '')       # Remove any remaining brackets
                
                # Clean up excessive whitespace that might result from markdown removal
                cleaned_text = re.sub(r'\n\s*\n\s*\n+', '\n\n', cleaned_text)  # Replace multiple newlines with double newlines
                cleaned_text = re.sub(r' +', ' ', cleaned_text)  # Replace multiple spaces with single space
                cleaned_text = re.sub(r'^\s+', '', cleaned_text, flags=re.MULTILINE)  # Remove leading whitespace from lines
                
                logging.debug(f"Streaming chunk: {cleaned_text[:50]}...")
                yield cleaned_text
    except Exception as e:
        logging.error(f"Error in stream_llm_response: {e}")
        yield "An error occurred while processing your request."

@router.post("/chat", response_class=StreamingResponse)
async def chat_with_document(query: ChatQuery, current_user: dict = Depends(get_current_user)):
    try:
        session_id = current_user.get("session_id")
        
        # Log AI interaction for audit (without query content for privacy)
        if session_id:
            request_meta_dict = {
                "request_id": f"ai_chat_{query.document_id}",
                "session_id": session_id,
                "ip": getattr(get_current_request_meta(), 'ip', None) if get_current_request_meta() else None
            }
            log_ai_interaction_session(
                session_id=session_id,
                user_id=str(current_user["_id"]),
                document_id=query.document_id,
                query_type="chat",
                request_meta=request_meta_dict
            )
        else:
            # Fallback to legacy logging if no session
            request_meta = get_current_request_meta() or create_request_meta_from_context()
            log_ai_interaction(
                user_id=str(current_user["_id"]),
                document_id=query.document_id,
                query_type="chat",
                request_meta=request_meta
            )
        
        # Get the active collection
        collection = get_active_collection()
        
        # Get the document from MongoDB to have full context
        document = get_document_by_id(query.document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")
        
        document_title = document.get("title", "Untitled Document")
        
        # Embed the user's query
        query_embedding = embed_text(query.query)
        
        # Perform a similarity search, filtering by the document ID if possible
        search_results = collection.query(
            query_embeddings=[query_embedding],
            n_results=query.top_k,
            where={"mongo_id": query.document_id}  # Filter by the specific document
        )

        # Format ChromaDB results for AI processing
        formatted_search_results = []
        document_content = ""
        
        if search_results and search_results['ids'] and search_results['ids'][0]:
            # Add document metadata info
            formatted_search_results.append({
                'id': 'document_info',
                'score': 1.0,
                'payload': {
                    'title': document_title,
                    'document_id': query.document_id,
                    'type': 'document_metadata'
                },
                'content': f"Document Title: {document_title}"
            })
            
            # Process each search result chunk
            document_chunks = []
            for i in range(len(search_results['ids'][0])):
                chunk_id = search_results['ids'][0][i]
                chunk_distance = search_results['distances'][0][i] if search_results.get('distances') else 0
                chunk_score = 1 - chunk_distance
                chunk_metadata = search_results['metadatas'][0][i] if search_results.get('metadatas') else {}
                chunk_content = search_results['documents'][0][i] if (
                    search_results.get('documents') and 
                    search_results['documents'][0] and 
                    i < len(search_results['documents'][0]) and
                    search_results['documents'][0][i] is not None
                ) else ""
                
                if chunk_content:
                    formatted_search_results.append({
                        'id': chunk_id,
                        'score': chunk_score,
                        'payload': chunk_metadata,
                        'content': str(chunk_content)
                    })
                    document_chunks.append(str(chunk_content))
                    
            # Combine chunks for context
            if document_chunks:
                document_content = " ".join(document_chunks)
                logging.info(f"Retrieved {len(document_chunks)} chunks with {len(document_content)} characters")
        
        # If no relevant chunks found, try to get broader content
        if not document_content:
            # Try to get any content from this document (without query filtering)
            try:
                all_doc_results = collection.get(
                    where={"mongo_id": query.document_id},
                    limit=5  # Get first 5 chunks to provide some context
                )
                
                if all_doc_results and all_doc_results.get('documents'):
                    fallback_chunks = [str(chunk) for chunk in all_doc_results['documents'] if chunk is not None]
                    if fallback_chunks:
                        document_content = " ".join(fallback_chunks[:3])  # Use first 3 chunks
                        formatted_search_results.append({
                            'id': 'fallback_content',
                            'score': 0.5,
                            'payload': {'type': 'document_content', 'source': 'fallback'},
                            'content': "Here are some excerpts from the document: " + document_content[:1000] + "..."
                        })
                        logging.info(f"Used fallback content retrieval: {len(document_content)} characters")
            except Exception as e:
                logging.warning(f"Fallback content retrieval failed: {e}")
        
        # Final fallback to MongoDB content
        if not document_content:
            content_base64 = document.get("content", "")
            if content_base64:
                formatted_search_results.append({
                    'id': 'document_content_notice',
                    'score': 0.3,
                    'payload': {
                        'message': "The document content is available but may need re-processing for better search results."
                    },
                    'content': "Document content is stored but not currently searchable. Please re-upload or re-process this document for better AI responses."
                })

        # Add debug log before streaming
        logging.info(f"Starting stream response for query: {query.query}")
        logging.info(f"Found {len(formatted_search_results)} relevant chunks")
        
        # Stream the response from the language model
        return StreamingResponse(
            stream_llm_response(query.query, formatted_search_results), 
            media_type="text/plain"
        )
    except Exception as e:
        logging.error(f"Error in chat_with_document: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while processing the chat query.")

@router.post("/stream", response_class=StreamingResponse)
async def stream_chat_with_document(query: ChatQuery):
    """
    Streaming endpoint for AI chat - alias for /chat endpoint to match frontend expectations.
    """
    return await chat_with_document(query)

@router.post("/compliance", response_model=ComplianceResponse)
async def check_compliance(query: ComplianceQuery):
    """
    Endpoint to analyze document compliance against relevant clauses with audit logging.
    """
    try:
        # Log compliance check for audit
        request_meta = get_current_request_meta() or create_request_meta_from_context()
        user_id = "current_user_id"  # This should come from authentication context
        
        log_ai_interaction(
            user_id=user_id,
            document_id=query.document_id,
            query_type="compliance_check",
            request_meta=request_meta
        )
        
        # Get the document from the database - not using await since this is not an async function
        document = get_document_by_id(query.document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        collection = get_active_collection()

        # Get all document chunks from ChromaDB by mongo_id
        results = collection.get(where={"mongo_id": query.document_id})
        
        document_chunks = results.get('documents', [])
        
        # If no chunks in vector db, use content from mongo
        if not document_chunks:
            content = document.get("content", "")
            if not content:
                raise HTTPException(status_code=404, detail="Document content not found.")
            document_chunks = [content]

        # Handle the case where document_chunks is a nested list (like [[chunk1, chunk2, ...]])
        flattened_chunks = []
        for chunk_or_list in document_chunks:
            if isinstance(chunk_or_list, list):
                flattened_chunks.extend(chunk_or_list)
            else:
                flattened_chunks.append(chunk_or_list)
                
        # Filter out None values and convert all items to strings before joining
        valid_chunks = [str(chunk) for chunk in flattened_chunks if chunk is not None]
        
        if not valid_chunks:
            raise HTTPException(status_code=404, detail="No valid content found in document chunks.")
            
        # Combine chunks into a representative sample (first 10k chars)
        document_sample = " ".join(valid_chunks)[:10000]
        
        # Step 1: Determine document domain using Gemini
        domain_prompt = f"""
        You are a Contract document analyzer. Based on the following document excerpt, determine the most likely domain or category of this document.
        Choose from the following domains: Pharmaceutical, Legal, Finance, HR, Technology, Procurement, Sales, Marketing, or Other.
        Please note that every document is Legal but that dosent mean its domain is Legal. Focus on the primary purpose or industry context of the document. If unsure, choose Other.
        Document:
        {document_sample}
        
        Return only the domain name, nothing else.
        """
        
        model = GenerativeModel(REASONING_MODEL)
        domain_response = await model.generate_content_async(domain_prompt)
        predicted_domain = domain_response.text.strip()
        
        # Step 2: Get relevant clauses for the domain
        clauses = get_clauses(predicted_domain)
        
        if not clauses:
            # If no clauses found for the predicted domain, try with a more general approach
            clauses = get_clauses()
            
        # Log the number of clauses found
        logging.info(f"Found {len(clauses)} clauses for domain: {predicted_domain}")
        
        # Step 3: Check compliance against each clause
        clause_matches = []
        total_score = 0
        
        # Skip compliance check if no clauses found
        if not clauses:
            logging.warning("No clauses found for compliance check. Returning empty result.")
            return ComplianceResponse(
                score=0,
                domain=predicted_domain,
                analysis="No compliance clauses found for this document type. Manual review recommended.",
                clause_matches=[],
                html_content=""
            )
        
        for clause in clauses:
            clause_text = clause.get("description", "")
            clause_title = clause.get("title", "")
            
            # Skip clauses with missing data
            if not clause_text or not clause_title:
                logging.warning(f"Skipping clause with missing data: {clause}")
                continue
                
            # Log the clause being processed
            logging.info(f"Processing clause: {clause_title}")
            
            # Check if the clause is present in the document
            compliance_prompt = f"""
            You are a legal compliance checker. Given a document and a clause, determine if the document complies with the clause.
            
            Document excerpt:
            {document_sample}
            
            Clause: {clause_title}
            Clause Description: {clause_text}
            
            Analyze whether the document complies with this clause. Return ONLY a JSON with the following format:
            {{
                "compliant": true/false,
                "confidence": 1-10,
                "risk_level": "High/Medium/Low",
                "explanation": "brief explanation",
                "recommendation": "specific suggestion with exact location/section to change"
            }}
            
            For risk_level: Use "High" for critical non-compliance, "Medium" for moderate issues, "Low" for minor concerns.
            For recommendation: Be specific about what section needs change and how to change it (e.g., "In Section 3.2, change 'may' to 'shall' to make the obligation mandatory").
            
            Return ONLY valid JSON. No markdown formatting, no additional text.
            """
            
            compliance_response = await model.generate_content_async(compliance_prompt)
            
            try:
                # Clean the response text to ensure it's valid JSON
                response_text = compliance_response.text.strip()
                # Remove any markdown code block markers if present
                if response_text.startswith("```json"):
                    response_text = response_text[7:]
                if response_text.endswith("```"):
                    response_text = response_text[:-3]
                response_text = response_text.strip()
                
                compliance_result = json.loads(response_text)
                
                # Calculate score for this clause
                clause_score = compliance_result.get("confidence", 5) * 10
                if compliance_result.get("compliant", False):
                    clause_score = min(100, clause_score)
                else:
                    clause_score = max(0, clause_score - 50)
                
                clause_match = {
                    "title": clause_title,
                    "description": clause_text,
                    "compliant": compliance_result.get("compliant", False),
                    "score": clause_score,
                    "risk_level": compliance_result.get("risk_level", "Medium"),
                    "explanation": compliance_result.get("explanation", ""),
                    "recommendation": compliance_result.get("recommendation", "")
                }
                
                clause_matches.append(clause_match)
                total_score += clause_score
                
            except json.JSONDecodeError as e:
                logging.error(f"JSON decode error for clause '{clause_title}': {e}")
                logging.error(f"Raw response: {compliance_response.text}")
                
                # Handle non-JSON responses
                clause_match = {
                    "title": clause_title,
                    "description": clause_text,
                    "compliant": False,
                    "score": 0,
                    "risk_level": "High",
                    "explanation": "Error analyzing compliance - invalid JSON response",
                    "recommendation": "Manual review required"
                }
                clause_matches.append(clause_match)
        
        # Sort clause matches by risk level (High -> Medium -> Low) and then by compliance status
        risk_priority = {"High": 1, "Medium": 2, "Low": 3}
        clause_matches.sort(key=lambda x: (risk_priority.get(x.get("risk_level", "Medium"), 2), not x.get("compliant", False)))
        
        # Calculate simple compliance score (compliant clauses / total clauses)
        compliant_count = sum(1 for clause in clause_matches if clause.get("compliant", False))
        total_clauses = len(clause_matches)
        simple_score = f"{compliant_count}/{total_clauses}" if total_clauses > 0 else "0/0"
        
        # Step 4: Generate overall analysis
        analysis_prompt = f"""
        You are a legal compliance analyzer. Based on the following compliance checks, provide an overall analysis of the document's compliance.
        
        Document: {document.get('filename', 'N/A')}
        Domain: {predicted_domain}
        Compliance Score: {simple_score}
        
        Compliance Checks (sorted by risk level):
        {json.dumps(clause_matches, indent=2)}
        
        IMPORTANT INSTRUCTIONS:
        1. Start with a brief compliance summary table in HTML format with columns: Clause, Risk Level, Status
        2. After the table, provide a concise analysis highlighting major issues and specific recommendations.
        3. DO NOT USE MARKDOWN FORMATTING. Use HTML tags for structure.
        4. DO NOT USE ANY EMOJIS OR SYMBOLS like checkmarks, X marks, or stars.
        5. Keep the tone formal and professional.
        6. Focus on actionable insights and specific improvements needed.
        7. Use color coding for risk levels: High risk = red text, Medium risk = orange text, Low risk = green text
        8. Use CSS classes for styling: risk-high, risk-medium, risk-low, compliant, non-compliant
        9. Add proper table borders and styling
        10. Each clause in the table should have an id attribute for linking (e.g., id="clause-1")
        
        Format your response as:
        <div class="compliance-summary">
        <h4>Compliance Summary</h4>
        <table class="compliance-table" style="border-collapse: collapse; width: 100%; border: 1px solid #ddd;">
        <thead><tr style="background-color: #000000;"><th style="border: 1px solid #ddd; padding: 8px;">Clause</th><th style="border: 1px solid #ddd; padding: 8px;">Risk Level</th><th style="border: 1px solid #ddd; padding: 8px;">Status</th></tr></thead>
        <tbody>
        [Table rows for each clause with appropriate color classes and id attributes]
        </tbody>
        </table>
        
        <h4>Analysis & Recommendations</h4>
        <p>[Your analysis here with specific recommendations for each clause]</p>
        </div>
        """
        
        analysis_response = await model.generate_content_async(analysis_prompt)
        analysis = analysis_response.text
        
        # Log the analysis for debugging
        logging.info(f"Generated analysis: {analysis[:100]}...")
        
        # Generate HTML content
        html_prompt = f"""
        You are a legal compliance analyzer. Based on the following compliance checks, generate a well-structured HTML content for displaying the compliance analysis.
        
        Document: {document.get('filename', 'N/A')}
        Domain: {predicted_domain}
        Compliance Score: {simple_score}
        
        Compliance Checks (sorted by risk level):
        {json.dumps(clause_matches, indent=2)}
        
        IMPORTANT INSTRUCTIONS:
        1. Generate clean, well-structured HTML for displaying the compliance analysis.
        2. Use appropriate HTML elements like <div>, <h1>, <h2>, <h3>, <p>, <table>, etc.
        3. Include styling classes that can be targeted with CSS.
        4. DO NOT USE EMOJIS. Instead use text like "Compliant" or "Non-compliant".
        5. For compliant/non-compliant indicators, use appropriate HTML elements with class names (e.g., <span class="compliant">Compliant</span>).
        6. Structure the content with sections for overall analysis and individual clause assessments.
        7. Make sure the HTML is valid and properly formatted.
        8. Include a summary table at the top showing clause name, risk level, and status (remove action required column).
        9. Sort clauses by risk level (High to Low).
        10. Use color coding with CSS classes: risk-high (red), risk-medium (orange), risk-low (green)
        11. Use compliance status classes: compliant (green), non-compliant (red)
        12. Add proper table borders with inline styles for immediate visibility
        13. Each clause should have a unique ID (clause-1, clause-2, etc.) for linking from the table
        14. Table rows should link to their corresponding detailed sections using href="#clause-id"
        15. Clearly show AI suggestions and recommendations for each clause
        16. Return ONLY the HTML content, no explanations or additional text.
        
        Use proper table structure with borders, clickable clause names that link to detailed sections, and clear AI recommendations.
        """
        
        html_response = await model.generate_content_async(html_prompt)
        html_content = html_response.text.strip()
        
        # Clean up the HTML content if needed
        if html_content.startswith("```html"):
            html_content = html_content[7:]
        if html_content.endswith("```"):
            html_content = html_content[:-3]
        html_content = html_content.strip()
        
        return ComplianceResponse(
            score=compliant_count if total_clauses > 0 else 0,  # Use simple count of compliant clauses
            domain=predicted_domain,
            analysis=analysis,
            clause_matches=clause_matches,
            html_content=html_content
        )
        
    except Exception as e:
        logging.error(f"Error in compliance endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

async def get_document_content(document_id: str) -> str:
    """
    Helper function to fetch document content by ID.
    """
    # get_document_by_id is not an async function, so no await
    document = get_document_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    # Return content as string or empty string if not found
    return document.get("content", "")

async def stream_clause_analysis(document_content: str, clauses: List[Dict]):
    """
    Stream the clause analysis response from the LLM.
    """
    try:
        # Create the system prompt
        system_prompt = """
You are an AI assistant for legal contract analysis. Your task is to analyze a contract document against a list of standard clauses.
For each clause, determine if the clause is present in the document, and if so, evaluate the compliance of the document with the clause.
Provide a detailed analysis for each clause, including any recommendations for improving compliance.
"""

        # Create the user prompt
        user_prompt = f"Document Content:\n```\n{document_content}\n```\n\nClauses to check:\n{json.dumps(clauses, indent=2)}"

        model = GenerativeModel(
            model_name=REASONING_MODEL,
            system_instruction=system_prompt
        )

        response_stream = await model.generate_content_async(user_prompt, stream=True)
        async for chunk in response_stream:
            if chunk.text:
                yield chunk.text
    except Exception as e:
        logging.error(f"Error in stream_clause_analysis: {e}")
        yield "An error occurred during clause analysis."

@router.post("/analyze_clauses", response_class=StreamingResponse)
async def analyze_clauses(query: ComplianceQuery):
    """
    Endpoint to analyze a document against standard clauses for compliance.
    """
    try:
        document_content = await get_document_content(query.document_id)
        clauses = get_clauses()
        
        if not clauses:
            raise HTTPException(status_code=404, detail="No clauses found to analyze.")
            
        return StreamingResponse(stream_clause_analysis(document_content, clauses), media_type="text/event-stream")
        
    except Exception as e:
        logging.error(f"Error in analyze_clauses: {e}")
        raise HTTPException(status_code=500, detail="An error occurred during clause analysis.")

# New endpoint to get all clauses
@router.get("/clauses")
async def list_clauses():
    """
    Endpoint to retrieve all standard clauses from the database.
    """
    try:
        clauses = get_clauses()
        return clauses
    except Exception as e:
        logging.error(f"Error fetching clauses: {e}")
        raise HTTPException(status_code=500, detail="Could not fetch clauses.")

# New endpoint to add a clause
class Clause(BaseModel):
    text: str
    domain: str

@router.post("/clauses")
async def add_clause(clause: Clause):
    """
    Endpoint to add a new clause to the database.
    """
    try:
        # For simplicity, this example doesn't handle DB operations for adding clauses.
        # In a real app, you would add the clause to your MongoDB.
        logging.info(f"Received new clause: {clause.text} in domain {clause.domain}")
        # Here you would call a database function like:
        # await create_clause(clause.text, clause.domain)
        return {"message": "Clause added successfully (simulation)."}
    except Exception as e:
        logging.error(f"Error adding clause: {e}")
        raise HTTPException(status_code=500, detail="Could not add clause.")

# New endpoint for semantic search within a document
class SearchInDocQuery(BaseModel):
    query: str
    document_id: str
    top_k: int = 5

@router.post("/search_in_document")
async def search_in_document(query: SearchInDocQuery):
    """
    Endpoint to perform a semantic search within a specific document.
    """
    try:
        # Get the active collection
        collection = get_active_collection()
        
        # Embed the query
        query_embedding = embed_text(query.query)
        
        # Perform search
        search_results = collection.query(
            query_embeddings=[query_embedding],
            n_results=query.top_k,
            where={"mongo_id": query.document_id} # Filter by document
        )
        
        # Format results
        formatted_results = []
        if search_results and search_results['ids']:
            for i in range(len(search_results['ids'][0])):
                # Handle case where document might be None
                document_text = ''
                if (search_results.get('documents') and 
                    search_results['documents'][0] and 
                    i < len(search_results['documents'][0]) and
                    search_results['documents'][0][i] is not None):
                    document_text = str(search_results['documents'][0][i])
                    
                formatted_results.append({
                    'id': search_results['ids'][0][i],
                    'score': 1 - search_results['distances'][0][i],
                    'payload': search_results['metadatas'][0][i],
                    'text': document_text
                })

        return formatted_results
    except Exception as e:
        logging.error(f"Error in search_in_document: {e}")
        raise HTTPException(status_code=500, detail="An error occurred during semantic search.")

# Endpoint to suggest edits
class SuggestEditQuery(BaseModel):
    document_id: str
    clause_text: str
    user_feedback: str

@router.post("/suggest_edit", response_class=StreamingResponse)
async def suggest_edit(query: SuggestEditQuery):
    """
    Endpoint to suggest edits to a clause in a document based on user feedback.
    """
    try:
        document_content = await get_document_content(query.document_id)
        
        system_prompt = """
You are an AI assistant that helps users edit legal documents.
Your task is to suggest edits to a clause in a contract document based on user feedback.
Preserve the original meaning and intent of the clause while making it clearer and more compliant.
"""

        user_prompt = f"Document Content:\n```\n{document_content}\n```\n\nClause to modify:\n`{query.clause_text}`\n\nUser's feedback on what to change:\n`{query.user_feedback}`\n\nPlease provide a revised version of the clause."

        model = GenerativeModel(
            model_name=REASONING_MODEL,
            system_instruction=system_prompt
        )
        
        response_stream = await model.generate_content_async(user_prompt, stream=True)
        
        async def stream_wrapper():
            async for chunk in response_stream:
                if chunk.text:
                    yield chunk.text
        
        return StreamingResponse(stream_wrapper(), media_type="text/plain")
    except Exception as e:
        logging.error(f"Error in suggest_edit: {e}")
        raise HTTPException(status_code=500, detail="Failed to suggest edits.")

# Endpoint to summarize the document
class SummarizeQuery(BaseModel):
    document_id: str

@router.post("/summarize", response_class=StreamingResponse)
async def summarize_document(query: SummarizeQuery):
    """
    Endpoint to summarize the key points of a document.
    """
    try:
        document_content = await get_document_content(query.document_id)
        
        system_prompt = "You are an AI assistant that summarizes legal documents. Provide a concise summary of the key points, obligations, and risks in the document."
        user_prompt = f"Please summarize the following document:\n\n```\n{document_content}\n```"
        
        model = GenerativeModel(
            model_name=REASONING_MODEL,
            system_instruction=system_prompt
        )
        
        response_stream = await model.generate_content_async(user_prompt, stream=True)
        
        async def stream_wrapper():
            async for chunk in response_stream:
                if chunk.text:
                    yield chunk.text
                    
        return StreamingResponse(stream_wrapper(), media_type="text/plain")
    except Exception as e:
        logging.error(f"Error in summarize_document: {e}")
        raise HTTPException(status_code=500, detail="Failed to summarize document.")

# Endpoint for risk analysis
class RiskAnalysisQuery(BaseModel):
    document_id: str

@router.post("/risk_analysis", response_class=StreamingResponse)
async def analyze_risk(query: RiskAnalysisQuery):
    """
    Endpoint to analyze a document for potential risks and ambiguities.
    """
    try:
        document_content = await get_document_content(query.document_id)
        
        system_prompt = """
You are an AI specializing in legal risk analysis. Identify potential risks, ambiguities, and unfavorable terms in the following contract.
Provide a detailed analysis of the risks and suggest possible mitigations or improvements.
"""

        user_prompt = f"Analyze the following document for risks:\n\n```\n{document_content}\n```"
        
        model = GenerativeModel(
            model_name=REASONING_MODEL,
            system_instruction=system_prompt
        )
        
        response_stream = await model.generate_content_async(user_prompt, stream=True)
        
        async def stream_wrapper():
            async for chunk in response_stream:
                if chunk.text:
                    yield chunk.text
                    
        return StreamingResponse(stream_wrapper(), media_type="text/plain")
    except Exception as e:
        logging.error(f"Error in analyze_risk: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze risk.")