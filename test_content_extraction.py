#!/usr/bin/env python3
"""
Test script to verify that content extraction properly filters out formatting noise.
"""

import os
import sys
from dotenv import load_dotenv
from pymongo import MongoClient
import json
import re

# Add the current directory to the path so we can import from push_mongo_to_chroma
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from push_mongo_to_chroma import (
    extract_document_content, 
    is_meaningful_text,
    clean_text,
    extract_json_text,
    extract_sfdt_text
)

# Load environment variables
load_dotenv()
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")

# MongoDB Setup
print("Connecting to MongoDB...")
mongo_client = MongoClient(MONGODB_URL)
db = mongo_client["document_review_db"]
documents_collection = db["documents"]

def test_content_extraction():
    """Test content extraction on a sample of documents."""
    
    # Get a small sample of documents
    docs = list(documents_collection.find({}).limit(3))
    
    print(f"Testing content extraction on {len(docs)} documents...\n")
    
    for i, doc in enumerate(docs):
        doc_id = str(doc.get("_id"))
        title = doc.get("title", "Untitled")
        filename = doc.get("filename", "unknown.docx")
        encoded_content = doc.get("content", "")
        
        print(f"{'='*60}")
        print(f"Document {i+1}: {title}")
        print(f"Filename: {filename}")
        print(f"ID: {doc_id}")
        print(f"Content length: {len(encoded_content)} characters")
        print(f"{'='*60}")
        
        if not encoded_content:
            print("❌ No content found")
            continue
            
        try:
            # Extract content
            extracted_content = extract_document_content(encoded_content, filename, doc_id)
            
            print(f"Raw extracted length: {len(extracted_content)} characters")
            
            # Clean the content
            cleaned_content = clean_text(extracted_content)
            print(f"Cleaned content length: {len(cleaned_content)} characters")
            
            # Check if it's meaningful
            is_meaningful = is_meaningful_text(cleaned_content)
            print(f"Is meaningful: {is_meaningful}")
            
            # Show first 200 characters
            if extracted_content:
                print(f"\nFirst 200 characters:")
                print(f"'{extracted_content[:200]}...'")
                
                # Check for formatting noise patterns
                noise_patterns = [
                    (r'[\d\.\-\s]{50,}', "Number sequences"),
                    (r'(True|False\s*){10,}', "Boolean repetition"),
                    (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', "Timestamps"),
                    (r'[a-z0-9]{20,}', "Long IDs"),
                    (r'Default\s+Paragraph\s+Font', "Font formatting"),
                ]
                
                print(f"\nNoise pattern detection:")
                for pattern, name in noise_patterns:
                    matches = re.findall(pattern, extracted_content)
                    if matches:
                        print(f"  ⚠️  {name}: {len(matches)} matches")
                        if len(matches) <= 3:
                            for match in matches:
                                print(f"    '{match[:50]}...'")
                    else:
                        print(f"  ✅ {name}: No matches")
                        
            else:
                print("❌ No content extracted")
                
        except Exception as e:
            print(f"❌ Error extracting content: {e}")
            
        print(f"\n")

def test_meaningful_text_detection():
    """Test the is_meaningful_text function with various inputs."""
    
    print("Testing meaningful text detection...")
    
    test_cases = [
        # Meaningful text
        ("This is a contract between two parties.", True),
        ("The terms and conditions are as follows:", True),
        ("Payment shall be made within 30 days.", True),
        
        # Important numerical data that should be preserved
        ("The total amount is $50,000.", True),
        ("Payment of $25,000 USD is due.", True),
        ("Interest rate of 5.5% per annum.", True),
        ("The contract period is 12 months.", True),
        ("Due date: January 15, 2025.", True),
        ("Service fee: €1,500 per month.", True),
        ("Penalty of 2% for late payment.", True),
        ("Net 30 days payment terms.", True),
        ("Annual salary: $75,000.", True),
        ("Budget allocation: 2.5 million.", True),
        ("Clause 5.2 states that...", True),
        ("Section 3 of the agreement.", True),
        ("Effective date: 01/01/2025.", True),
        ("Rate: $50 per hour.", True),
        ("Office space: 1,200 sq ft.", True),
        ("Team size: 25 employees.", True),
        
        # Formatting noise (should be filtered out)
        ("Default Paragraph Font", False),
        ("2025-04-24T12:32:51.355Z", False),
        ("81.05000305175781 28.75 0.5 0.5 0.5", False),
        ("True True True True True", False),
        ("ge9u99zer6o19yiahw84zm", False),
        ("20000076293945", False),
        ("96.5999984741211 96.5999984741211 224.89999389648438", False),
        ("3478669694 -18 -18 108 -18 108 144 -18 144 180", False),
        
        # Edge cases
        ("A", False),  # Too short
        ("AB", False),  # Too short
        ("ABC", True),  # Minimum length
        ("123", True),  # Short numbers might be meaningful (1-3 digits)
        ("2025", True),  # Years are meaningful
        ("12345", False),  # Medium numbers without context (likely ID)
        ("20000076293945", False),  # Long numbers (likely ID)
        ("", False),  # Empty
        ("   ", False),  # Whitespace
        ("$", False),  # Single symbol
        ("$ 100", True),  # Currency with amount
        ("100%", True),  # Percentage
        ("5.5%", True),  # Decimal percentage
    ]
    
    for text, expected in test_cases:
        result = is_meaningful_text(text)
        status = "✅" if result == expected else "❌"
        print(f"{status} '{text}' -> {result} (expected {expected})")

if __name__ == "__main__":
    print("Content Extraction Test Script")
    print("=" * 50)
    
    test_meaningful_text_detection()
    print("\n" + "=" * 50)
    test_content_extraction()
    
    print("Test completed!")
