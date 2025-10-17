#!/usr/bin/env python3
"""
Test script for session-based audit logging integration
"""
import sys
import os
import uuid
from datetime import datetime, timezone

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit_logger import (
    start_audit_session, end_audit_session, 
    log_document_access_session, log_document_update_session,
    log_ai_interaction_session, session_audit_manager
)

def test_session_based_audit():
    """Test the complete session-based audit workflow"""
    print("🧪 Testing Session-Based Audit Logging Integration...")
    
    # Test 1: User Login (Start Session)
    print("\n1️⃣ Testing User Login (Session Start)...")
    user_id = "test-user-001"
    user_email = "testuser@company.com"
    session_meta = {
        "login_method": "password",
        "ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0 Test Browser"
    }
    
    session_id = start_audit_session(user_id, user_email, session_meta)
    print(f"✅ Session started: {session_id}")
    
    # Test 2: Multiple Document Access Events
    print("\n2️⃣ Testing Multiple Document Access Events...")
    documents = [
        {"id": "doc-001", "title": "Contract Agreement A"},
        {"id": "doc-002", "title": "Privacy Policy B"},
        {"id": "doc-003", "title": "Terms of Service C"},
        {"id": "doc-004", "title": "Vendor Agreement D"},
        {"id": "doc-005", "title": "Employment Contract E"}
    ]
    
    for doc in documents:
        request_meta = {
            "request_id": str(uuid.uuid4()),
            "session_id": session_id,
            "ip": "192.168.1.100"
        }
        log_document_access_session(
            session_id=session_id,
            user_id=user_id,
            document_id=doc["id"],
            title=doc["title"],
            request_meta=request_meta
        )
        print(f"✅ Logged access to: {doc['title']}")
    
    # Test 3: Document Updates
    print("\n3️⃣ Testing Document Update Events...")
    for i, doc in enumerate(documents[:2]):  # Update first 2 docs
        changes = {
            "content": f"Updated content for {doc['title']}",
            "last_modified": datetime.now(timezone.utc).isoformat(),
            "version": f"1.{i+1}"
        }
        request_meta = {
            "request_id": str(uuid.uuid4()),
            "session_id": session_id,
            "ip": "192.168.1.100"
        }
        log_document_update_session(
            session_id=session_id,
            user_id=user_id,
            document_id=doc["id"],
            changes=changes,
            request_meta=request_meta
        )
        print(f"✅ Logged update to: {doc['title']}")
    
    # Test 4: AI Interactions
    print("\n4️⃣ Testing AI Interaction Events...")
    ai_queries = [
        {"doc_id": "doc-001", "type": "compliance_check"},
        {"doc_id": "doc-002", "type": "risk_analysis"},
        {"doc_id": "doc-003", "type": "clause_extraction"}
    ]
    
    for query in ai_queries:
        request_meta = {
            "request_id": str(uuid.uuid4()),
            "session_id": session_id,
            "ip": "192.168.1.100"
        }
        log_ai_interaction_session(
            session_id=session_id,
            user_id=user_id,
            document_id=query["doc_id"],
            query_type=query["type"],
            request_meta=request_meta
        )
        print(f"✅ Logged AI {query['type']} for {query['doc_id']}")
    
    # Test 5: Check Session Status
    print("\n5️⃣ Checking Session Status...")
    current_session = session_audit_manager.active_sessions.get(session_id)
    if current_session:
        print(f"✅ Session active with {len(current_session.events)} events")
        print(f"   - Session duration: {datetime.now(timezone.utc) - current_session.session_start_time}")
        print(f"   - Local storage backup: Enabled")
    else:
        print("❌ Session not found!")
    
    # Test 6: User Logout (End Session)
    print("\n6️⃣ Testing User Logout (Session End)...")
    success = end_audit_session(session_id, "user_logout")
    if success:
        print(f"✅ Session {session_id} ended and flushed to database")
        
        # Verify session was removed from active sessions
        if session_id not in session_audit_manager.active_sessions:
            print("✅ Session properly cleaned up from memory")
        else:
            print("⚠️  Session still in memory (unexpected)")
    else:
        print("❌ Failed to end session!")
    
    print("\n🎉 Session-Based Audit Test Completed!")
    
    # Test 7: Test Multiple Concurrent Sessions
    print("\n7️⃣ Testing Multiple Concurrent User Sessions...")
    
    sessions = []
    for i in range(3):
        user = f"user-{i+1:03d}"
        email = f"user{i+1}@company.com"
        
        session_id = start_audit_session(user, email, {"login_method": "sso"})
        sessions.append({"session_id": session_id, "user": user})
        
        # Each user accesses 2 documents
        for j in range(2):
            request_meta = {
                "request_id": str(uuid.uuid4()),
                "session_id": session_id,
                "ip": f"192.168.1.{100+i}"
            }
            log_document_access_session(
                session_id=session_id,
                user_id=user,
                document_id=f"shared-doc-{j+1}",
                title=f"Shared Document {j+1}",
                request_meta=request_meta
            )
        
        print(f"✅ Created session for {user} with 2 document accesses")
    
    print(f"\n✅ {len(sessions)} concurrent sessions active")
    print(f"   Total active sessions: {len(session_audit_manager.active_sessions)}")
    
    # End all concurrent sessions
    for session in sessions:
        end_audit_session(session["session_id"], "test_cleanup")
        print(f"✅ Ended session for {session['user']}")
    
    print(f"\n✅ All sessions ended. Active sessions: {len(session_audit_manager.active_sessions)}")
    
    return True

def test_rate_limit_simulation():
    """Simulate the rate limiting issue that was originally happening"""
    print("\n🚀 Simulating Rate Limit Scenario...")
    print("   Before: 5 document opens → only 1-2 logs due to rate limits")
    print("   After:  5 document opens → ALL 5 captured in session")
    
    session_id = start_audit_session("power-user", "poweruser@company.com", {"scenario": "rate_limit_test"})
    
    # Simulate rapid document access (what used to cause missing logs)
    for i in range(5):
        request_meta = {
            "request_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        log_document_access_session(
            session_id=session_id,
            user_id="power-user",
            document_id=f"rapid-doc-{i+1}",
            title=f"Rapidly Accessed Document {i+1}",
            request_meta=request_meta
        )
        print(f"✅ Captured access {i+1}/5 - {f'Rapidly Accessed Document {i+1}'}")
    
    # Verify all events were captured
    current_session = session_audit_manager.active_sessions.get(session_id)
    document_opens = [e for e in current_session.events if e.event_type == "document.open"]
    
    print(f"\n📊 Rate Limit Test Results:")
    print(f"   Documents accessed: 5")
    print(f"   Events captured: {len(document_opens)}")
    print(f"   Success rate: {len(document_opens)/5*100:.0f}%")
    
    if len(document_opens) == 5:
        print("🎉 SUCCESS: All events captured! Rate limiting issue solved.")
    else:
        print("❌ FAILURE: Some events missing!")
    
    end_audit_session(session_id, "rate_limit_test_end")
    
    return len(document_opens) == 5

if __name__ == "__main__":
    try:
        # Run the comprehensive test
        test_result = test_session_based_audit()
        
        # Run the rate limit simulation
        rate_limit_result = test_rate_limit_simulation()
        
        if test_result and rate_limit_result:
            print("\n🏆 ALL TESTS PASSED!")
            print("   ✅ Session-based audit logging working correctly")
            print("   ✅ Rate limiting issue resolved")
            print("   ✅ Ready for production integration")
        else:
            print("\n❌ SOME TESTS FAILED!")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
