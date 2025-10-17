#!/usr/bin/env python3
"""
Audit System Setup and Installation Script
Helps configure and verify the audit logging system.
"""

import os
import sys
import subprocess
import secrets
from pathlib import Path

def check_dependencies():
    """Check if required Python packages are installed"""
    # Map package names to their import names
    required_packages = {
        'pymongo': 'pymongo',
        'python-jose': 'jose',
        'passlib': 'passlib', 
        'pydantic': 'pydantic',
        'fastapi': 'fastapi'
    }
    
    missing_packages = []
    
    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package_name)
    
    if missing_packages:
        print(f"[ERROR] Missing required packages: {', '.join(missing_packages)}")
        print("Install them with:")
        print(f"pip install {' '.join(missing_packages)}")
        return False
    
    print("[SUCCESS] All required packages are installed")
    return True

def setup_environment():
    """Set up environment variables"""
    env_file = Path(".env")
    
    # Generate secure audit key if not exists
    audit_key = secrets.token_hex(32)
    
    env_vars = {
        "AUDIT_SECRET_KEY": audit_key,
        "MONGODB_URL": "mongodb://localhost:27017",
        "AUDIT_COLLECTION_NAME": "audit_logs"
    }
    
    if env_file.exists():
        print("📄 .env file exists, checking for audit variables...")
        with open(env_file, 'r') as f:
            content = f.read()
        
        need_update = False
        for var, value in env_vars.items():
            if var not in content:
                content += f"\n{var}={value}"
                need_update = True
        
        if need_update:
            with open(env_file, 'w') as f:
                f.write(content)
            print("[SUCCESS] Updated .env file with audit system variables")
        else:
            print("[SUCCESS] All audit variables already present in .env")
    else:
        print("📄 Creating .env file...")
        with open(env_file, 'w') as f:
            f.write("# Audit System Configuration\n")
            for var, value in env_vars.items():
                f.write(f"{var}={value}\n")
        print("[SUCCESS] Created .env file with audit system configuration")
    
    print(f"🔐 Generated new AUDIT_SECRET_KEY: {audit_key[:16]}...")
    print("[WARNING]  Keep this key secure and don't share it!")

def test_audit_system():
    """Run audit system tests"""
    print("[TEST] Running audit system tests...")
    
    try:
        result = subprocess.run([
            sys.executable, "test_audit_system.py"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[SUCCESS] All audit system tests passed!")
            return True
        else:
            print("[ERROR] Some tests failed:")
            print(result.stdout)
            print(result.stderr)
            return False
    except Exception as e:
        print(f"[ERROR] Error running tests: {e}")
        return False

def verify_database_connection():
    """Verify MongoDB connection and create indexes"""
    try:
        from audit_logger import audit_collection
        
        # Test connection
        audit_collection.database.command('ping')
        print("[SUCCESS] MongoDB connection successful")
        
        # Create indexes
        audit_collection.create_index("timestamp_utc")
        audit_collection.create_index("event_type")
        audit_collection.create_index("actor.user_id")
        audit_collection.create_index("request_meta.request_id")
        audit_collection.create_index("retention_policy_tag")
        audit_collection.create_index("target.object_id")
        
        print("[SUCCESS] Audit collection indexes created")
        
        return True
    except Exception as e:
        print(f"[ERROR] Database connection failed: {e}")
        print("   Make sure MongoDB is running and MONGODB_URL is correct")
        return False

def create_sample_audit_entry():
    """Create a sample audit entry to test the system"""
    try:
        from audit_logger import log_audit, EventType, Actor, Target, Outcome, ObjectType, ActorType, OutcomeStatus
        from audit_middleware import RequestMeta
        import uuid
        
        request_meta = RequestMeta(
            request_id=str(uuid.uuid4()),
            ip="127.0.0.1",
            user_agent="audit-setup-script"
        )
        
        audit_id = log_audit(
            event_type=EventType.AUDIT_INTEGRITY_CHECK,
            actor=Actor(user_id="setup-script", actor_type=ActorType.SYSTEM),
            target=Target(object_type=ObjectType.COLLECTION, object_id="audit_logs"),
            outcome=Outcome(status=OutcomeStatus.SUCCESS, code="SETUP_TEST"),
            details={"test": "audit_system_setup", "version": "1.0"},
            request_meta=request_meta,
            retention_tag="retention_7y"
        )
        
        print(f"[SUCCESS] Created sample audit entry: {audit_id}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to create sample audit entry: {e}")
        return False

def run_integrity_check():
    """Run initial integrity check"""
    try:
        from audit_logger import run_integrity_check
        
        result = run_integrity_check()
        if result.get("failed", 0) == 0:
            print("[SUCCESS] Audit integrity check passed")
            return True
        else:
            print(f"[ERROR] Integrity check failed: {result}")
            return False
    except Exception as e:
        print(f"[ERROR] Error running integrity check: {e}")
        return False

def main():
    """Main setup function"""
    print("🔧 Audit Logging System Setup")
    print("=" * 40)
    
    success = True
    
    # Check dependencies
    if not check_dependencies():
        success = False
    
    # Setup environment
    setup_environment()
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Verify database connection
    if not verify_database_connection():
        success = False
    
    # Create sample audit entry
    if not create_sample_audit_entry():
        success = False
    
    # Run integrity check
    if not run_integrity_check():
        success = False
    
    # Run tests
    if not test_audit_system():
        success = False
    
    print("\n" + "=" * 40)
    if success:
        print("[SUCCESS] Audit system setup completed successfully!")
        print("\nNext steps:")
        print("1. Review AUDIT_IMPLEMENTATION_GUIDE.md")
        print("2. Configure RBAC in audit_config.py")
        print("3. Set up monitoring and alerting")
        print("4. Schedule integrity checks")
        print("5. Configure retention policies")
    else:
        print("[ERROR] Audit system setup encountered errors")
        print("Please review the errors above and try again")
        sys.exit(1)

if __name__ == "__main__":
    main()
