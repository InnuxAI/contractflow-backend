# Audit Logging System Implementation Guide

## Overview

This document provides comprehensive instructions for implementing and maintaining the append-only, tamper-evident audit logging system for the contractflow application.

## Architecture

The audit system consists of several key components:

1. **audit_logger.py** - Core audit logging functionality
2. **audit_middleware.py** - Request middleware for context management
3. **audit_integrity_checker.py** - Integrity verification and monitoring
4. **audit_config.py** - Configuration and RBAC settings
5. **test_audit_system.py** - Comprehensive unit tests

## Implementation Steps

### Phase 1: Core Infrastructure Setup (Days 1-2)

#### Step 1.1: Environment Configuration
```bash
# Add to your .env file
AUDIT_SECRET_KEY=your-256-bit-secret-key-for-hmac-signatures
MONGODB_URL=mongodb://localhost:27017  # Your existing MongoDB
AUDIT_COLLECTION_NAME=audit_logs
```

⚠️ **CRITICAL**: Generate a secure AUDIT_SECRET_KEY:
```python
import secrets
print(secrets.token_hex(32))  # Use this output as your AUDIT_SECRET_KEY
```

#### Step 1.2: Install Dependencies
```bash
pip install pymongo python-jose[cryptography] passlib[bcrypt] pydantic fastapi
```

#### Step 1.3: Database Setup
The audit system will automatically create the required collection and indexes when first used. To manually create indexes:

```python
from audit_logger import audit_collection

# Indexes are created automatically, but you can verify:
audit_collection.create_index("timestamp_utc")
audit_collection.create_index("event_type")
audit_collection.create_index("actor.user_id")
audit_collection.create_index("request_meta.request_id")
```

### Phase 2: Integration with Existing Code (Days 3-4)

#### Step 2.1: Update main.py
The main.py file has been updated to include the audit middleware. Key changes:

```python
# Add middleware BEFORE CORS
app.add_middleware(AuditMiddleware)

# Import audit components
from audit_logger import (
    log_audit, EventType, Actor, Target, Outcome, ObjectType,
    ActorType, OutcomeStatus, log_document_access, log_document_update
)
from audit_middleware import get_current_request_meta, create_request_meta_from_context
```

#### Step 2.2: Update auth.py
Authentication endpoints now include comprehensive audit logging:

- Login success/failure tracking
- Token issuance logging
- Unauthorized access attempts
- Session management

#### Step 2.3: Update Document Endpoints
All document operations now include audit trails:

- Document access (read events)
- Document updates with change tracking
- Status changes and approvals
- Unauthorized access attempts

#### Step 2.4: Update AI Chat Module
AI interactions are logged with privacy protection:

- Query types logged (not content)
- Document associations tracked
- Compliance check activities

### Phase 3: Admin Scripts and Background Jobs (Day 5)

#### Step 3.1: Enhanced Admin Scripts
Update your existing admin scripts:

```python
# Example: Updated clear_collection.py
from audit_middleware import AuditContextManager
from audit_logger import log_admin_operation

def your_admin_function(operator_id="system-admin"):
    with AuditContextManager("your_operation", operator_id) as ctx:
        # Your existing code here
        
        # Log the operation
        log_admin_operation(
            operator_id=operator_id,
            operation="your_operation_name",
            target_info={"details": "operation details"},
            request_meta=create_request_meta_from_context(ctx.request_id)
        )
```

#### Step 3.2: Background Jobs
For any background jobs or cron tasks:

```python
from audit_middleware import AuditContextManager

def background_job():
    with AuditContextManager("background_job", "system-scheduler"):
        # Your background job code
        # Audit logging will work automatically within this context
        pass
```

### Phase 4: Monitoring and Integrity (Day 6)

#### Step 4.1: Set Up Integrity Checks
Add to your cron jobs or scheduler:

```bash
# Daily integrity check
0 2 * * * cd /path/to/contractflow-backend && python audit_integrity_checker.py --action integrity

# Weekly retention policy application (dry run first)
0 3 * * 0 cd /path/to/contractflow-backend && python audit_integrity_checker.py --action retention --dry-run

# Security anomaly checks every 4 hours
0 */4 * * * cd /path/to/contractflow-backend && python audit_integrity_checker.py --action security --hours 4
```

#### Step 4.2: Set Up Alerting
Configure alerts in your monitoring system:

```python
# Example: Check for integrity failures
result = run_integrity_check()
if result.get("failed", 0) > 0:
    send_alert("Audit integrity check failed", result)
```

### Phase 5: RBAC and Access Control (Day 7)

#### Step 5.1: Implement Audit Access Controls
Create endpoint for audit access:

```python
from audit_logger import get_audit_entries, log_audit_read_access

@app.get("/admin/audit")
async def get_audit_logs(
    current_user: dict = Depends(get_current_user),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = 100
):
    # Check permissions
    if current_user["role"] not in ["audit_admin", "compliance_officer"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Apply data filters based on role
    if current_user["role"] == "compliance_officer":
        # Filter out sensitive admin events
        filtered_events = [et for et in EventType if not et.value.startswith("admin.")]
        entries = get_audit_entries(
            event_types=filtered_events,
            start_time=start_date,
            end_time=end_date,
            limit=limit
        )
    else:
        entries = get_audit_entries(
            start_time=start_date,
            end_time=end_date,
            limit=limit
        )
    
    return entries
```

## Testing and Validation

### Running Tests
```bash
# Run all audit system tests
python test_audit_system.py

# Run with verbose output
python test_audit_system.py -v
```

### Manual Testing Checklist

1. **Authentication Events**
   - [ ] Login success creates audit entry
   - [ ] Login failure creates audit entry
   - [ ] Token issuance logged
   - [ ] Unauthorized access attempts logged

2. **Document Operations**
   - [ ] Document access logged
   - [ ] Document updates create change records
   - [ ] Status changes tracked
   - [ ] Unauthorized access attempts blocked and logged

3. **AI Interactions**
   - [ ] Chat queries logged (without content)
   - [ ] Compliance checks tracked
   - [ ] User associations recorded

4. **Admin Operations**
   - [ ] Admin scripts log operations
   - [ ] Operator identification tracked
   - [ ] Background jobs create audit context

5. **System Integrity**
   - [ ] Integrity checks pass
   - [ ] Tampered entries detected
   - [ ] Rate limiting works for non-security events
   - [ ] Security events never rate limited

## Security Considerations

### Data Protection
1. **Sensitive Data Sanitization**
   - Passwords, tokens, and secrets are automatically redacted
   - PII is hashed for privacy protection
   - Document content is not stored (only hashes/diffs)

2. **Encryption at Rest**
   - Configure MongoDB encryption for audit collection
   - Use encrypted storage for backup systems
   - Secure key management for HMAC signatures

3. **Access Controls**
   - Implement role-based access to audit logs
   - Log all audit reads (audit-of-audit)
   - Restrict direct database access

### Network Security
1. **API Security**
   - All audit endpoints require authentication
   - Rate limiting applies to audit reads
   - HTTPS required for all audit-related communications

2. **Database Security**
   - Use connection encryption (TLS/SSL)
   - Implement network segmentation
   - Regular security updates

## Operations and Maintenance

### Daily Operations
```bash
# Check system health
python audit_integrity_checker.py --action integrity

# Generate daily report
python audit_integrity_checker.py --action report --days 1 --output daily_report.json

# Check for security anomalies
python audit_integrity_checker.py --action security --hours 24
```

### Weekly Operations
```bash
# Generate weekly compliance report
python audit_integrity_checker.py --action report --days 7 --output weekly_report.json

# Apply retention policy (dry run first)
python audit_integrity_checker.py --action retention --dry-run

# If dry run looks good, apply for real
python audit_integrity_checker.py --action retention
```

### Monthly Operations
```bash
# Generate monthly audit report
python audit_integrity_checker.py --action report --days 30 --output monthly_report.json

# Review and update retention policies
# Review RBAC settings
# Security audit of audit system
```

## Troubleshooting

### Common Issues

1. **Audit Entries Not Created**
   - Check MONGODB_URL connection
   - Verify AUDIT_SECRET_KEY is set
   - Check application logs for errors
   - Ensure audit_collection has write permissions

2. **Integrity Check Failures**
   - Review recent system changes
   - Check for manual database modifications
   - Verify AUDIT_SECRET_KEY hasn't changed
   - Run detailed integrity report

3. **Performance Issues**
   - Monitor audit collection size
   - Check database indexes
   - Review rate limiting settings
   - Consider async audit processing

4. **Permission Errors**
   - Verify user roles in RBAC configuration
   - Check audit access permissions
   - Review authentication tokens

### Emergency Procedures

1. **Suspected Data Tampering**
   ```bash
   # Run full integrity check
   python audit_integrity_checker.py --action integrity
   
   # Generate security report
   python audit_integrity_checker.py --action security --hours 168  # Last week
   
   # Backup current audit logs
   mongodump --collection audit_logs --db document_review_db
   ```

2. **System Compromise**
   - Immediately enable legal hold on all audit logs
   - Export critical audit data to secure offline storage
   - Review all admin operations in suspicious timeframe
   - Notify security team and compliance officer

## Compliance and Legal

### Data Retention
- Configure retention policies in audit_config.py
- Review legal requirements for your jurisdiction
- Implement legal hold procedures
- Document data residency requirements

### Audit Reports
- Generate regular compliance reports
- Maintain audit trail documentation
- Provide access logs for regulatory requests
- Ensure audit system itself is audited

### Privacy Compliance
- PII is automatically hashed in audit logs
- Implement data subject request procedures
- Document privacy protection measures
- Regular privacy impact assessments

## Monitoring and Alerting

### Key Metrics to Monitor
1. Audit log volume and growth rate
2. Integrity check success rate
3. Failed login attempt patterns
4. Administrative action frequency
5. System performance metrics

### Recommended Alerts
1. **Immediate Alerts**
   - Integrity check failures
   - Privilege escalation attempts
   - Audit system errors

2. **Daily Alerts**
   - Security anomaly summaries
   - Failed operation reports
   - System health status

3. **Weekly Alerts**
   - Compliance report summaries
   - Retention policy status
   - Performance trends

## Future Enhancements

### Planned Features
1. Real-time streaming to SIEM systems
2. Machine learning for anomaly detection
3. Automated incident response
4. Enhanced privacy controls
5. Blockchain-based tamper evidence

### Integration Opportunities
1. SIEM/SOAR platform integration
2. Compliance management systems
3. Data loss prevention (DLP) tools
4. Identity and access management (IAM)
5. Business intelligence dashboards

## Support and Contact

For technical support or questions about the audit system:
- Review this documentation
- Check the test cases for examples
- Consult the configuration file for settings
- Contact the security team for compliance questions

Remember: The audit system is critical infrastructure. Always test changes in a development environment first, and maintain backups of all audit data.
