#!/usr/bin/env python3
"""
Audit integrity verification and monitoring script.
Runs periodic integrity checks and generates reports.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List

# Add current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from audit_logger import (
    run_integrity_check, apply_retention_policy, get_audit_entries,
    EventType, log_audit, Actor, Target, Outcome, ObjectType,
    ActorType, OutcomeStatus
)
from audit_middleware import AuditContextManager, create_request_meta_from_context

def generate_audit_report(
    start_date: datetime,
    end_date: datetime,
    operator_id: str = "system-auditor"
) -> Dict[str, Any]:
    """Generate comprehensive audit report for a date range"""
    
    with AuditContextManager("generate_audit_report", operator_id) as audit_ctx:
        print(f"📊 Generating audit report from {start_date.date()} to {end_date.date()}")
        
        # Get audit entries for the period
        entries = get_audit_entries(
            start_time=start_date,
            end_time=end_date,
            limit=10000  # Adjust based on your needs
        )
        
        # Analyze the entries
        event_summary = {}
        user_activity = {}
        security_events = []
        failed_operations = []
        
        for entry in entries:
            event_type = entry.get("event_type", "unknown")
            actor = entry.get("actor", {})
            outcome = entry.get("outcome", {})
            
            # Count event types
            event_summary[event_type] = event_summary.get(event_type, 0) + 1
            
            # Track user activity
            user_id = actor.get("user_id")
            if user_id:
                if user_id not in user_activity:
                    user_activity[user_id] = {
                        "email": actor.get("user_email", "unknown"),
                        "event_count": 0,
                        "events": []
                    }
                user_activity[user_id]["event_count"] += 1
                user_activity[user_id]["events"].append(event_type)
            
            # Collect security events
            if event_type.startswith("security.") or event_type.endswith(".failed"):
                security_events.append(entry)
            
            # Collect failed operations
            if outcome.get("status") == "failure":
                failed_operations.append(entry)
        
        report = {
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": {
                "total_events": len(entries),
                "unique_event_types": len(event_summary),
                "active_users": len(user_activity),
                "security_events": len(security_events),
                "failed_operations": len(failed_operations)
            },
            "event_breakdown": event_summary,
            "user_activity": user_activity,
            "security_events": security_events[:50],  # Limit for report size
            "failed_operations": failed_operations[:50],  # Limit for report size
        }
        
        # Log report generation
        request_meta = create_request_meta_from_context(audit_ctx.request_id)
        log_audit(
            event_type=EventType.AUDIT_READ,
            actor=Actor(user_id=operator_id, actor_type=ActorType.SYSTEM),
            target=Target(object_type=ObjectType.COLLECTION, object_id="audit_logs"),
            outcome=Outcome(status=OutcomeStatus.SUCCESS, code="AUDIT_REPORT_GENERATED"),
            details={
                "report_period_days": (end_date - start_date).days,
                "total_events_analyzed": len(entries),
                "report_sections": list(report.keys())
            },
            request_meta=request_meta,
            retention_tag="retention_7y"
        )
        
        return report

def check_security_anomalies(
    hours_back: int = 24,
    operator_id: str = "system-security-monitor"
) -> Dict[str, Any]:
    """Check for security anomalies in recent audit logs"""
    
    with AuditContextManager("security_anomaly_check", operator_id) as audit_ctx:
        print(f"🔍 Checking for security anomalies in last {hours_back} hours")
        
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        
        # Get recent security-related events
        security_events = get_audit_entries(
            event_types=[
                EventType.USER_LOGIN_FAILED,
                EventType.SECURITY_FAILED_LOGIN_ATTEMPT,
                EventType.SECURITY_PRIVILEGE_ESCALATION,
                EventType.SECURITY_UNUSUAL_APPROVAL,
                EventType.SECURITY_RATE_LIMIT_EXCEEDED
            ],
            start_time=start_time,
            limit=1000
        )
        
        anomalies = {
            "multiple_failed_logins": [],
            "privilege_escalations": [],
            "unusual_patterns": []
        }
        
        # Analyze failed login patterns
        failed_login_by_ip = {}
        failed_login_by_email = {}
        
        for event in security_events:
            if event.get("event_type") == EventType.USER_LOGIN_FAILED.value:
                ip = event.get("request_meta", {}).get("ip", "unknown")
                email = event.get("actor", {}).get("user_email", "unknown")
                
                failed_login_by_ip[ip] = failed_login_by_ip.get(ip, 0) + 1
                failed_login_by_email[email] = failed_login_by_email.get(email, 0) + 1
        
        # Flag IPs with multiple failed attempts
        for ip, count in failed_login_by_ip.items():
            if count >= 5:  # Threshold for suspicious activity
                anomalies["multiple_failed_logins"].append({
                    "type": "ip_based",
                    "ip": ip,
                    "failed_attempts": count,
                    "risk_level": "high" if count >= 10 else "medium"
                })
        
        # Flag emails with multiple failed attempts
        for email, count in failed_login_by_email.items():
            if count >= 3:  # Lower threshold for email-based attacks
                anomalies["multiple_failed_logins"].append({
                    "type": "email_based", 
                    "email": email,
                    "failed_attempts": count,
                    "risk_level": "high" if count >= 5 else "medium"
                })
        
        # Collect privilege escalation attempts
        for event in security_events:
            if event.get("event_type") == EventType.SECURITY_PRIVILEGE_ESCALATION.value:
                anomalies["privilege_escalations"].append(event)
        
        result = {
            "check_period_hours": hours_back,
            "total_security_events": len(security_events),
            "anomalies_found": sum(len(v) for v in anomalies.values()),
            "anomalies": anomalies,
            "recommendations": generate_security_recommendations(anomalies)
        }
        
        # Log security check
        request_meta = create_request_meta_from_context(audit_ctx.request_id)
        log_audit(
            event_type=EventType.AUDIT_INTEGRITY_CHECK,
            actor=Actor(user_id=operator_id, actor_type=ActorType.SYSTEM),
            target=Target(object_type=ObjectType.COLLECTION, object_id="audit_logs"),
            outcome=Outcome(
                status=OutcomeStatus.SUCCESS,
                code="SECURITY_ANOMALY_CHECK",
                message=f"Found {result['anomalies_found']} anomalies"
            ),
            details={
                "check_period_hours": hours_back,
                "anomalies_summary": {k: len(v) for k, v in anomalies.items()}
            },
            request_meta=request_meta,
            retention_tag="retention_7y"
        )
        
        return result

def generate_security_recommendations(anomalies: Dict[str, List]) -> List[str]:
    """Generate security recommendations based on detected anomalies"""
    recommendations = []
    
    if anomalies["multiple_failed_logins"]:
        recommendations.append("Implement IP-based rate limiting for login attempts")
        recommendations.append("Consider implementing CAPTCHA after failed attempts")
        recommendations.append("Set up automated alerts for suspicious login patterns")
    
    if anomalies["privilege_escalations"]:
        recommendations.append("Review user permissions and role assignments")
        recommendations.append("Implement additional authorization checks for sensitive operations")
        recommendations.append("Consider multi-factor authentication for administrative actions")
    
    if not recommendations:
        recommendations.append("No immediate security concerns detected")
    
    return recommendations

def main():
    parser = argparse.ArgumentParser(description="Audit integrity and security monitoring")
    parser.add_argument("--action", "-a", 
                       choices=["integrity", "retention", "report", "security"],
                       required=True,
                       help="Action to perform")
    parser.add_argument("--operator", "-o", default="system-auditor",
                       help="ID of the operator performing this action")
    parser.add_argument("--days", "-d", type=int, default=7,
                       help="Number of days for report generation")
    parser.add_argument("--hours", type=int, default=24,
                       help="Number of hours for security check")
    parser.add_argument("--dry-run", action="store_true",
                       help="Dry run mode (for retention policy)")
    parser.add_argument("--output", "-f", 
                       help="Output file for reports (JSON format)")
    
    args = parser.parse_args()
    
    if args.action == "integrity":
        print("🔍 Running audit integrity check...")
        result = run_integrity_check()
        print(f"✅ Integrity check complete: {result}")
        
        if result.get("failed", 0) > 0:
            print(f"⚠️  WARNING: {result['failed']} entries failed integrity check!")
            sys.exit(1)
    
    elif args.action == "retention":
        print(f"📅 Applying retention policy (dry_run={args.dry_run})...")
        result = apply_retention_policy(dry_run=args.dry_run)
        print(f"✅ Retention policy complete: {result}")
    
    elif args.action == "report":
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=args.days)
        
        print(f"📊 Generating audit report for last {args.days} days...")
        report = generate_audit_report(start_date, end_date, args.operator)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"📄 Report saved to {args.output}")
        else:
            print(f"📄 Report summary:")
            print(f"   Total events: {report['summary']['total_events']}")
            print(f"   Active users: {report['summary']['active_users']}")
            print(f"   Security events: {report['summary']['security_events']}")
            print(f"   Failed operations: {report['summary']['failed_operations']}")
    
    elif args.action == "security":
        print(f"🔍 Checking for security anomalies in last {args.hours} hours...")
        result = check_security_anomalies(args.hours, args.operator)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"📄 Security report saved to {args.output}")
        else:
            print(f"🔍 Security check summary:")
            print(f"   Total security events: {result['total_security_events']}")
            print(f"   Anomalies found: {result['anomalies_found']}")
            
            if result['anomalies_found'] > 0:
                print(f"⚠️  Recommendations:")
                for rec in result['recommendations']:
                    print(f"   • {rec}")
            
            if result['anomalies_found'] > 5:
                print(f"🚨 HIGH ALERT: Multiple security anomalies detected!")
                sys.exit(2)

if __name__ == "__main__":
    main()
