# Audit Logging System Configuration
# This file documents the configuration options and RBAC settings

# Environment Variables Required:
# AUDIT_SECRET_KEY - Secret key for HMAC signatures (CRITICAL - keep secure)
# MONGODB_URL - MongoDB connection string
# AUDIT_COLLECTION_NAME - Name of audit collection (default: audit_logs)

# Event Retention Policies
RETENTION_POLICIES = {
    "retention_1y": {
        "days": 365,
        "description": "Standard business records - 1 year retention",
        "applicable_events": [
            "document.create",
            "document.update", 
            "document.open",
            "ai.query.submitted"
        ]
    },
    "retention_3y": {
        "days": 1095,
        "description": "Financial and compliance records - 3 year retention",
        "applicable_events": [
            "document.approve",
            "document.reject",
            "email.sent",
            "report.export"
        ]
    },
    "retention_7y": {
        "days": 2555,
        "description": "Security and authentication records - 7 year retention",
        "applicable_events": [
            "user.login.success",
            "user.login.failed",
            "user.token.issued",
            "user.token.revoked",
            "security.*",
            "admin.*",
            "audit.*"
        ]
    },
    "retention_permanent": {
        "days": None,
        "description": "Critical security events - permanent retention",
        "applicable_events": [
            "security.privilege_escalation",
            "admin.user_delete",
            "audit.integrity_check"
        ]
    }
}

# RBAC Configuration for Audit System
AUDIT_RBAC = {
    "roles": {
        "audit_admin": {
            "description": "Full audit system administration",
            "permissions": [
                "audit.read.all",
                "audit.integrity.check", 
                "audit.retention.manage",
                "audit.export.all"
            ],
            "users": ["audit-admin@company.com"]
        },
        "compliance_officer": {
            "description": "Compliance monitoring and reporting",
            "permissions": [
                "audit.read.filtered",
                "audit.report.generate",
                "audit.export.compliance"
            ],
            "users": ["compliance@company.com"]
        },
        "security_analyst": {
            "description": "Security event monitoring",
            "permissions": [
                "audit.read.security",
                "audit.alert.configure",
                "audit.anomaly.check"
            ],
            "users": ["security@company.com"]
        },
        "system_admin": {
            "description": "System administration with limited audit access",
            "permissions": [
                "audit.read.own",
                "audit.integrity.verify"
            ],
            "users": ["admin@company.com"]
        }
    },
    "data_access_rules": {
        "audit.read.all": {
            "description": "Can read all audit entries without restriction",
            "data_filters": None
        },
        "audit.read.filtered": {
            "description": "Can read audit entries excluding sensitive admin operations",
            "data_filters": {
                "exclude_event_types": [
                    "admin.user_delete",
                    "audit.read",
                    "user.token.*"
                ]
            }
        },
        "audit.read.security": {
            "description": "Can only read security-related events",
            "data_filters": {
                "include_event_types": [
                    "user.login.*",
                    "security.*",
                    "user.token.*"
                ]
            }
        },
        "audit.read.own": {
            "description": "Can only read audit entries for their own actions",
            "data_filters": {
                "user_filter": "self_only"
            }
        }
    }
}

# Security Configuration
SECURITY_CONFIG = {
    "rate_limiting": {
        "enabled": True,
        "max_requests_per_minute": 100,
        "security_events_exempt": True,
        "blocked_action": "log_and_continue"
    },
    "integrity_checking": {
        "enabled": True,
        "check_interval_hours": 24,
        "batch_size": 1000,
        "alert_on_failure": True
    },
    "anomaly_detection": {
        "enabled": True,
        "failed_login_threshold": 5,
        "privilege_escalation_alert": True,
        "unusual_access_patterns": True
    },
    "encryption": {
        "logs_at_rest": True,
        "sensitive_fields": [
            "details.password",
            "details.token",
            "details.api_key",
            "details.secret"
        ],
        "pii_fields": [
            "actor.user_email",
            "details.email",
            "details.phone"
        ]
    }
}

# Monitoring and Alerting
MONITORING_CONFIG = {
    "alerts": {
        "integrity_failures": {
            "enabled": True,
            "threshold": 1,
            "notification_method": "email",
            "recipients": ["security@company.com", "audit-admin@company.com"]
        },
        "failed_login_spikes": {
            "enabled": True,
            "threshold": 10,
            "time_window_minutes": 15,
            "notification_method": "email",
            "recipients": ["security@company.com"]
        },
        "privilege_escalation": {
            "enabled": True,
            "threshold": 1,
            "notification_method": "immediate",
            "recipients": ["security@company.com", "admin@company.com"]
        },
        "audit_system_errors": {
            "enabled": True,
            "threshold": 5,
            "time_window_minutes": 10,
            "notification_method": "email",
            "recipients": ["audit-admin@company.com"]
        }
    },
    "dashboards": {
        "security_overview": {
            "enabled": True,
            "refresh_interval_minutes": 5,
            "widgets": [
                "recent_security_events",
                "failed_login_trends",
                "user_activity_summary",
                "system_health"
            ]
        },
        "compliance_reporting": {
            "enabled": True,
            "refresh_interval_hours": 6,
            "widgets": [
                "document_access_logs",
                "approval_workflows",
                "data_exports",
                "retention_compliance"
            ]
        }
    }
}

# Legal and Compliance Settings
COMPLIANCE_CONFIG = {
    "legal_hold": {
        "enabled": True,
        "automatic_triggers": [
            "litigation_notice",
            "regulatory_investigation",
            "security_incident"
        ],
        "manual_override_required": True,
        "authorized_users": ["legal@company.com", "compliance@company.com"]
    },
    "data_residency": {
        "enforce_location": True,
        "allowed_regions": ["US", "EU"],
        "cross_border_restrictions": True
    },
    "privacy_controls": {
        "auto_redact_pii": True,
        "data_subject_requests": {
            "access_enabled": True,
            "deletion_enabled": False,  # Audit logs generally exempt
            "rectification_enabled": False
        },
        "consent_tracking": False  # Not applicable for audit logs
    }
}

# Performance and Scaling
PERFORMANCE_CONFIG = {
    "database": {
        "connection_pool_size": 20,
        "write_concern": "majority",
        "read_preference": "primary",
        "indexes": [
            "timestamp_utc",
            "event_type", 
            "actor.user_id",
            "request_meta.request_id",
            "retention_policy_tag"
        ]
    },
    "async_processing": {
        "enabled": True,
        "queue_size": 1000,
        "batch_size": 50,
        "flush_interval_seconds": 5
    },
    "archival": {
        "enabled": True,
        "archive_after_days": 2555,  # 7 years default
        "archive_storage": "cold_storage",
        "compression": True
    }
}

# Integration Settings
INTEGRATION_CONFIG = {
    "siem_forwarding": {
        "enabled": False,  # Set to True when SIEM is configured
        "endpoint": "https://your-siem.company.com/api/events",
        "format": "cef",
        "authentication": "api_key",
        "batch_forwarding": True,
        "forward_all_events": False,
        "forward_event_types": [
            "security.*",
            "admin.*",
            "user.login.*"
        ]
    },
    "backup_systems": {
        "enabled": True,
        "backup_interval_hours": 6,
        "backup_retention_days": 90,
        "encryption_required": True,
        "offsite_backup": True
    }
}

# Development and Testing
DEV_CONFIG = {
    "mock_mode": False,  # Set to True for testing
    "sample_data_generation": False,
    "log_level": "INFO",  # DEBUG, INFO, WARNING, ERROR
    "test_users": [
        {
            "user_id": "test-user-1",
            "email": "test1@example.com",
            "role": "reviewer"
        },
        {
            "user_id": "test-user-2", 
            "email": "test2@example.com",
            "role": "approver"
        }
    ]
}
