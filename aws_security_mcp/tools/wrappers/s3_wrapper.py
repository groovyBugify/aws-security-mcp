"""S3 Service Wrapper for AWS Security MCP.

This wrapper consolidates all AWS S3 operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing S3 functions to reuse them
from aws_security_mcp.tools.s3_tools import (
    list_s3_buckets as _list_s3_buckets,
    get_s3_bucket_details as _get_s3_bucket_details,
    analyze_s3_bucket_security as _analyze_s3_bucket_security,
    find_public_buckets as _find_public_buckets
)

logger = logging.getLogger(__name__)

@register_tool()
async def s3_security_operations(operation: str, **params) -> str:
    """S3 Security Operations Hub - Comprehensive AWS S3 storage security monitoring.
    
    🪣 BUCKET MANAGEMENT:
    - list_buckets: List all S3 buckets with basic information and security details
    - get_bucket_details: Get comprehensive details about a specific bucket
    
    🔒 SECURITY ANALYSIS:
    - analyze_bucket_security: Analyze security configuration of a specific bucket
    - find_public_buckets: Find all public buckets and assess account-level exposure
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🪣 List all buckets:
    operation="list_buckets"
    
    🔍 Get bucket details:
    operation="get_bucket_details", bucket_name="my-bucket"
    
    🔒 Analyze bucket security:
    operation="analyze_bucket_security", bucket_name="my-bucket"
    
    🌐 Find public buckets:
    operation="find_public_buckets"
    
    Args:
        operation: The S3 operation to perform (see descriptions above)
        
        # Bucket parameters:
        bucket_name: S3 bucket name (required for bucket-specific operations)
        
    Returns:
        JSON formatted response with operation results and S3 security insights
    """
    
    logger.info(f"S3 operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_buckets":
            return json.dumps(await _list_s3_buckets())
            
        elif operation == "get_bucket_details":
            bucket_name = params.get("bucket_name")
            if not bucket_name:
                return json.dumps({
                    "error": "bucket_name parameter is required for get_bucket_details",
                    "usage": "operation='get_bucket_details', bucket_name='my-bucket'"
                })
            
            return json.dumps(await _get_s3_bucket_details(bucket_name=bucket_name))
            
        elif operation == "analyze_bucket_security":
            bucket_name = params.get("bucket_name")
            if not bucket_name:
                return json.dumps({
                    "error": "bucket_name parameter is required for analyze_bucket_security",
                    "usage": "operation='analyze_bucket_security', bucket_name='my-bucket'"
                })
            
            return json.dumps(await _analyze_s3_bucket_security(bucket_name=bucket_name))
            
        elif operation == "find_public_buckets":
            return json.dumps(await _find_public_buckets())
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_buckets", "get_bucket_details", 
                "analyze_bucket_security", "find_public_buckets"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_buckets": "operation='list_buckets'",
                    "get_bucket_details": "operation='get_bucket_details', bucket_name='my-bucket'",
                    "analyze_bucket_security": "operation='analyze_bucket_security', bucket_name='my-bucket'",
                    "find_public_buckets": "operation='find_public_buckets'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in S3 operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing S3 operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_s3_operations() -> str:
    """Discover all available AWS S3 operations with detailed usage examples.
    
    This tool provides comprehensive documentation of S3 operations available
    through the s3_security_operations tool, including parameter requirements
    and practical usage examples for S3 storage security monitoring and compliance.
    
    Returns:
        Detailed catalog of S3 operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS S3 (Simple Storage Service)",
        "description": "Object storage security monitoring, bucket configuration analysis, and data protection",
        "wrapper_tool": "s3_security_operations",
        "supported_features": {
            "bucket_management": "Monitor and analyze S3 bucket configurations and policies",
            "security_analysis": "Comprehensive security assessment of bucket configurations",
            "public_exposure": "Detect and analyze public bucket exposure risks",
            "compliance_monitoring": "Audit bucket configurations for compliance requirements"
        },
        "operation_categories": {
            "bucket_management": {
                "list_buckets": {
                    "description": "List all S3 buckets with basic information and security overview",
                    "parameters": {},
                    "examples": [
                        "s3_security_operations(operation='list_buckets')"
                    ],
                    "returns": [
                        "Complete list of all S3 buckets in the account",
                        "Basic bucket metadata (name, creation date, region)",
                        "Bucket count and summary statistics",
                        "Initial security posture indicators"
                    ]
                },
                "get_bucket_details": {
                    "description": "Get comprehensive details about a specific S3 bucket",
                    "parameters": {
                        "bucket_name": {"type": "str", "required": True, "description": "S3 bucket name"}
                    },
                    "examples": [
                        "s3_security_operations(operation='get_bucket_details', bucket_name='my-bucket')",
                        "s3_security_operations(operation='get_bucket_details', bucket_name='company-data-bucket')"
                    ],
                    "returns": [
                        "Detailed bucket configuration and settings",
                        "Bucket policy and ACL configurations",
                        "Versioning, encryption, and lifecycle settings",
                        "Public access block configuration",
                        "Logging and monitoring configurations",
                        "Cross-region replication settings"
                    ]
                }
            },
            "security_analysis": {
                "analyze_bucket_security": {
                    "description": "Analyze the security configuration of a specific S3 bucket",
                    "parameters": {
                        "bucket_name": {"type": "str", "required": True, "description": "S3 bucket name to analyze"}
                    },
                    "examples": [
                        "s3_security_operations(operation='analyze_bucket_security', bucket_name='my-bucket')",
                        "s3_security_operations(operation='analyze_bucket_security', bucket_name='sensitive-data-bucket')"
                    ],
                    "returns": [
                        "Comprehensive security assessment and rating",
                        "Public exposure analysis (ACL and policy-based)",
                        "Public access block effectiveness",
                        "Account-level public access block impact",
                        "Security recommendations and risk factors",
                        "Compliance status indicators"
                    ]
                },
                "find_public_buckets": {
                    "description": "Find all public S3 buckets and assess account-level exposure",
                    "parameters": {},
                    "examples": [
                        "s3_security_operations(operation='find_public_buckets')"
                    ],
                    "returns": [
                        "Complete assessment of public bucket exposure",
                        "List of all public buckets with exposure details",
                        "Summary statistics (total vs public buckets)",
                        "Account-level public access block status",
                        "Risk assessment and exposure percentage",
                        "Recommendations for securing public buckets"
                    ]
                }
            }
        },
        "s3_security_insights": {
            "common_operations": [
                "List all buckets: operation='list_buckets'",
                "Analyze bucket security: operation='analyze_bucket_security', bucket_name='my-bucket'",
                "Find public exposure: operation='find_public_buckets'",
                "Get bucket details: operation='get_bucket_details', bucket_name='my-bucket'"
            ],
            "security_monitoring_patterns": [
                "Regular audit of all bucket configurations and policies",
                "Monitor for public bucket exposure and unauthorized access",
                "Track encryption status and data protection measures",
                "Review access logging and monitoring configurations",
                "Validate bucket policy effectiveness and least privilege",
                "Monitor for policy changes and configuration drift"
            ],
            "data_protection_best_practices": [
                "Enable server-side encryption for all buckets (SSE-S3, SSE-KMS, or SSE-C)",
                "Implement bucket versioning for data protection and recovery",
                "Configure public access block at account and bucket levels",
                "Use bucket policies with least privilege principles",
                "Enable access logging for audit and compliance",
                "Implement lifecycle policies for cost optimization",
                "Configure cross-region replication for disaster recovery",
                "Use MFA delete for sensitive buckets"
            ],
            "compliance_considerations": [
                "Ensure encryption meets regulatory requirements (FIPS, GDPR, HIPAA)",
                "Implement proper access controls and audit logging",
                "Validate data residency and cross-region replication settings",
                "Monitor for compliance with corporate data governance policies",
                "Ensure proper retention and deletion policies",
                "Implement appropriate access monitoring and alerting",
                "Validate backup and disaster recovery configurations"
            ],
            "security_analysis_areas": [
                "Public exposure assessment (bucket policies, ACLs, public access blocks)",
                "Encryption configuration and key management",
                "Access control effectiveness (IAM, bucket policies, ACLs)",
                "Network access controls (VPC endpoints, IP restrictions)",
                "Logging and monitoring coverage (CloudTrail, access logs)",
                "Data lifecycle and retention policy compliance",
                "Cross-account access patterns and risks"
            ],
            "cost_and_performance": [
                "Monitor storage classes and lifecycle transitions",
                "Analyze access patterns for storage optimization",
                "Review data transfer costs and optimization opportunities",
                "Identify unused or rarely accessed buckets",
                "Optimize multipart upload configurations",
                "Monitor request patterns and optimize for performance"
            ]
        },
        "integration_patterns": {
            "with_other_services": [
                "Combine with IAM analysis for complete access assessment",
                "Integrate with CloudTrail for bucket access monitoring",
                "Use with Config for compliance rule evaluation",
                "Combine with SecurityHub for centralized security findings",
                "Integrate with GuardDuty for threat detection",
                "Use with KMS for encryption key management analysis"
            ],
            "automation_opportunities": [
                "Automated public bucket detection and remediation",
                "Encryption enforcement and compliance checking",
                "Lifecycle policy optimization and management",
                "Access pattern analysis and storage class optimization",
                "Security configuration drift detection and correction"
            ]
        },
        "data_security_categories": {
            "encryption_analysis": [
                "Server-side encryption configuration (SSE-S3, SSE-KMS, SSE-C)",
                "Client-side encryption implementation",
                "Key management and rotation policies",
                "Encryption in transit (HTTPS/TLS) enforcement"
            ],
            "access_control_assessment": [
                "Bucket policy analysis and effectiveness",
                "ACL configuration and public access risks",
                "IAM role and user access patterns",
                "Cross-account access and federation"
            ],
            "data_protection_measures": [
                "Versioning configuration and MFA delete",
                "Backup and cross-region replication",
                "Object lock and retention policies",
                "Lifecycle management and archival"
            ],
            "monitoring_and_logging": [
                "Access logging configuration and analysis",
                "CloudTrail integration and API monitoring",
                "Event notifications and alerting",
                "Metrics and performance monitoring"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 