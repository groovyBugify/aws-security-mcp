"""SecurityHub Service Wrapper for AWS Security MCP.

This wrapper consolidates all SecurityHub operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing SecurityHub functions to reuse them
from aws_security_mcp.tools.securityhub_tools import (
    get_securityhub_findings as _get_securityhub_findings,
    list_failed_security_standards as _list_failed_security_standards,
    get_account_security_score as _get_account_security_score
)

logger = logging.getLogger(__name__)

@register_tool()
async def securityhub_security_operations(operation: str, **params) -> str:
    """SecurityHub Security Operations Hub - Comprehensive security findings and compliance monitoring.
    
    🔍 SECURITY FINDINGS ANALYSIS:
    - get_findings: Get SecurityHub findings with advanced filtering and search capabilities
    
    📊 ACCOUNT SECURITY SCORING:
    - get_account_score: Get overall account security score with severity breakdown
    
    ⚠️ COMPLIANCE MONITORING:
    - list_failed_standards: List failed security standards and controls with detailed analysis
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🔍 Get all critical findings:
    operation="get_findings", severity="CRITICAL", limit=20
    
    📊 Get high severity findings with search:
    operation="get_findings", severity="HIGH", search_term="S3", limit=15
    
    📈 Get account security score:
    operation="get_account_score"
    
    ⚠️ List failed compliance controls:
    operation="list_failed_standards", limit=25
    
    🔍 Search for specific security issues:
    operation="get_findings", search_term="encryption", severity="ALL", limit=30
    
    📊 Get recent critical and high findings:
    operation="get_findings", severity="HIGH", limit=50
    
    Args:
        operation: The SecurityHub operation to perform (see descriptions above)
        
        # Finding parameters:
        limit: Maximum number of findings/items to return (default: 10)
        severity: Severity level filter (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, or ALL)
        search_term: Search term to filter findings by title, description, or resource
        
    Returns:
        JSON formatted response with operation results and SecurityHub security insights
    """
    
    logger.info(f"SecurityHub operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "get_findings":
            limit = params.get("limit", 10)
            severity = params.get("severity", "ALL")
            search_term = params.get("search_term", "")
            
            return await _get_securityhub_findings(
                limit=limit,
                severity=severity,
                search_term=search_term
            )
            
        elif operation == "get_account_score":
            return await _get_account_security_score()
            
        elif operation == "list_failed_standards":
            limit = params.get("limit", 20)
            
            return await _list_failed_security_standards(limit=limit)
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "get_findings", "get_account_score", "list_failed_standards"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "get_findings": "operation='get_findings', severity='CRITICAL', limit=20",
                    "get_account_score": "operation='get_account_score'",
                    "list_failed_standards": "operation='list_failed_standards', limit=25"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in SecurityHub operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing SecurityHub operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_securityhub_operations() -> str:
    """Discover all available SecurityHub operations with detailed usage examples.
    
    This tool provides comprehensive documentation of SecurityHub operations available
    through the securityhub_security_operations tool, including parameter requirements
    and practical usage examples for security findings and compliance monitoring.
    
    Returns:
        Detailed catalog of SecurityHub operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS SecurityHub",
        "description": "Central security findings and compliance dashboard for multi-account AWS environments",
        "wrapper_tool": "securityhub_security_operations",
        "supported_features": {
            "findings": "Aggregated security findings from multiple AWS security services",
            "compliance": "Security standards compliance monitoring (AWS Foundational, CIS, PCI DSS)",
            "scoring": "Account-level security scoring and trending",
            "standards": "Security control status tracking and remediation guidance"
        },
        "operation_categories": {
            "security_findings_analysis": {
                "get_findings": {
                    "description": "Get SecurityHub findings with advanced filtering and search capabilities",
                    "parameters": {
                        "limit": {"type": "int", "default": 10, "description": "Maximum number of findings to return"},
                        "severity": {"type": "str", "default": "ALL", "description": "Severity level filter", "options": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "ALL"]},
                        "search_term": {"type": "str", "description": "Search term to filter findings by title, description, or resource"}
                    },
                    "examples": [
                        "securityhub_security_operations(operation='get_findings')",
                        "securityhub_security_operations(operation='get_findings', severity='CRITICAL', limit=20)",
                        "securityhub_security_operations(operation='get_findings', severity='HIGH', search_term='S3')",
                        "securityhub_security_operations(operation='get_findings', search_term='encryption', limit=30)",
                        "securityhub_security_operations(operation='get_findings', severity='MEDIUM', search_term='IAM')"
                    ]
                }
            },
            "account_security_scoring": {
                "get_account_score": {
                    "description": "Get overall account security score with severity breakdown and standards status",
                    "parameters": {},
                    "examples": [
                        "securityhub_security_operations(operation='get_account_score')"
                    ]
                }
            },
            "compliance_monitoring": {
                "list_failed_standards": {
                    "description": "List failed security standards and controls with detailed analysis and remediation guidance",
                    "parameters": {
                        "limit": {"type": "int", "default": 20, "description": "Maximum number of failed controls to return"}
                    },
                    "examples": [
                        "securityhub_security_operations(operation='list_failed_standards')",
                        "securityhub_security_operations(operation='list_failed_standards', limit=50)"
                    ]
                }
            }
        },
        "securityhub_security_insights": {
            "common_operations": [
                "Get critical findings: operation='get_findings', severity='CRITICAL'",
                "Check account security score: operation='get_account_score'",
                "List compliance failures: operation='list_failed_standards'",
                "Search security issues: operation='get_findings', search_term='encryption'"
            ],
            "security_monitoring_patterns": [
                "Monitor critical and high severity findings daily",
                "Track security score trends over time",
                "Review failed compliance controls regularly",
                "Search for specific security issues (encryption, access, network)",
                "Correlate findings across multiple AWS services",
                "Monitor finding remediation progress",
                "Track compliance with security standards (CIS, AWS Foundational)",
                "Analyze security trends by resource type and region"
            ],
            "severity_levels": {
                "CRITICAL": "Immediate action required - security vulnerabilities that need urgent remediation",
                "HIGH": "High priority issues that should be addressed quickly",
                "MEDIUM": "Moderate security issues that should be remediated in planned cycles",
                "LOW": "Low impact findings that can be addressed during maintenance windows",
                "INFORMATIONAL": "Informational findings for awareness and best practices"
            },
            "supported_standards": [
                "AWS Foundational Security Standard",
                "CIS AWS Foundations Benchmark",
                "PCI DSS (Payment Card Industry Data Security Standard)",
                "AWS Control Tower Detective Guardrails",
                "Custom security standards"
            ],
            "finding_sources": [
                "AWS Config Rules",
                "Amazon GuardDuty",
                "Amazon Inspector",
                "Amazon Macie",
                "AWS Security Hub security checks",
                "Third-party security tools",
                "Custom findings via API"
            ],
            "security_best_practices": [
                "Enable SecurityHub in all regions and accounts",
                "Configure automatic remediation for common findings",
                "Set up SNS notifications for critical findings",
                "Integrate with AWS Systems Manager for patching",
                "Use CloudWatch dashboards for security metrics",
                "Implement finding suppression for accepted risks",
                "Regular review of failed compliance controls",
                "Automate security response with Lambda functions"
            ],
            "compliance_considerations": [
                "Track compliance status across multiple standards",
                "Document remediation efforts for audit purposes",
                "Monitor control status changes over time",
                "Ensure findings are addressed within SLA timeframes",
                "Validate remediation effectiveness",
                "Maintain evidence of security improvements",
                "Regular compliance reporting to stakeholders"
            ],
            "search_capabilities": [
                "Search by resource type (EC2, S3, IAM, etc.)",
                "Search by security control or rule name",
                "Search by finding description or title",
                "Search by AWS account or region",
                "Search by compliance standard",
                "Search by remediation guidance keywords"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 