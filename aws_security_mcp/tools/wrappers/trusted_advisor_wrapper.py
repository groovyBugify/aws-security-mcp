"""Trusted Advisor Service Wrapper for AWS Security MCP.

This wrapper consolidates all Trusted Advisor operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing Trusted Advisor functions to reuse them
from aws_security_mcp.tools.trusted_advisor_tools import (
    get_trusted_advisor_security_checks as _get_trusted_advisor_security_checks,
    list_trusted_advisor_security_recommendations as _list_trusted_advisor_security_recommendations,
    get_trusted_advisor_recommendation_details as _get_trusted_advisor_recommendation_details,
    list_trusted_advisor_affected_resources as _list_trusted_advisor_affected_resources
)

logger = logging.getLogger(__name__)

@register_tool()
async def trusted_advisor_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """Trusted Advisor Security Operations Hub - Comprehensive security recommendations and compliance monitoring.
    
    🔍 SECURITY CHECKS ANALYSIS:
    - get_security_checks: Get all security-related checks and their status
    
    📋 RECOMMENDATION MANAGEMENT:
    - list_security_recommendations: List all security recommendations with risk levels
    - get_recommendation_details: Get detailed recommendation information and remediation steps
    
    🎯 RESOURCE ANALYSIS:
    - list_affected_resources: List specific resources affected by security recommendations
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🔍 Get all security checks:
    operation="get_security_checks"
    
    📋 List security recommendations:
    operation="list_security_recommendations"
    
    🔍 Get recommendation details:
    operation="get_recommendation_details", recommendation_id="recommendation-12345"
    
    🎯 List affected resources:
    operation="list_affected_resources", recommendation_id="recommendation-12345"
    
    Args:
        operation: The Trusted Advisor operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access
        
        # Recommendation parameters:
        recommendation_id: ID of the specific recommendation to retrieve details or affected resources
        
    Returns:
        JSON formatted response with operation results and security insights
    """
    
    logger.info(f"Trusted Advisor operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "get_security_checks":
            result = await _get_trusted_advisor_security_checks(session_context=session_context)
            return json.dumps(result)
            
        elif operation == "list_security_recommendations":
            result = await _list_trusted_advisor_security_recommendations(session_context=session_context)
            return json.dumps(result)
            
        elif operation == "get_recommendation_details":
            recommendation_id = params.get("recommendation_id")
            
            if not recommendation_id:
                return json.dumps({
                    "error": "recommendation_id parameter is required for get_recommendation_details",
                    "usage": "operation='get_recommendation_details', recommendation_id='recommendation-12345'"
                })
            
            result = await _get_trusted_advisor_recommendation_details(recommendation_id, session_context=session_context)
            return json.dumps(result)
            
        elif operation == "list_affected_resources":
            recommendation_id = params.get("recommendation_id")
            
            if not recommendation_id:
                return json.dumps({
                    "error": "recommendation_id parameter is required for list_affected_resources",
                    "usage": "operation='list_affected_resources', recommendation_id='recommendation-12345'"
                })
            
            result = await _list_trusted_advisor_affected_resources(recommendation_id, session_context=session_context)
            return json.dumps(result)
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "get_security_checks", "list_security_recommendations", 
                "get_recommendation_details", "list_affected_resources"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "get_security_checks": "operation='get_security_checks'",
                    "list_security_recommendations": "operation='list_security_recommendations'",
                    "get_recommendation_details": "operation='get_recommendation_details', recommendation_id='recommendation-12345'",
                    "list_affected_resources": "operation='list_affected_resources', recommendation_id='recommendation-12345'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in Trusted Advisor operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing Trusted Advisor operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_trusted_advisor_operations(session_context: Optional[str] = None) -> str:
    """Discover all available Trusted Advisor operations with detailed usage examples.
    
    This tool provides comprehensive documentation of Trusted Advisor operations available
    through the trusted_advisor_security_operations tool, including parameter requirements
    and practical usage examples for security compliance monitoring.
    
    Args:
        session_context: Optional session key for cross-account access
    
    Returns:
        Detailed catalog of Trusted Advisor operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Trusted Advisor",
        "description": "Service providing real-time guidance to help optimize AWS infrastructure, improve security, and reduce costs",
        "wrapper_tool": "trusted_advisor_security_operations",
        "supported_features": {
            "security_checks": "Security and compliance checks based on AWS best practices",
            "recommendations": "Actionable recommendations for improving security posture",
            "resource_analysis": "Detailed analysis of specific resources flagged by recommendations",
            "risk_assessment": "Risk level categorization for prioritizing remediation efforts"
        },
        "operation_categories": {
            "security_checks_analysis": {
                "get_security_checks": {
                    "description": "Get all security-related checks from AWS Trusted Advisor with status and resource counts",
                    "parameters": {},
                    "examples": [
                        "trusted_advisor_security_operations(operation='get_security_checks')"
                    ],
                    "returns": "List of all security checks with status, risk levels, and resource counts"
                }
            },
            "recommendation_management": {
                "list_security_recommendations": {
                    "description": "List all security recommendations with risk levels and affected resource counts",
                    "parameters": {},
                    "examples": [
                        "trusted_advisor_security_operations(operation='list_security_recommendations')"
                    ],
                    "returns": "List of security recommendations with categories and risk assessments"
                },
                "get_recommendation_details": {
                    "description": "Get detailed information about a specific security recommendation including remediation steps",
                    "parameters": {
                        "recommendation_id": {"type": "str", "required": True, "description": "ID of the recommendation to retrieve details for"}
                    },
                    "examples": [
                        "trusted_advisor_security_operations(operation='get_recommendation_details', recommendation_id='AwsSolutions-IAM1')",
                        "trusted_advisor_security_operations(operation='get_recommendation_details', recommendation_id='AwsSolutions-S31')"
                    ],
                    "returns": "Detailed recommendation information with remediation guidance"
                }
            },
            "resource_analysis": {
                "list_affected_resources": {
                    "description": "List specific AWS resources affected by a security recommendation",
                    "parameters": {
                        "recommendation_id": {"type": "str", "required": True, "description": "ID of the recommendation to list affected resources for"}
                    },
                    "examples": [
                        "trusted_advisor_security_operations(operation='list_affected_resources', recommendation_id='AwsSolutions-IAM1')",
                        "trusted_advisor_security_operations(operation='list_affected_resources', recommendation_id='AwsSolutions-EC2-1')"
                    ],
                    "returns": "List of specific resources with metadata and status information"
                }
            }
        },
        "trusted_advisor_security_insights": {
            "common_operations": [
                "Get overview of all security checks: operation='get_security_checks'",
                "List current recommendations: operation='list_security_recommendations'",
                "Get specific recommendation details: operation='get_recommendation_details', recommendation_id='...'",
                "Identify affected resources: operation='list_affected_resources', recommendation_id='...'"
            ],
            "security_monitoring_patterns": [
                "Regular review of security check status and trending",
                "Prioritize high-risk recommendations for immediate attention",
                "Track remediation progress across multiple recommendations",
                "Monitor new recommendations as infrastructure evolves",
                "Correlate Trusted Advisor findings with Security Hub findings",
                "Use recommendation details to understand security implications",
                "Generate compliance reports based on security check results",
                "Automate remediation workflows for common recommendation types"
            ],
            "recommendation_categories": [
                "Security Groups - Specific ports unrestricted",
                "IAM Use - Root account usage and access key rotation",
                "MFA - Multi-factor authentication on root account",
                "EBS Public Snapshots - Publicly accessible snapshots",
                "RDS Security Groups - Database security group access",
                "S3 Bucket Permissions - Open access permissions",
                "CloudTrail Logging - Trail configuration and encryption",
                "ELB Security Groups - Load balancer security configurations"
            ],
            "risk_levels": {
                "error": "Critical security issues requiring immediate attention",
                "warning": "Important security improvements recommended", 
                "ok": "Security check passed with no issues identified"
            },
            "support_tier_requirements": {
                "basic": "Limited checks available with Basic support",
                "developer": "Core security checks available",
                "business": "Full security check suite available",
                "enterprise": "All checks plus API access for automation"
            },
            "integration_capabilities": [
                "AWS Config integration for compliance tracking",
                "Security Hub integration for centralized findings",
                "CloudWatch integration for metrics and alerting",
                "AWS CLI and SDK for programmatic access",
                "Third-party SIEM and security tool integration",
                "Custom dashboard and reporting solutions"
            ],
            "security_best_practices": [
                "Review Trusted Advisor recommendations weekly",
                "Prioritize 'error' status recommendations immediately",
                "Document exceptions and accepted risks appropriately",
                "Automate remediation for recurring recommendation types",
                "Use Trusted Advisor as part of security baseline validation",
                "Correlate findings with other AWS security services",
                "Track mean time to resolution for security recommendations",
                "Implement preventive controls based on common findings",
                "Regular security training based on Trusted Advisor insights",
                "Establish SLAs for different risk level remediations"
            ],
            "compliance_considerations": [
                "Map Trusted Advisor checks to compliance frameworks",
                "Document remediation actions for audit trails",
                "Regular reporting on security posture improvements",
                "Integration with compliance management systems",
                "Evidence collection for security assessments",
                "Trend analysis for continuous improvement programs",
                "Exception management and risk acceptance processes"
            ],
            "automation_opportunities": [
                "Automated remediation for common security findings",
                "Integration with infrastructure as code pipelines",
                "Notification and escalation workflows",
                "Custom dashboards and reporting automation",
                "Correlation with other security tool findings",
                "Preventive controls based on recommendation patterns",
                "Cost optimization tracking alongside security improvements"
            ],
            "common_security_checks": [
                "Security Groups - Unrestricted access (0.0.0.0/0) to specific ports",
                "IAM Access Key Rotation - Keys older than 90 days",
                "MFA on Root Account - Multi-factor authentication status",
                "EBS Public Snapshots - Snapshots with public access",
                "RDS Public Snapshots - Database snapshots with public access", 
                "S3 Bucket Permissions - Buckets with open read/write permissions",
                "ELB Listener Security - Load balancers with insecure listeners",
                "CloudTrail Logging - Missing or misconfigured CloudTrail"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 