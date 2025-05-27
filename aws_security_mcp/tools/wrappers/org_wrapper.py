"""Organizations Service Wrapper for AWS Security MCP.

This wrapper consolidates all AWS Organizations operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing Organizations functions to reuse them
from aws_security_mcp.tools.org_tools import (
    fetch_aws_org as _fetch_aws_org,
    details_aws_account as _details_aws_account,
    fetch_aws_org_controls as _fetch_aws_org_controls,
    fetch_scp_details as _fetch_scp_details
)

logger = logging.getLogger(__name__)

@register_tool()
async def organizations_security_operations(operation: str, **params) -> str:
    """Organizations Security Operations Hub - Comprehensive AWS Organizations security monitoring.
    
    🏢 ORGANIZATION OVERVIEW:
    - fetch_organization: Get complete organization structure and hierarchy
    
    👥 ACCOUNT MANAGEMENT:
    - get_account_details: Get detailed information about specific accounts or all accounts
    
    🛡️ GOVERNANCE & CONTROLS:
    - fetch_org_controls: Get all organization-level security controls (SCPs, policies)
    - get_scp_details: Get detailed Service Control Policy information and targets
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🏢 Get organization overview:
    operation="fetch_organization"
    
    👥 Get all account details:
    operation="get_account_details"
    
    🔍 Get specific account details:
    operation="get_account_details", account_id="123456789012"
    
    📋 Get multiple account details:
    operation="get_account_details", account_ids=["123456789012", "210987654321"]
    
    🛡️ Get organization controls:
    operation="fetch_org_controls"
    
    📜 Get SCP policy details:
    operation="get_scp_details", policy_id="p-1234567890abcdef0"
    
    Args:
        operation: The Organizations operation to perform (see descriptions above)
        
        # Account parameters:
        account_id: Single AWS account ID to fetch details for
        account_ids: List of AWS account IDs to fetch details for
        
        # Policy parameters:
        policy_id: SCP policy ID to fetch detailed information for
        
    Returns:
        JSON formatted response with operation results and Organizations security insights
    """
    
    logger.info(f"Organizations operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "fetch_organization":
            return json.dumps(await _fetch_aws_org())
            
        elif operation == "get_account_details":
            account_id = params.get("account_id")
            account_ids = params.get("account_ids")
            
            return json.dumps(await _details_aws_account(
                account_id=account_id,
                account_ids=account_ids
            ))
            
        elif operation == "fetch_org_controls":
            return json.dumps(await _fetch_aws_org_controls())
            
        elif operation == "get_scp_details":
            policy_id = params.get("policy_id")
            if not policy_id:
                return json.dumps({
                    "error": "policy_id parameter is required for get_scp_details",
                    "usage": "operation='get_scp_details', policy_id='p-1234567890abcdef0'"
                })
            
            return json.dumps(await _fetch_scp_details(policy_id=policy_id))
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "fetch_organization", "get_account_details", 
                "fetch_org_controls", "get_scp_details"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "fetch_organization": "operation='fetch_organization'",
                    "get_account_details": "operation='get_account_details'",
                    "fetch_org_controls": "operation='fetch_org_controls'",
                    "get_scp_details": "operation='get_scp_details', policy_id='p-1234567890abcdef0'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in Organizations operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing Organizations operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_organizations_operations() -> str:
    """Discover all available AWS Organizations operations with detailed usage examples.
    
    This tool provides comprehensive documentation of Organizations operations available
    through the organizations_security_operations tool, including parameter requirements
    and practical usage examples for organization security monitoring and governance.
    
    Returns:
        Detailed catalog of Organizations operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Organizations",
        "description": "Multi-account governance, security controls, and organizational management",
        "wrapper_tool": "organizations_security_operations",
        "supported_features": {
            "organization_structure": "Monitor organizational hierarchy and account relationships",
            "account_management": "Track account details, status, and configurations",
            "governance_controls": "Manage Service Control Policies and organizational policies",
            "compliance_monitoring": "Audit organizational compliance and security posture"
        },
        "operation_categories": {
            "organization_overview": {
                "fetch_organization": {
                    "description": "Get complete organization structure and hierarchy with security details",
                    "parameters": {},
                    "examples": [
                        "organizations_security_operations(operation='fetch_organization')"
                    ],
                    "returns": [
                        "Organization basic information (ID, master account, feature set)",
                        "Complete organizational hierarchy (OUs, accounts, relationships)",
                        "Root and organizational unit structure",
                        "Account distribution and nesting levels"
                    ]
                }
            },
            "account_management": {
                "get_account_details": {
                    "description": "Get detailed information about AWS accounts with effective policies",
                    "parameters": {
                        "account_id": {"type": "str", "description": "Single AWS account ID to fetch details for"},
                        "account_ids": {"type": "list", "description": "List of AWS account IDs to fetch details for"},
                        "note": "If neither parameter is provided, details for all accounts will be fetched"
                    },
                    "examples": [
                        "organizations_security_operations(operation='get_account_details')",
                        "organizations_security_operations(operation='get_account_details', account_id='123456789012')",
                        "organizations_security_operations(operation='get_account_details', account_ids=['123456789012', '210987654321'])"
                    ],
                    "returns": [
                        "Account basic information (ID, name, email, status)",
                        "Account creation date and join method",
                        "Effective policies applied to each account",
                        "Policy inheritance from organizational units",
                        "Account-specific policy attachments"
                    ]
                }
            },
            "governance_controls": {
                "fetch_org_controls": {
                    "description": "Get all organization-level security controls and policies",
                    "parameters": {},
                    "examples": [
                        "organizations_security_operations(operation='fetch_org_controls')"
                    ],
                    "returns": [
                        "Service Control Policies (SCPs) with details",
                        "Tag Policies for resource tagging compliance",
                        "Backup Policies for data protection",
                        "AI Services Opt-out Policies",
                        "Root information with enabled policy types",
                        "Policy status and attachment information"
                    ]
                },
                "get_scp_details": {
                    "description": "Get detailed Service Control Policy information and targets",
                    "parameters": {
                        "policy_id": {"type": "str", "required": True, "description": "SCP policy ID (e.g., 'p-1234567890abcdef0')"}
                    },
                    "examples": [
                        "organizations_security_operations(operation='get_scp_details', policy_id='p-1234567890abcdef0')",
                        "organizations_security_operations(operation='get_scp_details', policy_id='p-exampleabcdef123')"
                    ],
                    "returns": [
                        "Complete policy document and permissions",
                        "Policy metadata (name, description, type)",
                        "All targets where policy is attached (OUs, accounts)",
                        "Target details including names and types",
                        "Policy effect analysis and scope"
                    ]
                }
            }
        },
        "organizations_security_insights": {
            "common_operations": [
                "Get organization overview: operation='fetch_organization'",
                "Audit all accounts: operation='get_account_details'",
                "Review governance controls: operation='fetch_org_controls'",
                "Analyze specific SCP: operation='get_scp_details', policy_id='p-xxx'"
            ],
            "security_monitoring_patterns": [
                "Regular audit of organizational structure and account relationships",
                "Monitor Service Control Policy effectiveness and coverage",
                "Track account creation and status changes",
                "Review policy inheritance and effective permissions",
                "Validate compliance with organizational governance standards",
                "Monitor for unauthorized account creation or changes"
            ],
            "governance_best_practices": [
                "Implement least-privilege SCPs for account restrictions",
                "Use organizational units for logical grouping and policy application",
                "Regularly review and audit effective policies on accounts",
                "Implement tag policies for consistent resource tagging",
                "Enable all available policy types for comprehensive governance",
                "Monitor master account permissions and access",
                "Implement backup policies for data protection compliance",
                "Use preventive controls through SCPs rather than detective controls"
            ],
            "compliance_considerations": [
                "Ensure SCPs align with regulatory requirements",
                "Document policy inheritance and effective permissions",
                "Audit account access and administrative permissions",
                "Monitor for compliance with internal governance policies",
                "Track organizational changes for audit trails",
                "Validate account isolation and segregation",
                "Ensure proper data residency through organizational controls"
            ],
            "security_analysis_areas": [
                "Service Control Policy coverage and gaps",
                "Account privilege escalation paths",
                "Cross-account access patterns and risks",
                "Organizational unit structure security",
                "Master account security posture",
                "Policy conflict detection and resolution",
                "Account creation and lifecycle management"
            ],
            "cost_and_operational_efficiency": [
                "Monitor account usage and optimization opportunities",
                "Track organizational unit efficiency",
                "Analyze policy management overhead",
                "Review consolidated billing and cost allocation",
                "Identify unused or dormant accounts"
            ]
        },
        "integration_patterns": {
            "with_other_services": [
                "Combine with IAM analysis for complete permissions audit",
                "Integrate with CloudTrail for organizational activity monitoring",
                "Use with Config for compliance rule evaluation",
                "Combine with SecurityHub for centralized security findings"
            ],
            "automation_opportunities": [
                "Automated SCP compliance checking",
                "Account provisioning and governance automation",
                "Policy drift detection and remediation",
                "Organizational structure validation"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 