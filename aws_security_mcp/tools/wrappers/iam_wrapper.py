"""IAM Service Wrapper for AWS Security MCP.

This wrapper consolidates all IAM operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing IAM functions to reuse them
from aws_security_mcp.tools.iam_tools import (
    find_iam_role as _find_iam_role,
    find_iam_user as _find_iam_user,
    list_iam_roles as _list_iam_roles,
    list_iam_users as _list_iam_users,
    find_access_key as _find_access_key,
    get_iam_policy_details as _get_iam_policy_details,
    get_iam_policy_batch as _get_iam_policy_batch
)

logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects."""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def safe_json_dumps(data: Any, **kwargs) -> str:
    """Safely serialize data to JSON, handling datetime objects."""
    return json.dumps(data, cls=DateTimeEncoder, **kwargs)

@register_tool()
async def iam_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """IAM Security Operations Hub - Comprehensive identity and access management security monitoring.
    
    👤 USER MANAGEMENT:
    - find_user: Find and get detailed information about a specific IAM user
    - list_users: List IAM users with optional filtering and pagination
    
    🛡️ ROLE MANAGEMENT:
    - find_role: Find and get detailed information about a specific IAM role
    - list_roles: List IAM roles with optional filtering and pagination
    
    🔑 ACCESS KEY MANAGEMENT:
    - find_access_key: Find details about an IAM access key including associated user
    
    📋 POLICY MANAGEMENT:
    - get_policy_details: Get detailed information about a specific IAM policy
    - get_policy_batch: Get details about multiple IAM policies in batch
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    👤 Find specific user in current account:
    operation="find_user", user_name="john.doe"
    
    🏢 Find specific user in another account:
    operation="find_user", user_name="john.doe", session_context="123456789012_aws_dev"
    
    👤 List all users (names only):
    operation="list_users", names_only=True
    
    👤 List users with pagination:
    operation="list_users", max_items=50, path_prefix="/developers/"
    
    🛡️ Find specific role:
    operation="find_role", role_name="EC2InstanceRole"
    
    🛡️ List all roles (names only):
    operation="list_roles", names_only=True
    
    🛡️ List roles with filtering:
    operation="list_roles", max_items=100, path_prefix="/service-roles/"
    
    🔑 Find access key details:
    operation="find_access_key", access_key_id="AKIAIOSFODNN7EXAMPLE"
    
    📋 Get policy details:
    operation="get_policy_details", policy_arn="arn:aws:iam::123456789012:policy/MyPolicy"
    
    📋 Get policy with versions:
    operation="get_policy_details", policy_arn="arn:aws:iam::aws:policy/PowerUserAccess", include_versions=True
    
    📋 Get multiple policies:
    operation="get_policy_batch", policy_arns=["arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/PowerUserAccess"]
    
    Args:
        operation: The IAM operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
                        Use list_available_sessions() to discover available session keys
        
        # User/Role parameters:
        user_name: IAM user name (required for user operations)
        role_name: IAM role name (required for role operations)
        
        # Listing parameters:
        max_items: Maximum number of items to return for list operations
        marker: Pagination token for subsequent requests
        path_prefix: Filter items by path prefix
        names_only: If True, returns only names (faster for large lists)
        
        # Access key parameters:
        access_key_id: The access key ID to search for
        
        # Policy parameters:
        policy_arn: The ARN of the policy to retrieve
        policy_arns: List of policy ARNs for batch operations
        include_versions: Whether to include all policy versions
        
        # Formatting parameters:
        format_response: Whether to format the response for security analysis (default: True)
        
    Returns:
        JSON formatted response with operation results and IAM security insights
    """
    
    logger.info(f"IAM operation requested: {operation}" + (f" with session_context: {session_context}" if session_context else ""))
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "find_user":
            user_name = params.get("user_name")
            if not user_name:
                return safe_json_dumps({
                    "error": "user_name parameter is required for find_user",
                    "usage": "operation='find_user', user_name='john.doe'"
                })
            
            format_response = params.get("format_response", True)
            return safe_json_dumps(await _find_iam_user(
                user_name=user_name,
                format_response=format_response,
                session_context=session_context
            ))
            
        elif operation == "list_users":
            max_items = params.get("max_items")
            marker = params.get("marker")
            path_prefix = params.get("path_prefix")
            format_response = params.get("format_response", True)
            names_only = params.get("names_only", False)
            
            return safe_json_dumps(await _list_iam_users(
                max_items=max_items,
                marker=marker,
                path_prefix=path_prefix,
                format_response=format_response,
                names_only=names_only,
                session_context=session_context
            ))
            
        elif operation == "find_role":
            role_name = params.get("role_name")
            if not role_name:
                return safe_json_dumps({
                    "error": "role_name parameter is required for find_role",
                    "usage": "operation='find_role', role_name='EC2InstanceRole'"
                })
            
            format_response = params.get("format_response", True)
            return safe_json_dumps(await _find_iam_role(
                role_name=role_name,
                format_response=format_response,
                session_context=session_context
            ))
            
        elif operation == "list_roles":
            max_items = params.get("max_items")
            marker = params.get("marker")
            path_prefix = params.get("path_prefix")
            format_response = params.get("format_response", True)
            names_only = params.get("names_only", False)
            
            return safe_json_dumps(await _list_iam_roles(
                max_items=max_items,
                marker=marker,
                path_prefix=path_prefix,
                format_response=format_response,
                names_only=names_only,
                session_context=session_context
            ))
            
        elif operation == "find_access_key":
            access_key_id = params.get("access_key_id")
            if not access_key_id:
                return safe_json_dumps({
                    "error": "access_key_id parameter is required for find_access_key",
                    "usage": "operation='find_access_key', access_key_id='AKIAIOSFODNN7EXAMPLE'"
                })
            
            format_response = params.get("format_response", True)
            return safe_json_dumps(await _find_access_key(
                access_key_id=access_key_id,
                format_response=format_response,
                session_context=session_context
            ))
            
        elif operation == "get_policy_details":
            policy_arn = params.get("policy_arn")
            if not policy_arn:
                return safe_json_dumps({
                    "error": "policy_arn parameter is required for get_policy_details",
                    "usage": "operation='get_policy_details', policy_arn='arn:aws:iam::123456789012:policy/MyPolicy'"
                })
            
            include_versions = params.get("include_versions", False)
            format_response = params.get("format_response", True)
            return safe_json_dumps(await _get_iam_policy_details(
                policy_arn=policy_arn,
                include_versions=include_versions,
                format_response=format_response,
                session_context=session_context
            ))
            
        elif operation == "get_policy_batch":
            policy_arns = params.get("policy_arns")
            if not policy_arns or not isinstance(policy_arns, list):
                return safe_json_dumps({
                    "error": "policy_arns parameter (list) is required for get_policy_batch",
                    "usage": "operation='get_policy_batch', policy_arns=['arn:aws:iam::aws:policy/ReadOnlyAccess', 'arn:aws:iam::aws:policy/PowerUserAccess']"
                })
            
            include_versions = params.get("include_versions", False)
            format_response = params.get("format_response", True)
            return safe_json_dumps(await _get_iam_policy_batch(
                policy_arns=policy_arns,
                include_versions=include_versions,
                format_response=format_response,
                session_context=session_context
            ))
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "find_user", "list_users", "find_role", "list_roles",
                "find_access_key", "get_policy_details", "get_policy_batch"
            ]
            
            return safe_json_dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "find_user": "operation='find_user', user_name='john.doe'",
                    "list_users": "operation='list_users', names_only=True",
                    "find_role": "operation='find_role', role_name='EC2InstanceRole'",
                    "list_roles": "operation='list_roles', names_only=True",
                    "find_access_key": "operation='find_access_key', access_key_id='AKIAIOSFODNN7EXAMPLE'",
                    "get_policy_details": "operation='get_policy_details', policy_arn='arn:aws:iam::123456789012:policy/MyPolicy'",
                    "get_policy_batch": "operation='get_policy_batch', policy_arns=['arn1', 'arn2']"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in IAM operation '{operation}': {e}")
        return safe_json_dumps({
            "error": {
                "message": f"Error executing IAM operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_iam_operations() -> str:
    """Discover all available IAM operations with detailed usage examples.
    
    This tool provides comprehensive documentation of IAM operations available
    through the iam_security_operations tool, including parameter requirements
    and practical usage examples for identity and access management security monitoring.
    
    Returns:
        Detailed catalog of IAM operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS IAM (Identity and Access Management)",
        "description": "Identity and access management security monitoring and analysis",
        "wrapper_tool": "iam_security_operations",
        "supported_features": {
            "user_management": "Find and analyze IAM users with their permissions and access patterns",
            "role_management": "Find and analyze IAM roles with trust relationships and permissions",
            "access_key_analysis": "Analyze access keys and their usage patterns",
            "policy_analysis": "Analyze IAM policies and their permissions",
            "batch_operations": "Perform batch operations for efficient policy analysis",
            "security_assessment": "Comprehensive security assessment of IAM configurations"
        },
        "operation_categories": {
            "user_management": {
                "find_user": {
                    "description": "Find and get detailed information about a specific IAM user",
                    "parameters": {
                        "user_name": {"type": "str", "required": True, "description": "Name of the IAM user to find"},
                        "format_response": {"type": "bool", "default": True, "description": "Whether to format response for security analysis"}
                    },
                    "examples": [
                        "iam_security_operations(operation='find_user', user_name='john.doe')",
                        "iam_security_operations(operation='find_user', user_name='service-account', format_response=False)"
                    ]
                },
                "list_users": {
                    "description": "List IAM users with optional filtering and pagination",
                    "parameters": {
                        "max_items": {"type": "int", "description": "Maximum number of users to return"},
                        "marker": {"type": "str", "description": "Pagination token for subsequent requests"},
                        "path_prefix": {"type": "str", "description": "Filter users by path prefix"},
                        "format_response": {"type": "bool", "default": True, "description": "Whether to format response for security analysis"},
                        "names_only": {"type": "bool", "default": False, "description": "If True, returns only user names (faster)"}
                    },
                    "examples": [
                        "iam_security_operations(operation='list_users')",
                        "iam_security_operations(operation='list_users', names_only=True)",
                        "iam_security_operations(operation='list_users', max_items=50, path_prefix='/developers/')",
                        "iam_security_operations(operation='list_users', marker='previous_token')"
                    ]
                }
            },
            "role_management": {
                "find_role": {
                    "description": "Find and get detailed information about a specific IAM role",
                    "parameters": {
                        "role_name": {"type": "str", "required": True, "description": "Name of the IAM role to find"},
                        "format_response": {"type": "bool", "default": True, "description": "Whether to format response for security analysis"}
                    },
                    "examples": [
                        "iam_security_operations(operation='find_role', role_name='EC2InstanceRole')",
                        "iam_security_operations(operation='find_role', role_name='LambdaExecutionRole')",
                        "iam_security_operations(operation='find_role', role_name='CrossAccountRole', format_response=False)"
                    ]
                },
                "list_roles": {
                    "description": "List IAM roles with optional filtering and pagination",
                    "parameters": {
                        "max_items": {"type": "int", "description": "Maximum number of roles to return"},
                        "marker": {"type": "str", "description": "Pagination token for subsequent requests"},
                        "path_prefix": {"type": "str", "description": "Filter roles by path prefix"},
                        "format_response": {"type": "bool", "default": True, "description": "Whether to format response for security analysis"},
                        "names_only": {"type": "bool", "default": False, "description": "If True, returns only role names (faster)"}
                    },
                    "examples": [
                        "iam_security_operations(operation='list_roles')",
                        "iam_security_operations(operation='list_roles', names_only=True)",
                        "iam_security_operations(operation='list_roles', max_items=100, path_prefix='/service-roles/')",
                        "iam_security_operations(operation='list_roles', path_prefix='/aws-service-role/')"
                    ]
                }
            },
            "access_key_analysis": {
                "find_access_key": {
                    "description": "Find details about an IAM access key including associated user",
                    "parameters": {
                        "access_key_id": {"type": "str", "required": True, "description": "The access key ID to search for"},
                        "format_response": {"type": "bool", "default": True, "description": "Whether to format response for security analysis"}
                    },
                    "examples": [
                        "iam_security_operations(operation='find_access_key', access_key_id='AKIAIOSFODNN7EXAMPLE')",
                        "iam_security_operations(operation='find_access_key', access_key_id='AKIA1234567890ABCDEF')"
                    ]
                }
            },
            "policy_analysis": {
                "get_policy_details": {
                    "description": "Get detailed information about a specific IAM policy",
                    "parameters": {
                        "policy_arn": {"type": "str", "required": True, "description": "The ARN of the policy to retrieve"},
                        "include_versions": {"type": "bool", "default": False, "description": "Whether to include all policy versions"},
                        "format_response": {"type": "bool", "default": True, "description": "Whether to format response for security analysis"}
                    },
                    "examples": [
                        "iam_security_operations(operation='get_policy_details', policy_arn='arn:aws:iam::123456789012:policy/MyPolicy')",
                        "iam_security_operations(operation='get_policy_details', policy_arn='arn:aws:iam::aws:policy/PowerUserAccess', include_versions=True)",
                        "iam_security_operations(operation='get_policy_details', policy_arn='arn:aws:iam::aws:policy/ReadOnlyAccess')"
                    ]
                },
                "get_policy_batch": {
                    "description": "Get details about multiple IAM policies in batch",
                    "parameters": {
                        "policy_arns": {"type": "List[str]", "required": True, "description": "List of policy ARNs to retrieve"},
                        "include_versions": {"type": "bool", "default": False, "description": "Whether to include all policy versions"},
                        "format_response": {"type": "bool", "default": True, "description": "Whether to format response for security analysis"}
                    },
                    "examples": [
                        "iam_security_operations(operation='get_policy_batch', policy_arns=['arn:aws:iam::aws:policy/ReadOnlyAccess', 'arn:aws:iam::aws:policy/PowerUserAccess'])",
                        "iam_security_operations(operation='get_policy_batch', policy_arns=['arn:aws:iam::123456789012:policy/CustomPolicy1', 'arn:aws:iam::123456789012:policy/CustomPolicy2'], include_versions=True)"
                    ]
                }
            }
        },
        "iam_security_insights": {
            "common_operations": [
                "List all users: operation='list_users', names_only=True",
                "List all roles: operation='list_roles', names_only=True",
                "Find specific user: operation='find_user', user_name='username'",
                "Find specific role: operation='find_role', role_name='rolename'",
                "Analyze access key: operation='find_access_key', access_key_id='AKIA...'"
            ],
            "security_monitoring_patterns": [
                "Audit user permissions and group memberships",
                "Monitor role trust relationships and cross-account access",
                "Track access key usage and last activity",
                "Analyze policy permissions and privilege escalation risks",
                "Review MFA settings and console access patterns",
                "Monitor for unused or dormant accounts",
                "Check for overprivileged users and roles",
                "Validate service-linked roles and their permissions"
            ],
            "security_best_practices": [
                "Implement least privilege access principles",
                "Regularly rotate access keys and remove unused keys",
                "Enable MFA for all users with console access",
                "Use roles instead of users for programmatic access",
                "Implement strong password policies",
                "Monitor for root account usage",
                "Use AWS managed policies when possible",
                "Regular access reviews and cleanup of unused resources",
                "Implement proper tagging for IAM resources",
                "Use CloudTrail to monitor IAM API calls"
            ],
            "compliance_considerations": [
                "Ensure proper segregation of duties",
                "Implement approval workflows for privileged access",
                "Maintain audit logs of all IAM changes",
                "Regular compliance audits and reviews",
                "Document role purposes and justifications",
                "Implement break-glass procedures for emergency access",
                "Monitor for policy violations and drift",
                "Ensure proper offboarding procedures for users"
            ],
            "risk_assessment": [
                "Identify users with administrative privileges",
                "Monitor for policies allowing dangerous actions (iam:*, *:*)",
                "Check for roles that can assume other roles",
                "Identify cross-account trust relationships",
                "Monitor for policies with NotAction or NotResource",
                "Check for policies with overly broad resource specifications",
                "Identify users with programmatic access but no MFA",
                "Monitor for service accounts with unnecessary permissions"
            ],
            "performance_optimization": [
                "Use names_only=True for large user/role lists",
                "Implement pagination for large result sets",
                "Use batch operations for multiple policy analyses",
                "Cache frequently accessed policy details",
                "Filter results using path_prefix when possible"
            ]
        }
    }
    
    return safe_json_dumps(operations_catalog, indent=2) 