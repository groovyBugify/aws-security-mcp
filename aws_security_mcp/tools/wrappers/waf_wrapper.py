"""WAF Service Wrapper for AWS Security MCP.

This wrapper consolidates all WAF operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import WAF service functions directly
from aws_security_mcp.services import waf

logger = logging.getLogger(__name__)

@register_tool()
async def waf_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """WAF Security Operations Hub - Comprehensive web application firewall management and protection.
    
    🛡️ WEB ACL MANAGEMENT:
    - list_web_acls: List WAF Web ACLs with filtering and scope selection
    - get_web_acl_details: Get detailed Web ACL configuration and rules
    
    🚫 IP SET MANAGEMENT:
    - list_ip_sets: List WAF IP sets for allow/block lists
    - get_ip_set_details: Get detailed IP set configuration and addresses
    
    📝 RULE GROUP MANAGEMENT:
    - list_rule_groups: List WAF rule groups and managed rules
    - get_rule_group_details: Get detailed rule group configuration and rules
    
    🔗 RESOURCE PROTECTION:
    - list_protected_resources: List resources protected by Web ACLs
    
    📊 CLASSIC WAF (DEPRECATED):
    - list_classic_web_acls: List Classic WAF Web ACLs (use WAFv2 instead)
    - get_classic_web_acl_details: Get Classic WAF Web ACL details
    
    Args:
        operation: The WAF operation to perform
        session_context: Optional session key for cross-account access
        **params: Operation-specific parameters
        
    Returns:
        JSON string with operation results and security insights
    """
    try:
        if operation == "list_web_acls":
            scope = params.get('scope', 'REGIONAL')
            limit = params.get('limit', 100)
            next_token = params.get('next_token')
            
            result = await waf.list_web_acls(
                scope=scope,
                max_items=limit,
                next_marker=next_token,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "list_web_acls",
                "scope": scope,
                "web_acls": result.get('web_acls', []),
                "next_token": result.get('next_marker'),
                "has_more": result.get('has_more', False),
                "total_count": len(result.get('web_acls', [])),
                "security_insights": {
                    "protection_coverage": f"Found {len(result.get('web_acls', []))} Web ACLs providing application protection",
                    "scope_analysis": f"Scanning {scope} scope for web application firewalls"
                }
            }, indent=2)
            
        elif operation == "get_web_acl_details":
            web_acl_id = params.get('web_acl_id')
            web_acl_name = params.get('web_acl_name')
            web_acl_arn = params.get('web_acl_arn')
            scope = params.get('scope', 'REGIONAL')
            
            # Check if we have valid parameters
            if not web_acl_arn and not (web_acl_id and web_acl_name):
                return json.dumps({
                    "error": "Either web_acl_arn must be provided, or both web_acl_id and web_acl_name must be provided for get_web_acl_details"
                })
            
            result = await waf.get_web_acl(
                web_acl_id=web_acl_id,
                web_acl_name=web_acl_name,
                web_acl_arn=web_acl_arn,
                scope=scope,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "get_web_acl_details",
                "web_acl": result,
                "security_insights": {
                    "rule_analysis": f"Web ACL contains {len(result.get('Rules', []))} rules",
                    "default_action": result.get('DefaultAction', {}).get('Type', 'Unknown'),
                    "protection_level": "High" if len(result.get('Rules', [])) > 5 else "Medium"
                }
            }, indent=2)
            
        elif operation == "list_ip_sets":
            scope = params.get('scope', 'REGIONAL')
            limit = params.get('limit', 100)
            next_token = params.get('next_token')
            
            result = await waf.list_ip_sets(
                scope=scope,
                max_items=limit,
                next_marker=next_token,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "list_ip_sets",
                "scope": scope,
                "ip_sets": result.get('ip_sets', []),
                "next_token": result.get('next_marker'),
                "has_more": result.get('has_more', False),
                "total_count": len(result.get('ip_sets', [])),
                "security_insights": {
                    "ip_management": f"Found {len(result.get('ip_sets', []))} IP sets for access control",
                    "scope_coverage": f"IP sets configured for {scope} scope"
                }
            }, indent=2)
            
        elif operation == "get_ip_set_details":
            ip_set_id = params.get('ip_set_id')
            ip_set_name = params.get('ip_set_name')
            ip_set_arn = params.get('ip_set_arn')
            scope = params.get('scope', 'REGIONAL')
            
            # Check if we have valid parameters
            if not ip_set_arn and not (ip_set_id and ip_set_name):
                return json.dumps({
                    "error": "Either ip_set_arn must be provided, or both ip_set_id and ip_set_name must be provided for get_ip_set_details"
                })
            
            result = await waf.get_ip_set(
                ip_set_id=ip_set_id,
                ip_set_name=ip_set_name,
                ip_set_arn=ip_set_arn,
                scope=scope,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "get_ip_set_details",
                "ip_set": result,
                "security_insights": {
                    "address_count": len(result.get('Addresses', [])),
                    "ip_version": result.get('IPAddressVersion', 'Unknown'),
                    "access_control": "Block list" if "block" in result.get('Name', '').lower() else "Allow list"
                }
            }, indent=2)
            
        elif operation == "list_rule_groups":
            scope = params.get('scope', 'REGIONAL')
            limit = params.get('limit', 100)
            next_token = params.get('next_token')
            
            result = await waf.list_rule_groups(
                scope=scope,
                max_items=limit,
                next_marker=next_token,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "list_rule_groups",
                "scope": scope,
                "rule_groups": result.get('rule_groups', []),
                "next_token": result.get('next_marker'),
                "has_more": result.get('has_more', False),
                "total_count": len(result.get('rule_groups', [])),
                "security_insights": {
                    "rule_management": f"Found {len(result.get('rule_groups', []))} rule groups",
                    "protection_layers": "Multiple rule groups provide layered security"
                }
            }, indent=2)
            
        elif operation == "get_rule_group_details":
            rule_group_id = params.get('rule_group_id')
            rule_group_name = params.get('rule_group_name')
            rule_group_arn = params.get('rule_group_arn')
            scope = params.get('scope', 'REGIONAL')
            
            # Check if we have valid parameters
            if not rule_group_arn and not (rule_group_id and rule_group_name):
                return json.dumps({
                    "error": "Either rule_group_arn must be provided, or both rule_group_id and rule_group_name must be provided for get_rule_group_details"
                })
            
            result = await waf.get_rule_group(
                rule_group_id=rule_group_id,
                rule_group_name=rule_group_name,
                rule_group_arn=rule_group_arn,
                scope=scope,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "get_rule_group_details",
                "rule_group": result,
                "security_insights": {
                    "rule_count": len(result.get('Rules', [])),
                    "capacity_used": result.get('Capacity', 0),
                    "rule_complexity": "High" if result.get('Capacity', 0) > 100 else "Medium"
                }
            }, indent=2)
            
        elif operation == "list_protected_resources":
            web_acl_arn = params.get('web_acl_arn')
            resource_type = params.get('resource_type', 'APPLICATION_LOAD_BALANCER')
            
            if not web_acl_arn:
                return json.dumps({
                    "error": "web_acl_arn is required for list_protected_resources"
                })
            
            result = await waf.list_resources_for_web_acl(
                web_acl_arn=web_acl_arn,
                resource_type=resource_type,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "list_protected_resources",
                "web_acl_arn": web_acl_arn,
                "resource_type": resource_type,
                "protected_resources": result,
                "total_count": len(result),
                "security_insights": {
                    "protection_coverage": f"{len(result)} {resource_type} resources protected",
                    "security_posture": "Good" if len(result) > 0 else "Needs attention"
                }
            }, indent=2)
            
        elif operation == "list_classic_web_acls":
            limit = params.get('limit', 100)
            next_token = params.get('next_token')
            
            result = await waf.list_classic_web_acls(
                max_items=limit,
                next_marker=next_token,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "list_classic_web_acls",
                "web_acls": result.get('web_acls', []),
                "next_token": result.get('next_marker'),
                "has_more": result.get('has_more', False),
                "total_count": len(result.get('web_acls', [])),
                "security_insights": {
                    "migration_notice": "Classic WAF is deprecated - consider migrating to WAFv2",
                    "legacy_protection": f"Found {len(result.get('web_acls', []))} Classic WAF Web ACLs"
                }
            }, indent=2)
            
        elif operation == "get_classic_web_acl_details":
            web_acl_id = params.get('web_acl_id')
            
            if not web_acl_id:
                return json.dumps({
                    "error": "web_acl_id is required for get_classic_web_acl_details"
                })
            
            result = await waf.get_classic_web_acl(
                web_acl_id=web_acl_id,
                session_context=session_context
            )
            
            return json.dumps({
                "operation": "get_classic_web_acl_details",
                "web_acl": result,
                "security_insights": {
                    "migration_notice": "Classic WAF is deprecated - consider migrating to WAFv2",
                    "rule_count": len(result.get('Rules', [])),
                    "default_action": result.get('DefaultAction', {}).get('Type', 'Unknown')
                }
            }, indent=2)
            
        else:
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": [
                    "list_web_acls", "get_web_acl_details",
                    "list_ip_sets", "get_ip_set_details", 
                    "list_rule_groups", "get_rule_group_details",
                    "list_protected_resources",
                    "list_classic_web_acls", "get_classic_web_acl_details"
                ]
            })
            
    except Exception as e:
        logger.error(f"Error in WAF operation {operation}: {e}")
        return json.dumps({
            "error": f"Error executing WAF operation '{operation}': {str(e)}",
            "operation": operation,
            "parameters": params
        })

@register_tool()
async def discover_waf_operations(session_context: Optional[str] = None) -> str:
    """Discover all available WAF operations with detailed usage examples.
    
    This tool provides comprehensive documentation of WAF operations available
    through the waf_security_operations tool, including parameter requirements
    and practical usage examples for web application firewall management.
    
    Args:
        session_context: Optional session key for cross-account access (for documentation consistency)
    
    Returns:
        Detailed catalog of WAF operations with examples and parameter descriptions
    """
    operations_catalog = {
        "waf_operations_guide": {
            "description": "Comprehensive AWS WAF security operations for web application protection",
            "operations": {
                "list_web_acls": {
                    "description": "List WAF Web ACLs with scope filtering",
                    "parameters": {
                        "scope": "REGIONAL or CLOUDFRONT (default: REGIONAL)",
                        "limit": "Maximum number of Web ACLs to return (default: 100)",
                        "next_token": "Pagination token for next page"
                    },
                    "example": {
                        "operation": "list_web_acls",
                        "scope": "REGIONAL",
                        "limit": 50
                    }
                },
                "get_web_acl_details": {
                    "description": "Get detailed Web ACL configuration and rules",
                    "parameters": {
                        "Option 1 - Using ID and Name": {
                            "web_acl_id": "Required - Web ACL ID",
                            "web_acl_name": "Required - Web ACL name"
                        },
                        "Option 2 - Using ARN": {
                            "web_acl_arn": "Required - Web ACL ARN"
                        },
                        "scope": "REGIONAL or CLOUDFRONT (default: REGIONAL)"
                    },
                    "examples": [
                        {
                            "description": "Using ID and name",
                            "operation": "get_web_acl_details",
                            "web_acl_id": "12345678-1234-1234-1234-123456789012",
                            "web_acl_name": "MyWebACL",
                            "scope": "REGIONAL"
                        },
                        {
                            "description": "Using ARN",
                            "operation": "get_web_acl_details",
                            "web_acl_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/12345678-1234-1234-1234-123456789012"
                        }
                    ]
                },
                "list_ip_sets": {
                    "description": "List WAF IP sets for access control",
                    "parameters": {
                        "scope": "REGIONAL or CLOUDFRONT (default: REGIONAL)",
                        "limit": "Maximum number of IP sets to return (default: 100)",
                        "next_token": "Pagination token for next page"
                    },
                    "example": {
                        "operation": "list_ip_sets",
                        "scope": "REGIONAL"
                    }
                },
                "get_ip_set_details": {
                    "description": "Get detailed IP set configuration and addresses",
                    "parameters": {
                        "Option 1 - Using ID and Name": {
                            "ip_set_id": "Required - IP set ID",
                            "ip_set_name": "Required - IP set name"
                        },
                        "Option 2 - Using ARN": {
                            "ip_set_arn": "Required - IP set ARN"
                        },
                        "scope": "REGIONAL or CLOUDFRONT (default: REGIONAL)"
                    },
                    "examples": [
                        {
                            "description": "Using ID and name",
                            "operation": "get_ip_set_details",
                            "ip_set_id": "12345678-1234-1234-1234-123456789012",
                            "ip_set_name": "BlockedIPs"
                        },
                        {
                            "description": "Using ARN",
                            "operation": "get_ip_set_details",
                            "ip_set_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BlockedIPs/12345678-1234-1234-1234-123456789012"
                        }
                    ]
                },
                "list_rule_groups": {
                    "description": "List WAF rule groups and managed rules",
                    "parameters": {
                        "scope": "REGIONAL or CLOUDFRONT (default: REGIONAL)",
                        "limit": "Maximum number of rule groups to return (default: 100)",
                        "next_token": "Pagination token for next page"
                    },
                    "example": {
                        "operation": "list_rule_groups",
                        "scope": "REGIONAL"
                    }
                },
                "get_rule_group_details": {
                    "description": "Get detailed rule group configuration and rules",
                    "parameters": {
                        "Option 1 - Using ID and Name": {
                            "rule_group_id": "Required - Rule group ID",
                            "rule_group_name": "Required - Rule group name"
                        },
                        "Option 2 - Using ARN": {
                            "rule_group_arn": "Required - Rule group ARN"
                        },
                        "scope": "REGIONAL or CLOUDFRONT (default: REGIONAL)"
                    },
                    "examples": [
                        {
                            "description": "Using ID and name",
                            "operation": "get_rule_group_details",
                            "rule_group_id": "12345678-1234-1234-1234-123456789012",
                            "rule_group_name": "CustomRules"
                        },
                        {
                            "description": "Using ARN",
                            "operation": "get_rule_group_details",
                            "rule_group_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/CustomRules/12345678-1234-1234-1234-123456789012"
                        }
                    ]
                },
                "list_protected_resources": {
                    "description": "List resources protected by a Web ACL",
                    "parameters": {
                        "web_acl_arn": "Required - Web ACL ARN",
                        "resource_type": "Resource type (default: APPLICATION_LOAD_BALANCER)"
                    },
                    "example": {
                        "operation": "list_protected_resources",
                        "web_acl_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/12345678-1234-1234-1234-123456789012",
                        "resource_type": "APPLICATION_LOAD_BALANCER"
                    }
                },
                "list_classic_web_acls": {
                    "description": "List Classic WAF Web ACLs (deprecated)",
                    "parameters": {
                        "limit": "Maximum number of Web ACLs to return (default: 100)",
                        "next_token": "Pagination token for next page"
                    },
                    "note": "Classic WAF is deprecated - migrate to WAFv2"
                },
                "get_classic_web_acl_details": {
                    "description": "Get Classic WAF Web ACL details (deprecated)",
                    "parameters": {
                        "web_acl_id": "Required - Classic Web ACL ID"
                    },
                    "note": "Classic WAF is deprecated - migrate to WAFv2"
                }
            },
            "security_best_practices": {
                "web_acl_configuration": "Ensure Web ACLs have appropriate rules for your application",
                "ip_set_management": "Regularly review and update IP allow/block lists",
                "rule_group_optimization": "Use managed rule groups for common attack patterns",
                "resource_protection": "Verify all critical resources are protected by Web ACLs",
                "monitoring": "Enable WAF logging and monitoring for security insights"
            }
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 