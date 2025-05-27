"""WAF Service Wrapper for AWS Security MCP.

This wrapper consolidates all WAF operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing WAF functions to reuse them
from aws_security_mcp.tools.waf_tools import (
    list_waf_web_acls as _list_waf_web_acls,
    get_waf_web_acl_details as _get_waf_web_acl_details,
    list_waf_ip_sets as _list_waf_ip_sets,
    get_waf_ip_set_details as _get_waf_ip_set_details,
    list_waf_rule_groups as _list_waf_rule_groups,
    get_waf_rule_group_details as _get_waf_rule_group_details,
    list_waf_resources_for_web_acl as _list_waf_resources_for_web_acl,
    list_all_waf_components as _list_all_waf_components
)

logger = logging.getLogger(__name__)

@register_tool()
async def waf_security_operations(operation: str, **params) -> str:
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
    - list_resources_for_web_acl: List resources protected by a specific Web ACL
    
    📊 COMPREHENSIVE OVERVIEW:
    - list_all_components: Get complete WAF inventory (Web ACLs, IP sets, rule groups)
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🛡️ List regional Web ACLs:
    operation="list_web_acls", scope="REGIONAL", limit=50
    
    🌍 List CloudFront Web ACLs:
    operation="list_web_acls", scope="CLOUDFRONT", limit=25
    
    🔍 Get Web ACL details:
    operation="get_web_acl_details", web_acl_id="12345678-1234-1234-1234-123456789012", web_acl_name="MyWebACL", scope="REGIONAL"
    
    🚫 List IP sets:
    operation="list_ip_sets", scope="REGIONAL", limit=30
    
    📋 Get IP set details:
    operation="get_ip_set_details", ip_set_id="12345678-1234-1234-1234-123456789012", ip_set_name="MyIPSet", scope="REGIONAL"
    
    📝 List rule groups:
    operation="list_rule_groups", scope="REGIONAL", limit=40
    
    🔍 Get rule group details:
    operation="get_rule_group_details", rule_group_id="12345678-1234-1234-1234-123456789012", rule_group_name="MyRuleGroup", scope="REGIONAL"
    
    🔗 List protected resources:
    operation="list_resources_for_web_acl", web_acl_arn="arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/12345678-1234-1234-1234-123456789012"
    
    📊 Get complete overview:
    operation="list_all_components", scope="REGIONAL", limit=100
    
    Args:
        operation: The WAF operation to perform (see descriptions above)
        
        # Scope parameters:
        scope: WAF scope - "REGIONAL" for ALB/API Gateway, "CLOUDFRONT" for CloudFront (default: "REGIONAL")
        
        # Web ACL parameters:
        web_acl_id: ID of the Web ACL for detailed operations
        web_acl_name: Name of the Web ACL for detailed operations
        web_acl_arn: ARN of the Web ACL for resource listing
        
        # IP Set parameters:
        ip_set_id: ID of the IP set for detailed operations
        ip_set_name: Name of the IP set for detailed operations
        
        # Rule Group parameters:
        rule_group_id: ID of the rule group for detailed operations
        rule_group_name: Name of the rule group for detailed operations
        
        # Resource parameters:
        resource_type: Type of resource to list (default: "APPLICATION_LOAD_BALANCER")
        
        # Pagination parameters:
        limit: Maximum number of items to return (default: 100)
        next_token: Pagination token for large result sets
        
    Returns:
        JSON formatted response with operation results and WAF security insights
    """
    
    logger.info(f"WAF operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_web_acls":
            scope = params.get("scope", "REGIONAL")
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            result = await _list_waf_web_acls(
                scope=scope,
                limit=limit,
                next_token=next_token
            )
            return json.dumps(result)
            
        elif operation == "get_web_acl_details":
            web_acl_id = params.get("web_acl_id")
            web_acl_name = params.get("web_acl_name")
            scope = params.get("scope", "REGIONAL")
            
            if not web_acl_id or not web_acl_name:
                return json.dumps({
                    "error": "Both web_acl_id and web_acl_name parameters are required for get_web_acl_details",
                    "usage": "operation='get_web_acl_details', web_acl_id='12345678-1234-1234-1234-123456789012', web_acl_name='MyWebACL', scope='REGIONAL'"
                })
            
            result = await _get_waf_web_acl_details(
                web_acl_id=web_acl_id,
                web_acl_name=web_acl_name,
                scope=scope
            )
            return json.dumps(result)
            
        elif operation == "list_ip_sets":
            scope = params.get("scope", "REGIONAL")
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            result = await _list_waf_ip_sets(
                scope=scope,
                limit=limit,
                next_token=next_token
            )
            return json.dumps(result)
            
        elif operation == "get_ip_set_details":
            ip_set_id = params.get("ip_set_id")
            ip_set_name = params.get("ip_set_name")
            scope = params.get("scope", "REGIONAL")
            
            if not ip_set_id or not ip_set_name:
                return json.dumps({
                    "error": "Both ip_set_id and ip_set_name parameters are required for get_ip_set_details",
                    "usage": "operation='get_ip_set_details', ip_set_id='12345678-1234-1234-1234-123456789012', ip_set_name='MyIPSet', scope='REGIONAL'"
                })
            
            result = await _get_waf_ip_set_details(
                ip_set_id=ip_set_id,
                ip_set_name=ip_set_name,
                scope=scope
            )
            return json.dumps(result)
            
        elif operation == "list_rule_groups":
            scope = params.get("scope", "REGIONAL")
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            result = await _list_waf_rule_groups(
                scope=scope,
                limit=limit,
                next_token=next_token
            )
            return json.dumps(result)
            
        elif operation == "get_rule_group_details":
            rule_group_id = params.get("rule_group_id")
            rule_group_name = params.get("rule_group_name")
            scope = params.get("scope", "REGIONAL")
            
            if not rule_group_id or not rule_group_name:
                return json.dumps({
                    "error": "Both rule_group_id and rule_group_name parameters are required for get_rule_group_details",
                    "usage": "operation='get_rule_group_details', rule_group_id='12345678-1234-1234-1234-123456789012', rule_group_name='MyRuleGroup', scope='REGIONAL'"
                })
            
            result = await _get_waf_rule_group_details(
                rule_group_id=rule_group_id,
                rule_group_name=rule_group_name,
                scope=scope
            )
            return json.dumps(result)
            
        elif operation == "list_resources_for_web_acl":
            web_acl_arn = params.get("web_acl_arn")
            resource_type = params.get("resource_type", "APPLICATION_LOAD_BALANCER")
            
            if not web_acl_arn:
                return json.dumps({
                    "error": "web_acl_arn parameter is required for list_resources_for_web_acl",
                    "usage": "operation='list_resources_for_web_acl', web_acl_arn='arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/12345678-1234-1234-1234-123456789012'"
                })
            
            result = await _list_waf_resources_for_web_acl(
                web_acl_arn=web_acl_arn,
                resource_type=resource_type
            )
            return json.dumps(result)
            
        elif operation == "list_all_components":
            scope = params.get("scope", "REGIONAL")
            limit = params.get("limit", 100)
            
            result = await _list_all_waf_components(
                scope=scope,
                limit=limit
            )
            return json.dumps(result)
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_web_acls", "get_web_acl_details", "list_ip_sets", "get_ip_set_details",
                "list_rule_groups", "get_rule_group_details", "list_resources_for_web_acl",
                "list_all_components"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_web_acls": "operation='list_web_acls', scope='REGIONAL', limit=50",
                    "get_web_acl_details": "operation='get_web_acl_details', web_acl_id='12345678-1234-1234-1234-123456789012', web_acl_name='MyWebACL'",
                    "list_ip_sets": "operation='list_ip_sets', scope='REGIONAL'",
                    "list_all_components": "operation='list_all_components', scope='REGIONAL'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in WAF operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing WAF operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_waf_operations() -> str:
    """Discover all available WAF operations with detailed usage examples.
    
    This tool provides comprehensive documentation of WAF operations available
    through the waf_security_operations tool, including parameter requirements
    and practical usage examples for web application firewall management.
    
    Returns:
        Detailed catalog of WAF operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS WAF",
        "description": "Web Application Firewall service for protecting web applications from common web exploits",
        "wrapper_tool": "waf_security_operations",
        "supported_features": {
            "web_acls": "Web Access Control Lists for filtering web requests",
            "ip_sets": "IP address allow/block lists for geographic and threat-based filtering",
            "rule_groups": "Reusable rule collections for common protection patterns",
            "managed_rules": "AWS and marketplace managed rule sets",
            "custom_rules": "Custom rules for application-specific protection"
        },
        "operation_categories": {
            "web_acl_management": {
                "list_web_acls": {
                    "description": "List WAF Web ACLs with filtering and scope selection",
                    "parameters": {
                        "scope": {"type": "str", "default": "REGIONAL", "description": "WAF scope", "options": ["REGIONAL", "CLOUDFRONT"]},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of Web ACLs to return"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching next set of Web ACLs"}
                    },
                    "examples": [
                        "waf_security_operations(operation='list_web_acls')",
                        "waf_security_operations(operation='list_web_acls', scope='REGIONAL', limit=50)",
                        "waf_security_operations(operation='list_web_acls', scope='CLOUDFRONT', limit=25)",
                        "waf_security_operations(operation='list_web_acls', scope='REGIONAL', next_token='token123')"
                    ]
                },
                "get_web_acl_details": {
                    "description": "Get detailed Web ACL configuration including rules, conditions, and associations",
                    "parameters": {
                        "web_acl_id": {"type": "str", "required": True, "description": "ID of the Web ACL"},
                        "web_acl_name": {"type": "str", "required": True, "description": "Name of the Web ACL"},
                        "scope": {"type": "str", "default": "REGIONAL", "description": "WAF scope", "options": ["REGIONAL", "CLOUDFRONT"]}
                    },
                    "examples": [
                        "waf_security_operations(operation='get_web_acl_details', web_acl_id='12345678-1234-1234-1234-123456789012', web_acl_name='MyWebACL')",
                        "waf_security_operations(operation='get_web_acl_details', web_acl_id='87654321-4321-4321-4321-210987654321', web_acl_name='ProductionWebACL', scope='CLOUDFRONT')"
                    ]
                }
            },
            "ip_set_management": {
                "list_ip_sets": {
                    "description": "List WAF IP sets for allow/block lists and geographic filtering",
                    "parameters": {
                        "scope": {"type": "str", "default": "REGIONAL", "description": "WAF scope", "options": ["REGIONAL", "CLOUDFRONT"]},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of IP sets to return"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching next set of IP sets"}
                    },
                    "examples": [
                        "waf_security_operations(operation='list_ip_sets')",
                        "waf_security_operations(operation='list_ip_sets', scope='REGIONAL', limit=30)",
                        "waf_security_operations(operation='list_ip_sets', scope='CLOUDFRONT')"
                    ]
                },
                "get_ip_set_details": {
                    "description": "Get detailed IP set configuration including IP addresses and CIDR blocks",
                    "parameters": {
                        "ip_set_id": {"type": "str", "required": True, "description": "ID of the IP set"},
                        "ip_set_name": {"type": "str", "required": True, "description": "Name of the IP set"},
                        "scope": {"type": "str", "default": "REGIONAL", "description": "WAF scope", "options": ["REGIONAL", "CLOUDFRONT"]}
                    },
                    "examples": [
                        "waf_security_operations(operation='get_ip_set_details', ip_set_id='12345678-1234-1234-1234-123456789012', ip_set_name='AllowedIPs')",
                        "waf_security_operations(operation='get_ip_set_details', ip_set_id='87654321-4321-4321-4321-210987654321', ip_set_name='BlockedIPs', scope='CLOUDFRONT')"
                    ]
                }
            },
            "rule_group_management": {
                "list_rule_groups": {
                    "description": "List WAF rule groups including managed and custom rule collections",
                    "parameters": {
                        "scope": {"type": "str", "default": "REGIONAL", "description": "WAF scope", "options": ["REGIONAL", "CLOUDFRONT"]},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of rule groups to return"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching next set of rule groups"}
                    },
                    "examples": [
                        "waf_security_operations(operation='list_rule_groups')",
                        "waf_security_operations(operation='list_rule_groups', scope='REGIONAL', limit=40)",
                        "waf_security_operations(operation='list_rule_groups', scope='CLOUDFRONT')"
                    ]
                },
                "get_rule_group_details": {
                    "description": "Get detailed rule group configuration including individual rules and conditions",
                    "parameters": {
                        "rule_group_id": {"type": "str", "required": True, "description": "ID of the rule group"},
                        "rule_group_name": {"type": "str", "required": True, "description": "Name of the rule group"},
                        "scope": {"type": "str", "default": "REGIONAL", "description": "WAF scope", "options": ["REGIONAL", "CLOUDFRONT"]}
                    },
                    "examples": [
                        "waf_security_operations(operation='get_rule_group_details', rule_group_id='12345678-1234-1234-1234-123456789012', rule_group_name='CustomRules')",
                        "waf_security_operations(operation='get_rule_group_details', rule_group_id='87654321-4321-4321-4321-210987654321', rule_group_name='SQLInjectionRules', scope='CLOUDFRONT')"
                    ]
                }
            },
            "resource_protection": {
                "list_resources_for_web_acl": {
                    "description": "List AWS resources protected by a specific Web ACL",
                    "parameters": {
                        "web_acl_arn": {"type": "str", "required": True, "description": "ARN of the Web ACL"},
                        "resource_type": {"type": "str", "default": "APPLICATION_LOAD_BALANCER", "description": "Type of AWS resource"}
                    },
                    "examples": [
                        "waf_security_operations(operation='list_resources_for_web_acl', web_acl_arn='arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/12345678-1234-1234-1234-123456789012')",
                        "waf_security_operations(operation='list_resources_for_web_acl', web_acl_arn='arn:aws:wafv2:us-east-1:123456789012:regional/webacl/APIGatewayACL/87654321-4321-4321-4321-210987654321', resource_type='API_GATEWAY')"
                    ]
                }
            },
            "comprehensive_overview": {
                "list_all_components": {
                    "description": "Get complete WAF inventory including Web ACLs, IP sets, and rule groups",
                    "parameters": {
                        "scope": {"type": "str", "default": "REGIONAL", "description": "WAF scope", "options": ["REGIONAL", "CLOUDFRONT"]},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of each component type to return"}
                    },
                    "examples": [
                        "waf_security_operations(operation='list_all_components')",
                        "waf_security_operations(operation='list_all_components', scope='CLOUDFRONT', limit=50)",
                        "waf_security_operations(operation='list_all_components', scope='REGIONAL', limit=200)"
                    ]
                }
            }
        },
        "waf_security_insights": {
            "common_operations": [
                "List regional Web ACLs: operation='list_web_acls', scope='REGIONAL'",
                "List CloudFront Web ACLs: operation='list_web_acls', scope='CLOUDFRONT'",
                "Get complete inventory: operation='list_all_components'",
                "Check protected resources: operation='list_resources_for_web_acl', web_acl_arn='arn:...'"
            ],
            "web_application_protection_patterns": [
                "Monitor Web ACL configurations and rule effectiveness",
                "Review IP sets for threat intelligence and geographic blocking",
                "Analyze rule groups for comprehensive protection coverage",
                "Validate resource associations with appropriate Web ACLs",
                "Track blocked vs allowed traffic patterns",
                "Monitor false positive rates and tune rules accordingly",
                "Review managed rule set updates and recommendations",
                "Implement rate limiting and bot detection rules"
            ],
            "waf_scopes": {
                "REGIONAL": "Protects Application Load Balancers, API Gateway, and App Runner services",
                "CLOUDFRONT": "Protects CloudFront distributions for global edge protection"
            },
            "supported_resource_types": [
                "Application Load Balancer (ALB)",
                "API Gateway REST API",
                "API Gateway GraphQL API", 
                "CloudFront distributions",
                "AWS App Runner services",
                "Amazon Cognito user pools"
            ],
            "protection_capabilities": [
                "SQL injection attack prevention",
                "Cross-site scripting (XSS) protection",
                "Rate limiting and DDoS mitigation",
                "Geographic blocking and IP reputation filtering",
                "Bot detection and management",
                "Custom rule logic for application-specific threats",
                "Managed rule sets from AWS and marketplace",
                "Request sampling and logging for analysis"
            ],
            "managed_rule_groups": [
                "AWS Core Rule Set (CRS) for OWASP Top 10",
                "AWS Known Bad Inputs for common attack patterns",
                "AWS SQL Database for SQL injection protection",
                "AWS WordPress Application for WordPress-specific threats",
                "AWS IP Reputation List for known malicious IPs",
                "AWS Anonymous IP List for anonymous proxies/VPNs",
                "Third-party managed rules from AWS Marketplace"
            ],
            "security_best_practices": [
                "Use managed rule groups as baseline protection",
                "Implement custom rules for application-specific threats",
                "Configure appropriate default actions (allow/block)",
                "Enable request sampling and CloudWatch logging",
                "Regularly review and update IP sets and rule priorities",
                "Test rule changes in count mode before blocking",
                "Monitor CloudWatch metrics for attack patterns",
                "Implement rate limiting to prevent abuse",
                "Use geographic blocking judiciously to avoid false positives",
                "Coordinate with Shield Advanced for DDoS protection"
            ],
            "compliance_considerations": [
                "Maintain logs of blocked requests for security audits",
                "Document custom rule justifications and effectiveness",
                "Regular review of protection coverage and rule performance",
                "Ensure appropriate rules for PCI DSS, HIPAA, or other standards",
                "Track false positive rates and remediation actions",
                "Validate that all public-facing resources are protected",
                "Monitor rule group updates and security advisories"
            ],
            "monitoring_and_alerting": [
                "CloudWatch metrics for blocked/allowed requests",
                "CloudWatch alarms for unusual traffic patterns",
                "AWS Config rules for WAF configuration compliance",
                "AWS Security Hub integration for centralized security findings",
                "Custom dashboards for WAF performance and effectiveness",
                "Automated response to high-confidence attack patterns"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 