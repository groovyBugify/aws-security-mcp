"""Resource Tagging Service Wrapper for AWS Security MCP.

This wrapper consolidates all resource tagging operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing resource tagging functions to reuse them
from aws_security_mcp.tools.resource_tagging_tools import (
    search_resources_by_tag as _search_resources_by_tag,
    get_all_tag_keys as _get_all_tag_keys,
    get_tag_values_for_key as _get_tag_values_for_key
)

logger = logging.getLogger(__name__)

@register_tool()
async def resource_tagging_operations(operation: str, **params) -> str:
    """Resource Tagging Operations Hub - Comprehensive AWS resource discovery and inventory management through tags.
    
    🏷️ RESOURCE DISCOVERY:
    - search_resources_by_tag: Search AWS resources by tag key and optional value with filtering
    
    🔍 TAG KEY MANAGEMENT:
    - get_all_tag_keys: Get all tag keys used across the AWS account
    
    📋 TAG VALUE ANALYSIS:
    - get_tag_values_for_key: Get all values for a specific tag key in the account
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🏷️ Search by tag key only:
    operation="search_resources_by_tag", tag_key="Environment"
    
    🎯 Search by specific tag key-value:
    operation="search_resources_by_tag", tag_key="Environment", tag_value="Production"
    
    🔍 Search with resource type filtering:
    operation="search_resources_by_tag", tag_key="Team", tag_value="DevOps", resource_types=["ec2:instance", "s3:bucket"]
    
    📊 Get all tag keys in account:
    operation="get_all_tag_keys"
    
    📋 Get values for specific tag:
    operation="get_tag_values_for_key", tag_key="Environment"
    
    🏷️ Search with pagination:
    operation="search_resources_by_tag", tag_key="Owner", max_items=50, next_token="token123"
    
    📈 Large-scale inventory:
    operation="search_resources_by_tag", tag_key="CostCenter", group_by_type=true
    
    Args:
        operation: The resource tagging operation to perform (see descriptions above)
        
        # Search parameters:
        tag_key: The tag key to search for (required for search and tag value operations)
        tag_value: Optional tag value to filter by
        resource_types: List of resource types to filter by (e.g., ['ec2:instance', 's3:bucket'])
        group_by_type: Whether to group resources by service/resource type (default: true)
        
        # Pagination parameters:
        next_token: Token for pagination continuation
        max_items: Maximum number of items to return
        
    Returns:
        JSON formatted response with operation results and resource tagging insights
    """
    
    logger.info(f"Resource tagging operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "search_resources_by_tag":
            tag_key = params.get("tag_key")
            if not tag_key:
                return json.dumps({
                    "error": "tag_key parameter is required for search_resources_by_tag",
                    "usage": "operation='search_resources_by_tag', tag_key='Environment'"
                })
            
            tag_value = params.get("tag_value")
            resource_types = params.get("resource_types")
            next_token = params.get("next_token")
            max_items = params.get("max_items")
            group_by_type = params.get("group_by_type", True)
            
            return await _search_resources_by_tag(
                tag_key=tag_key,
                tag_value=tag_value,
                resource_types=resource_types,
                next_token=next_token,
                max_items=max_items,
                group_by_type=group_by_type
            )
            
        elif operation == "get_all_tag_keys":
            next_token = params.get("next_token")
            max_items = params.get("max_items")
            
            return await _get_all_tag_keys(
                next_token=next_token,
                max_items=max_items
            )
            
        elif operation == "get_tag_values_for_key":
            tag_key = params.get("tag_key")
            if not tag_key:
                return json.dumps({
                    "error": "tag_key parameter is required for get_tag_values_for_key",
                    "usage": "operation='get_tag_values_for_key', tag_key='Environment'"
                })
            
            next_token = params.get("next_token")
            max_items = params.get("max_items")
            
            return await _get_tag_values_for_key(
                tag_key=tag_key,
                next_token=next_token,
                max_items=max_items
            )
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "search_resources_by_tag", "get_all_tag_keys", "get_tag_values_for_key"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "search_resources_by_tag": "operation='search_resources_by_tag', tag_key='Environment'",
                    "get_all_tag_keys": "operation='get_all_tag_keys'",
                    "get_tag_values_for_key": "operation='get_tag_values_for_key', tag_key='Environment'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in resource tagging operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing resource tagging operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_resource_tagging_operations() -> str:
    """Discover all available resource tagging operations with detailed usage examples.
    
    This tool provides comprehensive documentation of resource tagging operations available
    through the resource_tagging_operations tool, including parameter requirements
    and practical usage examples for AWS resource discovery and inventory management.
    
    Returns:
        Detailed catalog of resource tagging operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Resource Groups Tagging API",
        "description": "Comprehensive AWS resource discovery and inventory management through tags",
        "wrapper_tool": "resource_tagging_operations",
        "supported_features": {
            "resource_discovery": "Find and inventory AWS resources using tag-based queries",
            "tag_management": "Analyze tag usage patterns across the AWS account",
            "inventory_operations": "Large-scale resource discovery and categorization",
            "compliance_tracking": "Track resource compliance through standardized tagging"
        },
        "operation_categories": {
            "resource_discovery": {
                "search_resources_by_tag": {
                    "description": "Search AWS resources by tag key and optional value with advanced filtering",
                    "parameters": {
                        "tag_key": {"type": "str", "required": True, "description": "The tag key to search for"},
                        "tag_value": {"type": "str", "description": "Optional tag value to filter by"},
                        "resource_types": {"type": "list", "description": "List of resource types to filter by (e.g., ['ec2:instance', 's3:bucket'])"},
                        "group_by_type": {"type": "bool", "default": True, "description": "Whether to group resources by service/resource type"},
                        "next_token": {"type": "str", "description": "Token for pagination continuation"},
                        "max_items": {"type": "int", "description": "Maximum number of items to return"}
                    },
                    "examples": [
                        "resource_tagging_operations(operation='search_resources_by_tag', tag_key='Environment')",
                        "resource_tagging_operations(operation='search_resources_by_tag', tag_key='Environment', tag_value='Production')",
                        "resource_tagging_operations(operation='search_resources_by_tag', tag_key='Team', resource_types=['ec2:instance', 's3:bucket'])",
                        "resource_tagging_operations(operation='search_resources_by_tag', tag_key='Owner', max_items=50)",
                        "resource_tagging_operations(operation='search_resources_by_tag', tag_key='CostCenter', group_by_type=False)"
                    ]
                }
            },
            "tag_key_management": {
                "get_all_tag_keys": {
                    "description": "Get all tag keys used across the AWS account",
                    "parameters": {
                        "next_token": {"type": "str", "description": "Token for pagination continuation"},
                        "max_items": {"type": "int", "description": "Maximum number of tag keys to return"}
                    },
                    "examples": [
                        "resource_tagging_operations(operation='get_all_tag_keys')",
                        "resource_tagging_operations(operation='get_all_tag_keys', max_items=100)"
                    ]
                }
            },
            "tag_value_analysis": {
                "get_tag_values_for_key": {
                    "description": "Get all values for a specific tag key in the account",
                    "parameters": {
                        "tag_key": {"type": "str", "required": True, "description": "The tag key to get values for"},
                        "next_token": {"type": "str", "description": "Token for pagination continuation"},
                        "max_items": {"type": "int", "description": "Maximum number of tag values to return"}
                    },
                    "examples": [
                        "resource_tagging_operations(operation='get_tag_values_for_key', tag_key='Environment')",
                        "resource_tagging_operations(operation='get_tag_values_for_key', tag_key='Team', max_items=50)"
                    ]
                }
            }
        },
        "resource_tagging_insights": {
            "common_operations": [
                "Find all production resources: operation='search_resources_by_tag', tag_key='Environment', tag_value='Production'",
                "Inventory by team: operation='search_resources_by_tag', tag_key='Team'",
                "Get all tag keys: operation='get_all_tag_keys'",
                "Analyze environment values: operation='get_tag_values_for_key', tag_key='Environment'"
            ],
            "inventory_best_practices": [
                "Use consistent tag naming conventions across all resources",
                "Implement mandatory tagging policies for cost tracking",
                "Regular auditing of tag compliance and standardization",
                "Use tag-based resource grouping for operational efficiency",
                "Monitor tag coverage across different resource types"
            ],
            "security_and_compliance": [
                "Tag resources with security classifications and access levels",
                "Use tags to track data sensitivity and compliance requirements",
                "Implement tag-based access controls and resource isolation",
                "Monitor untagged resources for security and compliance gaps",
                "Use tags for audit trails and change management tracking"
            ],
            "cost_optimization": [
                "Track resource ownership and cost centers through tags",
                "Identify unused or misconfigured resources via tagging gaps",
                "Implement automated cost allocation based on tags",
                "Monitor resource lifecycle and optimization opportunities",
                "Use tags for budget tracking and cost anomaly detection"
            ],
            "operational_insights": [
                "Group resources by application, environment, and team",
                "Track resource dependencies and relationships via tags",
                "Implement automated operations based on tag-driven policies",
                "Monitor resource health and performance by tag categories",
                "Use tags for disaster recovery and backup strategies"
            ],
            "common_resource_types": [
                "ec2:instance - EC2 instances",
                "ec2:volume - EBS volumes", 
                "ec2:snapshot - EBS snapshots",
                "ec2:security-group - Security groups",
                "s3:bucket - S3 buckets",
                "rds:db - RDS databases",
                "lambda:function - Lambda functions",
                "ecs:cluster - ECS clusters",
                "ecs:service - ECS services",
                "elasticloadbalancing:loadbalancer - Load balancers"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 