"""Load Balancer Service Wrapper for AWS Security MCP.

This wrapper consolidates all Elastic Load Balancing operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing load balancer functions to reuse them
from aws_security_mcp.tools.load_balancer_tools import (
    get_load_balancers as _get_load_balancers,
    describe_load_balancer as _describe_load_balancer,
    describe_instance_health as _describe_instance_health,
    get_target_groups as _get_target_groups,
    describe_target_health as _describe_target_health,
    describe_listeners as _describe_listeners,
    describe_load_balancer_listeners as _describe_load_balancer_listeners,
    describe_rules as _describe_rules,
    search_load_balancer as _search_load_balancer,
    describe_listeners_by_arns as _describe_listeners_by_arns,
    get_load_balancer_by_arn as _get_load_balancer_by_arn
)

logger = logging.getLogger(__name__)

@register_tool()
async def load_balancer_operations(operation: str, **params) -> str:
    """Load Balancer Operations Hub - Comprehensive traffic distribution and health monitoring.
    
    ⚖️ LOAD BALANCER DISCOVERY:
    - get_load_balancers: List load balancers with filtering by type, ARNs, names
    - describe_load_balancer: Get detailed information about a specific load balancer
    - search_load_balancer: Search for load balancers by ARN, name, or DNS name
    - get_load_balancer_by_arn: Retrieve load balancer details using ARN
    
    🎯 TARGET GROUP OPERATIONS:
    - get_target_groups: List target groups with optional load balancer filtering
    - describe_target_health: Check health status of targets in target groups
    
    🔗 LISTENER MANAGEMENT:
    - describe_listeners: List listeners for a specific load balancer
    - describe_load_balancer_listeners: Direct listener lookup using load balancer ARN
    - describe_listeners_by_arns: Batch describe listeners using their ARNs
    - describe_rules: Get routing rules for specific listeners
    
    🏥 HEALTH MONITORING:
    - describe_instance_health: Check health of instances in Classic Load Balancers
    - describe_target_health: Monitor target health in ALB/NLB target groups
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    ⚖️ List all load balancers:
    operation="get_load_balancers", load_balancer_type="application"
    
    🔍 Search for specific load balancer:
    operation="search_load_balancer", identifier="my-app-lb"
    
    🎯 Get target groups for load balancer:
    operation="get_target_groups", load_balancer_arn="arn:aws:elasticloadbalancing:..."
    
    🔗 List listeners for load balancer:
    operation="describe_listeners", load_balancer_arn="arn:aws:elasticloadbalancing:..."
    
    🏥 Check target health:
    operation="describe_target_health", target_group_arn="arn:aws:elasticloadbalancing:..."
    
    📊 Monitor Classic LB health:
    operation="describe_instance_health", load_balancer_name="classic-lb"
    
    🔧 Get routing rules:
    operation="describe_rules", listener_arn="arn:aws:elasticloadbalancing:..."
    
    Args:
        operation: The load balancer operation to perform (see descriptions above)
        
        # Load balancer parameters:
        load_balancer_type: Type filter ('classic', 'application', 'network', 'gateway')
        arns: List of load balancer ARNs for filtering
        names: List of load balancer names for filtering
        load_balancer_arn: Specific load balancer ARN
        load_balancer_name: Name of Classic Load Balancer
        identifier: Search term (ARN, name, or DNS name)
        
        # Target group parameters:
        target_group_arn: ARN of the target group
        targets: List of targets to describe (for target health)
        
        # Listener parameters:
        listener_arn: ARN of the listener
        listener_arns: List of listener ARNs for batch operations
        
        # Instance parameters (Classic LB):
        instance_ids: List of instance IDs for health checks
        
        # Pagination parameters:
        next_token: Pagination token for continued results
        max_items: Maximum items to return
        
    Returns:
        JSON formatted response with operation results and load balancer insights
    """
    
    logger.info(f"Load balancer operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "get_load_balancers":
            load_balancer_type = params.get("load_balancer_type")
            arns = params.get("arns")
            names = params.get("names")
            next_token = params.get("next_token")
            max_items = params.get("max_items")
            
            return await _get_load_balancers(
                load_balancer_type=load_balancer_type,
                arns=arns,
                names=names,
                next_token=next_token,
                max_items=max_items
            )
            
        elif operation == "describe_load_balancer":
            load_balancer_arn = params.get("load_balancer_arn")
            if not load_balancer_arn:
                return json.dumps({
                    "error": "load_balancer_arn parameter is required for describe_load_balancer",
                    "usage": "operation='describe_load_balancer', load_balancer_arn='arn:aws:elasticloadbalancing:...'"
                })
            
            return await _describe_load_balancer(load_balancer_arn=load_balancer_arn)
            
        elif operation == "search_load_balancer":
            identifier = params.get("identifier")
            if not identifier:
                return json.dumps({
                    "error": "identifier parameter is required for search_load_balancer",
                    "usage": "operation='search_load_balancer', identifier='my-load-balancer'"
                })
            
            return await _search_load_balancer(identifier=identifier)
            
        elif operation == "get_load_balancer_by_arn":
            load_balancer_arn = params.get("load_balancer_arn")
            if not load_balancer_arn:
                return json.dumps({
                    "error": "load_balancer_arn parameter is required for get_load_balancer_by_arn",
                    "usage": "operation='get_load_balancer_by_arn', load_balancer_arn='arn:aws:elasticloadbalancing:...'"
                })
            
            return await _get_load_balancer_by_arn(load_balancer_arn=load_balancer_arn)
            
        elif operation == "get_target_groups":
            load_balancer_arn = params.get("load_balancer_arn")
            next_token = params.get("next_token")
            max_items = params.get("max_items")
            
            return await _get_target_groups(
                load_balancer_arn=load_balancer_arn,
                next_token=next_token,
                max_items=max_items
            )
            
        elif operation == "describe_target_health":
            target_group_arn = params.get("target_group_arn")
            if not target_group_arn:
                return json.dumps({
                    "error": "target_group_arn parameter is required for describe_target_health",
                    "usage": "operation='describe_target_health', target_group_arn='arn:aws:elasticloadbalancing:...'"
                })
            
            targets = params.get("targets")
            
            return await _describe_target_health(
                target_group_arn=target_group_arn,
                targets=targets
            )
            
        elif operation == "describe_listeners":
            load_balancer_arn = params.get("load_balancer_arn")
            if not load_balancer_arn:
                return json.dumps({
                    "error": "load_balancer_arn parameter is required for describe_listeners",
                    "usage": "operation='describe_listeners', load_balancer_arn='arn:aws:elasticloadbalancing:...'"
                })
            
            next_token = params.get("next_token")
            max_items = params.get("max_items")
            
            return await _describe_listeners(
                load_balancer_arn=load_balancer_arn,
                next_token=next_token,
                max_items=max_items
            )
            
        elif operation == "describe_load_balancer_listeners":
            load_balancer_arn = params.get("load_balancer_arn")
            if not load_balancer_arn:
                return json.dumps({
                    "error": "load_balancer_arn parameter is required for describe_load_balancer_listeners",
                    "usage": "operation='describe_load_balancer_listeners', load_balancer_arn='arn:aws:elasticloadbalancing:...'"
                })
            
            next_token = params.get("next_token")
            max_items = params.get("max_items")
            
            return await _describe_load_balancer_listeners(
                load_balancer_arn=load_balancer_arn,
                next_token=next_token,
                max_items=max_items
            )
            
        elif operation == "describe_listeners_by_arns":
            listener_arns = params.get("listener_arns")
            if not listener_arns:
                return json.dumps({
                    "error": "listener_arns parameter is required for describe_listeners_by_arns",
                    "usage": "operation='describe_listeners_by_arns', listener_arns=['arn:aws:elasticloadbalancing:...']"
                })
            
            return await _describe_listeners_by_arns(listener_arns=listener_arns)
            
        elif operation == "describe_rules":
            listener_arn = params.get("listener_arn")
            if not listener_arn:
                return json.dumps({
                    "error": "listener_arn parameter is required for describe_rules",
                    "usage": "operation='describe_rules', listener_arn='arn:aws:elasticloadbalancing:...'"
                })
            
            next_token = params.get("next_token")
            max_items = params.get("max_items")
            
            return await _describe_rules(
                listener_arn=listener_arn,
                next_token=next_token,
                max_items=max_items
            )
            
        elif operation == "describe_instance_health":
            load_balancer_name = params.get("load_balancer_name")
            if not load_balancer_name:
                return json.dumps({
                    "error": "load_balancer_name parameter is required for describe_instance_health",
                    "usage": "operation='describe_instance_health', load_balancer_name='classic-lb-name'"
                })
            
            instance_ids = params.get("instance_ids")
            
            return await _describe_instance_health(
                load_balancer_name=load_balancer_name,
                instance_ids=instance_ids
            )
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "get_load_balancers", "describe_load_balancer", "search_load_balancer",
                "get_load_balancer_by_arn", "get_target_groups", "describe_target_health",
                "describe_listeners", "describe_load_balancer_listeners", 
                "describe_listeners_by_arns", "describe_rules", "describe_instance_health"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "get_load_balancers": "operation='get_load_balancers', load_balancer_type='application'",
                    "search_load_balancer": "operation='search_load_balancer', identifier='my-lb'",
                    "describe_target_health": "operation='describe_target_health', target_group_arn='arn:aws:...'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in load balancer operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing load balancer operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_load_balancer_operations() -> str:
    """Discover all available load balancer operations with detailed usage examples.
    
    This tool provides comprehensive documentation of load balancer operations available
    through the load_balancer_operations tool, including parameter requirements
    and practical usage examples.
    
    Returns:
        Detailed catalog of load balancer operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Elastic Load Balancing",
        "description": "Application, Network, Gateway, and Classic Load Balancer management and monitoring",
        "wrapper_tool": "load_balancer_operations",
        "supported_types": {
            "classic": "Classic Load Balancer (ELB)",
            "application": "Application Load Balancer (ALB)",
            "network": "Network Load Balancer (NLB)",
            "gateway": "Gateway Load Balancer (GWLB)"
        },
        "operation_categories": {
            "load_balancer_discovery": {
                "get_load_balancers": {
                    "description": "List load balancers with filtering by type, ARNs, or names",
                    "parameters": {
                        "load_balancer_type": {"type": "str", "options": ["classic", "application", "network", "gateway"], "description": "Filter by load balancer type"},
                        "arns": {"type": "list", "description": "Filter by specific ARNs"},
                        "names": {"type": "list", "description": "Filter by specific names"},
                        "next_token": {"type": "str", "description": "Pagination token"},
                        "max_items": {"type": "int", "description": "Maximum items to return"}
                    },
                    "examples": [
                        "load_balancer_operations(operation='get_load_balancers')",
                        "load_balancer_operations(operation='get_load_balancers', load_balancer_type='application')",
                        "load_balancer_operations(operation='get_load_balancers', names=['my-lb', 'prod-lb'])"
                    ]
                },
                "describe_load_balancer": {
                    "description": "Get detailed information about a specific load balancer using ARN",
                    "parameters": {
                        "load_balancer_arn": {"type": "str", "required": True, "description": "ARN of the load balancer"}
                    },
                    "example": "load_balancer_operations(operation='describe_load_balancer', load_balancer_arn='arn:aws:elasticloadbalancing:...')"
                },
                "search_load_balancer": {
                    "description": "Search for load balancers by ARN, name, or DNS name",
                    "parameters": {
                        "identifier": {"type": "str", "required": True, "description": "ARN, name, or DNS name to search for"}
                    },
                    "examples": [
                        "load_balancer_operations(operation='search_load_balancer', identifier='my-app-lb')",
                        "load_balancer_operations(operation='search_load_balancer', identifier='my-lb-123456.us-west-2.elb.amazonaws.com')"
                    ]
                }
            },
            "target_group_operations": {
                "get_target_groups": {
                    "description": "List target groups with optional load balancer filtering",
                    "parameters": {
                        "load_balancer_arn": {"type": "str", "description": "Filter by specific load balancer ARN"},
                        "next_token": {"type": "str", "description": "Pagination token"},
                        "max_items": {"type": "int", "description": "Maximum items to return"}
                    },
                    "examples": [
                        "load_balancer_operations(operation='get_target_groups')",
                        "load_balancer_operations(operation='get_target_groups', load_balancer_arn='arn:aws:elasticloadbalancing:...')"
                    ]
                },
                "describe_target_health": {
                    "description": "Check health status of targets in a target group",
                    "parameters": {
                        "target_group_arn": {"type": "str", "required": True, "description": "ARN of the target group"},
                        "targets": {"type": "list", "description": "Optional list of specific targets to check"}
                    },
                    "examples": [
                        "load_balancer_operations(operation='describe_target_health', target_group_arn='arn:aws:elasticloadbalancing:...')",
                        "load_balancer_operations(operation='describe_target_health', target_group_arn='arn:aws:...', targets=[{'Id': 'i-123', 'Port': 80}])"
                    ]
                }
            },
            "listener_operations": {
                "describe_listeners": {
                    "description": "List listeners for a specific load balancer",
                    "parameters": {
                        "load_balancer_arn": {"type": "str", "required": True, "description": "ARN of the load balancer"},
                        "next_token": {"type": "str", "description": "Pagination token"},
                        "max_items": {"type": "int", "description": "Maximum items to return"}
                    },
                    "example": "load_balancer_operations(operation='describe_listeners', load_balancer_arn='arn:aws:elasticloadbalancing:...')"
                },
                "describe_listeners_by_arns": {
                    "description": "Batch describe listeners using their ARNs",
                    "parameters": {
                        "listener_arns": {"type": "list", "required": True, "description": "List of listener ARNs"}
                    },
                    "example": "load_balancer_operations(operation='describe_listeners_by_arns', listener_arns=['arn:aws:elasticloadbalancing:...'])"
                },
                "describe_rules": {
                    "description": "Get routing rules for a specific listener",
                    "parameters": {
                        "listener_arn": {"type": "str", "required": True, "description": "ARN of the listener"},
                        "next_token": {"type": "str", "description": "Pagination token"},
                        "max_items": {"type": "int", "description": "Maximum items to return"}
                    },
                    "example": "load_balancer_operations(operation='describe_rules', listener_arn='arn:aws:elasticloadbalancing:...')"
                }
            },
            "health_monitoring": {
                "describe_instance_health": {
                    "description": "Check health of instances in Classic Load Balancers",
                    "parameters": {
                        "load_balancer_name": {"type": "str", "required": True, "description": "Name of the Classic Load Balancer"},
                        "instance_ids": {"type": "list", "description": "Optional list of instance IDs to filter"}
                    },
                    "examples": [
                        "load_balancer_operations(operation='describe_instance_health', load_balancer_name='classic-lb')",
                        "load_balancer_operations(operation='describe_instance_health', load_balancer_name='classic-lb', instance_ids=['i-123', 'i-456'])"
                    ]
                }
            }
        },
        "load_balancer_insights": {
            "common_operations": [
                "List all application load balancers: operation='get_load_balancers', load_balancer_type='application'",
                "Check target health: operation='describe_target_health', target_group_arn='arn:aws:...'",
                "Find load balancer by DNS: operation='search_load_balancer', identifier='my-lb.amazonaws.com'",
                "Get routing rules: operation='describe_rules', listener_arn='arn:aws:...'"
            ],
            "monitoring_best_practices": [
                "Regularly check target group health status",
                "Monitor listener configurations for security compliance",
                "Review routing rules for proper traffic distribution",
                "Audit load balancer access logs for security insights"
            ],
            "security_considerations": [
                "Ensure HTTPS listeners use secure SSL policies",
                "Review security group configurations for load balancers",
                "Monitor for load balancers exposed to internet unnecessarily",
                "Check for proper WAF integration on application load balancers"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 