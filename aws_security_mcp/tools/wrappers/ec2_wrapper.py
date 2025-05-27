"""EC2 Service Wrapper for AWS Security MCP.

This wrapper consolidates EC2 operations into a single tool while maintaining
semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing EC2 functions to reuse them
from aws_security_mcp.tools.ec2_tools import (
    list_ec2_instances as _list_ec2_instances,
    count_ec2_instances as _count_ec2_instances,
    list_security_groups as _list_security_groups,
    list_vpcs as _list_vpcs,
    list_route_tables as _list_route_tables,
    list_subnets as _list_subnets,
    list_ec2_resources as _list_ec2_resources,
    find_public_security_groups as _find_public_security_groups,
    find_instances_with_public_access as _find_instances_with_public_access,
    find_resource_by_ip as _find_resource_by_ip,
    find_instances_by_port as _find_instances_by_port,
    find_security_groups_by_port as _find_security_groups_by_port,
    batch_describe_security_groups as _batch_describe_security_groups,
    batch_describe_instances as _batch_describe_instances
)

logger = logging.getLogger(__name__)

@register_tool()
async def ec2_security_operations(operation: str, **params) -> str:
    """EC2 Security Operations Hub - Comprehensive infrastructure analysis and monitoring.
    
    🖥️ INSTANCE OPERATIONS:
    - list_instances: List EC2 instances with filtering by state, search terms, and pagination
    - count_instances: Count instances with filtering options (state, public access, ports)
    - batch_describe_instances: Get detailed info for multiple instances by ID
    - find_instances_with_public_access: Identify instances exposed to internet
    - find_instances_by_port: Find instances with specific ports open
    
    🛡️ SECURITY GROUP OPERATIONS:
    - list_security_groups: List security groups with advanced search and filtering
    - find_public_security_groups: Identify security groups open to internet (0.0.0.0/0)
    - find_security_groups_by_port: Find security groups with specific ports open
    - batch_describe_security_groups: Get detailed info for multiple security groups
    
    🌐 NETWORK OPERATIONS:
    - list_vpcs: List Virtual Private Clouds with details and search
    - list_subnets: List subnets with route table and ACL information
    - list_route_tables: List route tables with association details
    
    🔍 ANALYSIS OPERATIONS:
    - find_resource_by_ip: Find AWS resources associated with specific IP addresses
    - list_ec2_resources: Comprehensive listing of all EC2 resource types
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🖥️ List running instances:
    operation="list_instances", state="running", limit=50
    
    🔍 Search for web servers:
    operation="list_instances", search_term="web", state="running"
    
    🚨 Find internet-exposed instances:
    operation="find_instances_with_public_access", port=22
    
    🛡️ Audit public security groups:
    operation="find_public_security_groups", port=80
    
    📊 Count instances by state:
    operation="count_instances", state="running"
    
    🌐 Analyze VPC infrastructure:
    operation="list_vpcs", search_term="prod"
    
    🔎 Investigate IP ownership:
    operation="find_resource_by_ip", ip_address="1.2.3.4"
    
    Args:
        operation: The EC2 operation to perform (see descriptions above)
        
        # Instance parameters:
        limit: Maximum results to return (default varies by operation)
        search_term: Text search across resource names, IDs, descriptions
        state: Instance state filter (running, stopped, terminated, etc.)
        next_token: Pagination token for continued results
        
        # Security analysis parameters:
        port: Specific port number for security analysis (e.g., 22, 80, 443)
        has_public_access: Boolean filter for public internet access
        
        # Resource identification parameters:
        instance_ids: List of instance IDs for batch operations
        security_group_ids: List of security group IDs for batch operations
        ip_address: IP address to search for resource ownership
        
        # Network parameters:
        vpc_id: VPC ID for subnet/route table filtering
        include_details: Include detailed information (route tables, ACLs)
        resource_type: Type of EC2 resource (instances, security_groups, vpcs, etc.)
        
    Returns:
        JSON formatted response with operation results and security insights
    """
    
    logger.info(f"EC2 operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_instances":
            limit = params.get("limit")
            search_term = params.get("search_term", "")
            state = params.get("state", "running")
            next_token = params.get("next_token")
            
            return await _list_ec2_instances(
                limit=limit,
                search_term=search_term,
                state=state,
                next_token=next_token
            )
            
        elif operation == "count_instances":
            state = params.get("state", "")
            has_public_access = params.get("has_public_access")
            port = params.get("port")
            
            return await _count_ec2_instances(
                state=state,
                has_public_access=has_public_access,
                port=port
            )
            
        elif operation == "batch_describe_instances":
            instance_ids = params.get("instance_ids")
            if not instance_ids:
                return json.dumps({
                    "error": "instance_ids parameter is required for batch_describe_instances",
                    "usage": "operation='batch_describe_instances', instance_ids=['i-123', 'i-456']"
                })
            
            return await _batch_describe_instances(instance_ids=instance_ids)
            
        elif operation == "find_instances_with_public_access":
            port = params.get("port")
            state = params.get("state", "running")
            
            return await _find_instances_with_public_access(
                port=port,
                state=state
            )
            
        elif operation == "find_instances_by_port":
            port = params.get("port")
            if port is None:
                return json.dumps({
                    "error": "port parameter is required for find_instances_by_port",
                    "usage": "operation='find_instances_by_port', port=22"
                })
            
            state = params.get("state", "running")
            return await _find_instances_by_port(port=port, state=state)
            
        elif operation == "list_security_groups":
            limit = params.get("limit")
            search_term = params.get("search_term", "")
            next_token = params.get("next_token")
            
            return await _list_security_groups(
                limit=limit,
                search_term=search_term,
                next_token=next_token
            )
            
        elif operation == "find_public_security_groups":
            port = params.get("port")
            
            return await _find_public_security_groups(port=port)
            
        elif operation == "find_security_groups_by_port":
            port = params.get("port")
            if port is None:
                return json.dumps({
                    "error": "port parameter is required for find_security_groups_by_port",
                    "usage": "operation='find_security_groups_by_port', port=443"
                })
            
            return await _find_security_groups_by_port(port=port)
            
        elif operation == "batch_describe_security_groups":
            security_group_ids = params.get("security_group_ids")
            if not security_group_ids:
                return json.dumps({
                    "error": "security_group_ids parameter is required for batch_describe_security_groups",
                    "usage": "operation='batch_describe_security_groups', security_group_ids=['sg-123', 'sg-456']"
                })
            
            return await _batch_describe_security_groups(security_group_ids=security_group_ids)
            
        elif operation == "list_vpcs":
            limit = params.get("limit")
            search_term = params.get("search_term", "")
            next_token = params.get("next_token")
            
            return await _list_vpcs(
                limit=limit,
                search_term=search_term,
                next_token=next_token
            )
            
        elif operation == "list_subnets":
            vpc_id = params.get("vpc_id")
            include_details = params.get("include_details", True)
            limit = params.get("limit")
            search_term = params.get("search_term", "")
            next_token = params.get("next_token")
            
            return await _list_subnets(
                vpc_id=vpc_id,
                include_details=include_details,
                limit=limit,
                search_term=search_term,
                next_token=next_token
            )
            
        elif operation == "list_route_tables":
            limit = params.get("limit")
            search_term = params.get("search_term", "")
            next_token = params.get("next_token")
            
            return await _list_route_tables(
                limit=limit,
                search_term=search_term,
                next_token=next_token
            )
            
        elif operation == "find_resource_by_ip":
            ip_address = params.get("ip_address")
            if not ip_address:
                return json.dumps({
                    "error": "ip_address parameter is required for find_resource_by_ip",
                    "usage": "operation='find_resource_by_ip', ip_address='1.2.3.4'"
                })
            
            return await _find_resource_by_ip(ip_address=ip_address)
            
        elif operation == "list_ec2_resources":
            resource_type = params.get("resource_type", "all")
            limit = params.get("limit")
            search_term = params.get("search_term", "")
            state = params.get("state", "running")
            next_token = params.get("next_token")
            
            return await _list_ec2_resources(
                resource_type=resource_type,
                limit=limit,
                search_term=search_term,
                state=state,
                next_token=next_token
            )
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_instances", "count_instances", "batch_describe_instances",
                "find_instances_with_public_access", "find_instances_by_port",
                "list_security_groups", "find_public_security_groups", 
                "find_security_groups_by_port", "batch_describe_security_groups",
                "list_vpcs", "list_subnets", "list_route_tables",
                "find_resource_by_ip", "list_ec2_resources"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_instances": "operation='list_instances', state='running', limit=50",
                    "find_public_security_groups": "operation='find_public_security_groups', port=22",
                    "find_resource_by_ip": "operation='find_resource_by_ip', ip_address='1.2.3.4'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in EC2 operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing EC2 operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_ec2_operations() -> str:
    """Discover all available EC2 security operations with detailed usage examples.
    
    This tool provides comprehensive documentation of EC2 operations available
    through the ec2_security_operations tool, including parameter requirements
    and practical usage examples.
    
    Returns:
        Detailed catalog of EC2 operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS EC2",
        "description": "Elastic Compute Cloud infrastructure management and security analysis",
        "wrapper_tool": "ec2_security_operations",
        "operation_categories": {
            "instance_operations": {
                "list_instances": {
                    "description": "List EC2 instances with filtering and search capabilities",
                    "parameters": {
                        "limit": {"type": "int", "description": "Maximum instances to return"},
                        "search_term": {"type": "str", "description": "Filter by name, ID, IP, or type"},
                        "state": {"type": "str", "default": "running", "options": ["running", "stopped", "terminated", "pending"], "description": "Instance state filter"},
                        "next_token": {"type": "str", "description": "Pagination token"}
                    },
                    "examples": [
                        "ec2_security_operations(operation='list_instances', state='running')",
                        "ec2_security_operations(operation='list_instances', search_term='web', limit=20)"
                    ]
                },
                "count_instances": {
                    "description": "Count instances with optional filtering by state and security",
                    "parameters": {
                        "state": {"type": "str", "description": "Instance state to count"},
                        "has_public_access": {"type": "bool", "description": "Filter by public internet access"},
                        "port": {"type": "int", "description": "Specific port for access analysis"}
                    },
                    "examples": [
                        "ec2_security_operations(operation='count_instances', state='running')",
                        "ec2_security_operations(operation='count_instances', has_public_access=True, port=22)"
                    ]
                },
                "batch_describe_instances": {
                    "description": "Get detailed information for multiple instances by ID",
                    "parameters": {
                        "instance_ids": {"type": "list", "required": True, "description": "List of instance IDs"}
                    },
                    "example": "ec2_security_operations(operation='batch_describe_instances', instance_ids=['i-123', 'i-456'])"
                }
            },
            "security_analysis": {
                "find_instances_with_public_access": {
                    "description": "Identify instances exposed to the internet through security groups",
                    "parameters": {
                        "port": {"type": "int", "description": "Specific port to check (e.g., 22 for SSH)"},
                        "state": {"type": "str", "default": "running", "description": "Instance state filter"}
                    },
                    "examples": [
                        "ec2_security_operations(operation='find_instances_with_public_access')",
                        "ec2_security_operations(operation='find_instances_with_public_access', port=22)"
                    ]
                },
                "find_instances_by_port": {
                    "description": "Find instances with specific ports open in security groups",
                    "parameters": {
                        "port": {"type": "int", "required": True, "description": "Port number to search for"},
                        "state": {"type": "str", "default": "running", "description": "Instance state filter"}
                    },
                    "example": "ec2_security_operations(operation='find_instances_by_port', port=3389)"
                }
            },
            "security_group_operations": {
                "list_security_groups": {
                    "description": "List security groups with advanced search and filtering",
                    "parameters": {
                        "limit": {"type": "int", "description": "Maximum security groups to return"},
                        "search_term": {"type": "str", "description": "Search by name, ID, or special syntax (port:22, public:true)"},
                        "next_token": {"type": "str", "description": "Pagination token"}
                    },
                    "examples": [
                        "ec2_security_operations(operation='list_security_groups')",
                        "ec2_security_operations(operation='list_security_groups', search_term='port:22')"
                    ]
                },
                "find_public_security_groups": {
                    "description": "Find security groups open to internet (0.0.0.0/0)",
                    "parameters": {
                        "port": {"type": "int", "description": "Specific port to check for public access"}
                    },
                    "examples": [
                        "ec2_security_operations(operation='find_public_security_groups')",
                        "ec2_security_operations(operation='find_public_security_groups', port=80)"
                    ]
                }
            },
            "network_operations": {
                "list_vpcs": {
                    "description": "List Virtual Private Clouds with details",
                    "parameters": {
                        "limit": {"type": "int", "description": "Maximum VPCs to return"},
                        "search_term": {"type": "str", "description": "Filter by VPC ID, CIDR, or name"},
                        "next_token": {"type": "str", "description": "Pagination token"}
                    },
                    "example": "ec2_security_operations(operation='list_vpcs', search_term='prod')"
                },
                "list_subnets": {
                    "description": "List subnets with route table and ACL information",
                    "parameters": {
                        "vpc_id": {"type": "str", "description": "Filter by specific VPC"},
                        "include_details": {"type": "bool", "default": True, "description": "Include route tables and ACLs"}
                    },
                    "example": "ec2_security_operations(operation='list_subnets', vpc_id='vpc-123')"
                }
            }
        },
        "security_insights": {
            "common_security_checks": [
                "Find instances with SSH access: operation='find_instances_with_public_access', port=22",
                "Check for public security groups: operation='find_public_security_groups'",
                "Audit RDP access: operation='find_instances_by_port', port=3389",
                "Review all public instances: operation='find_instances_with_public_access'"
            ],
            "best_practices": [
                "Regular audit of public security groups and instances",
                "Monitor for unexpected public access on sensitive ports",
                "Use VPC flow logs for network traffic analysis",
                "Implement least privilege access in security groups"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 