"""Tools for working with AWS WAF.

This module provides tools for retrieving and analyzing AWS WAF resources,
including Web ACLs, IP sets, and rule groups.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union

from aws_security_mcp.formatters.waf import (
    format_waf_web_acl_json,
    format_waf_ip_set_json,
    format_waf_rule_group_json,
    format_waf_web_acl_summary_json,
    format_waf_ip_set_summary_json,
    format_waf_rule_group_summary_json,
    format_waf_resources_json
)
from aws_security_mcp.services.waf import WAFService
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
async def list_waf_web_acls(
    scope: str = 'REGIONAL',
    limit: int = 100,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List AWS WAF Web ACLs.
    
    Args:
        scope: The scope of the Web ACLs to retrieve ('REGIONAL' or 'CLOUDFRONT')
        limit: Maximum number of Web ACLs to return
        next_token: Pagination token for fetching the next set of Web ACLs
        
    Returns:
        JSON object with Web ACL information
    """
    logger.info(f"Listing WAF Web ACLs with scope: {scope}, limit: {limit}")
    
    waf_service = WAFService()
    response = await waf_service.list_web_acls(scope=scope, max_items=limit, next_marker=next_token)
    web_acls = response['web_acls']
    
    # Format the results
    formatted_web_acls = [format_waf_web_acl_summary_json(acl, scope) for acl in web_acls]
    
    result = {
        "scope": scope,
        "total_web_acls": len(web_acls),
        "web_acls": formatted_web_acls,
        "pagination": {
            "has_more": response['has_more'],
            "next_token": response['next_marker']
        }
    }
    
    return result


@register_tool()
async def get_waf_web_acl_details(
    web_acl_id: str,
    web_acl_name: str,
    scope: str = 'REGIONAL'
) -> Dict[str, Any]:
    """Get detailed information about a specific AWS WAF Web ACL.
    
    Args:
        web_acl_id: The ID of the Web ACL
        web_acl_name: The name of the Web ACL
        scope: The scope of the Web ACL ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        JSON object with detailed Web ACL information
    """
    logger.info(f"Getting details for WAF Web ACL: {web_acl_name} ({web_acl_id})")
    
    waf_service = WAFService()
    
    try:
        web_acl = await waf_service.get_web_acl(web_acl_id=web_acl_id, web_acl_name=web_acl_name, scope=scope)
        return format_waf_web_acl_json(web_acl, scope)
    except Exception as e:
        logger.error(f"Error getting WAF Web ACL details: {e}")
        return {
            "error": True,
            "message": f"Error retrieving Web ACL details for '{web_acl_name}': {str(e)}",
            "web_acl_id": web_acl_id,
            "web_acl_name": web_acl_name,
            "scope": scope
        }


@register_tool()
async def list_waf_ip_sets(
    scope: str = 'REGIONAL',
    limit: int = 100,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List AWS WAF IP sets.
    
    Args:
        scope: The scope of the IP sets to retrieve ('REGIONAL' or 'CLOUDFRONT')
        limit: Maximum number of IP sets to return
        next_token: Pagination token for fetching the next set of IP sets
        
    Returns:
        JSON object with IP set information
    """
    logger.info(f"Listing WAF IP sets with scope: {scope}, limit: {limit}")
    
    waf_service = WAFService()
    response = await waf_service.list_ip_sets(scope=scope, max_items=limit, next_marker=next_token)
    ip_sets = response['ip_sets']
    
    # Format the results
    formatted_ip_sets = [format_waf_ip_set_summary_json(ip_set, scope) for ip_set in ip_sets]
    
    result = {
        "scope": scope,
        "total_ip_sets": len(ip_sets),
        "ip_sets": formatted_ip_sets,
        "pagination": {
            "has_more": response['has_more'],
            "next_token": response['next_marker']
        }
    }
    
    return result


@register_tool()
async def get_waf_ip_set_details(
    ip_set_id: str,
    ip_set_name: str,
    scope: str = 'REGIONAL'
) -> Dict[str, Any]:
    """Get detailed information about a specific AWS WAF IP set.
    
    Args:
        ip_set_id: The ID of the IP set
        ip_set_name: The name of the IP set
        scope: The scope of the IP set ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        JSON object with detailed IP set information
    """
    logger.info(f"Getting details for WAF IP set: {ip_set_name} ({ip_set_id})")
    
    waf_service = WAFService()
    
    try:
        ip_set = await waf_service.get_ip_set(ip_set_id=ip_set_id, ip_set_name=ip_set_name, scope=scope)
        return format_waf_ip_set_json(ip_set, scope)
    except Exception as e:
        logger.error(f"Error getting WAF IP set details: {e}")
        return {
            "error": True,
            "message": f"Error retrieving IP set details for '{ip_set_name}': {str(e)}",
            "ip_set_id": ip_set_id,
            "ip_set_name": ip_set_name,
            "scope": scope
        }


@register_tool()
async def list_waf_rule_groups(
    scope: str = 'REGIONAL',
    limit: int = 100,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List AWS WAF rule groups.
    
    Args:
        scope: The scope of the rule groups to retrieve ('REGIONAL' or 'CLOUDFRONT')
        limit: Maximum number of rule groups to return
        next_token: Pagination token for fetching the next set of rule groups
        
    Returns:
        JSON object with rule group information
    """
    logger.info(f"Listing WAF rule groups with scope: {scope}, limit: {limit}")
    
    waf_service = WAFService()
    response = await waf_service.list_rule_groups(scope=scope, max_items=limit, next_marker=next_token)
    rule_groups = response['rule_groups']
    
    # Format the results
    formatted_rule_groups = [format_waf_rule_group_summary_json(rule_group, scope) for rule_group in rule_groups]
    
    result = {
        "scope": scope,
        "total_rule_groups": len(rule_groups),
        "rule_groups": formatted_rule_groups,
        "pagination": {
            "has_more": response['has_more'],
            "next_token": response['next_marker']
        }
    }
    
    return result


@register_tool()
async def get_waf_rule_group_details(
    rule_group_id: str,
    rule_group_name: str,
    scope: str = 'REGIONAL'
) -> Dict[str, Any]:
    """Get detailed information about a specific AWS WAF rule group.
    
    Args:
        rule_group_id: The ID of the rule group
        rule_group_name: The name of the rule group
        scope: The scope of the rule group ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        JSON object with detailed rule group information
    """
    logger.info(f"Getting details for WAF rule group: {rule_group_name} ({rule_group_id})")
    
    waf_service = WAFService()
    
    try:
        rule_group = await waf_service.get_rule_group(rule_group_id=rule_group_id, rule_group_name=rule_group_name, scope=scope)
        return format_waf_rule_group_json(rule_group, scope)
    except Exception as e:
        logger.error(f"Error getting WAF rule group details: {e}")
        return {
            "error": True,
            "message": f"Error retrieving rule group details for '{rule_group_name}': {str(e)}",
            "rule_group_id": rule_group_id,
            "rule_group_name": rule_group_name,
            "scope": scope
        }


@register_tool()
async def list_waf_resources_for_web_acl(
    web_acl_arn: str,
    resource_type: str = 'APPLICATION_LOAD_BALANCER'
) -> Dict[str, Any]:
    """List resources protected by a specific AWS WAF Web ACL.
    
    Args:
        web_acl_arn: The ARN of the Web ACL
        resource_type: The type of resource (e.g., 'APPLICATION_LOAD_BALANCER', 'API_GATEWAY')
        
    Returns:
        JSON object with resources protected by the Web ACL
    """
    logger.info(f"Listing resources for WAF Web ACL: {web_acl_arn}")
    
    waf_service = WAFService()
    
    try:
        resource_arns = await waf_service.list_resources_for_web_acl(web_acl_arn=web_acl_arn, resource_type=resource_type)
        return format_waf_resources_json(resource_arns, web_acl_arn)
    except Exception as e:
        logger.error(f"Error listing resources for WAF Web ACL: {e}")
        return {
            "error": True,
            "message": f"Error retrieving resources for Web ACL '{web_acl_arn}': {str(e)}",
            "web_acl_arn": web_acl_arn,
            "resource_type": resource_type
        }


@register_tool()
async def list_all_waf_components(scope: str = 'REGIONAL', limit: int = 100) -> Dict[str, Any]:
    """List all AWS WAF components (Web ACLs, IP sets, and rule groups).
    
    Args:
        scope: The scope of the components to retrieve ('REGIONAL' or 'CLOUDFRONT')
        limit: Maximum number of each component type to return
        
    Returns:
        JSON object with comprehensive WAF component information
    """
    logger.info(f"Listing all WAF components with scope: {scope}, limit: {limit}")
    
    waf_service = WAFService()
    
    # Get Web ACLs
    web_acls_response = await waf_service.list_web_acls(scope=scope, max_items=limit)
    formatted_web_acls = [format_waf_web_acl_summary_json(acl, scope) for acl in web_acls_response['web_acls']]
    
    # Get IP sets
    ip_sets_response = await waf_service.list_ip_sets(scope=scope, max_items=limit)
    formatted_ip_sets = [format_waf_ip_set_summary_json(ip_set, scope) for ip_set in ip_sets_response['ip_sets']]
    
    # Get rule groups
    rule_groups_response = await waf_service.list_rule_groups(scope=scope, max_items=limit)
    formatted_rule_groups = [format_waf_rule_group_summary_json(rule_group, scope) for rule_group in rule_groups_response['rule_groups']]
    
    result = {
        "scope": scope,
        "web_acls": {
            "total": len(formatted_web_acls),
            "items": formatted_web_acls,
            "has_more": web_acls_response['has_more']
        },
        "ip_sets": {
            "total": len(formatted_ip_sets),
            "items": formatted_ip_sets,
            "has_more": ip_sets_response['has_more']
        },
        "rule_groups": {
            "total": len(formatted_rule_groups),
            "items": formatted_rule_groups,
            "has_more": rule_groups_response['has_more']
        },
        "total_components": len(formatted_web_acls) + len(formatted_ip_sets) + len(formatted_rule_groups)
    }
    
    return result 