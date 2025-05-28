"""Tools for working with AWS WAF.

This module provides tools for retrieving and analyzing AWS WAF resources,
including Web ACLs, IP sets, and rule groups for both WAFv2 and Classic WAF.
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
from aws_security_mcp.services import waf
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
async def list_waf_web_acls(
    scope: str = 'REGIONAL',
    limit: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List AWS WAF Web ACLs.
    
    Args:
        scope: The scope of the Web ACLs to retrieve ('REGIONAL' or 'CLOUDFRONT')
        limit: Maximum number of Web ACLs to return
        next_token: Pagination token for fetching the next set of Web ACLs
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with Web ACL information
    """
    logger.info(f"Listing WAF Web ACLs with scope: {scope}, limit: {limit}")
    
    result = await waf.list_web_acls(
        scope=scope,
        max_items=limit,
        next_marker=next_token,
        session_context=session_context
    )
    
    # Format the response
    formatted_web_acls = []
    for web_acl in result.get('web_acls', []):
        formatted_web_acls.append(format_waf_web_acl_summary_json(web_acl))
    
    return {
        "web_acls": formatted_web_acls,
        "next_token": result.get('next_marker'),
        "has_more": result.get('has_more', False),
        "total_count": len(formatted_web_acls)
    }


@register_tool()
async def get_waf_web_acl_details(
    web_acl_id: str,
    web_acl_name: str,
    scope: str = 'REGIONAL',
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get detailed information about a specific WAF Web ACL.
    
    Args:
        web_acl_id: The ID of the Web ACL
        web_acl_name: The name of the Web ACL
        scope: The scope of the Web ACL ('REGIONAL' or 'CLOUDFRONT')
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with detailed Web ACL information
    """
    logger.info(f"Getting WAF Web ACL details for: {web_acl_name} ({web_acl_id})")
    
    web_acl = await waf.get_web_acl(
        web_acl_id=web_acl_id,
        web_acl_name=web_acl_name,
        scope=scope,
        session_context=session_context
    )
    
    return format_waf_web_acl_json(web_acl)


@register_tool()
async def list_waf_ip_sets(
    scope: str = 'REGIONAL',
    limit: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List AWS WAF IP sets.
    
    Args:
        scope: The scope of the IP sets to retrieve ('REGIONAL' or 'CLOUDFRONT')
        limit: Maximum number of IP sets to return
        next_token: Pagination token for fetching the next set of IP sets
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with IP set information
    """
    logger.info(f"Listing WAF IP sets with scope: {scope}, limit: {limit}")
    
    result = await waf.list_ip_sets(
        scope=scope,
        max_items=limit,
        next_marker=next_token,
        session_context=session_context
    )
    
    # Format the response
    formatted_ip_sets = []
    for ip_set in result.get('ip_sets', []):
        formatted_ip_sets.append(format_waf_ip_set_json(ip_set))
    
    return {
        "ip_sets": formatted_ip_sets,
        "next_token": result.get('next_marker'),
        "has_more": result.get('has_more', False),
        "total_count": len(formatted_ip_sets)
    }


@register_tool()
async def get_waf_ip_set_details(
    ip_set_id: str,
    ip_set_name: str,
    scope: str = 'REGIONAL',
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get detailed information about a specific WAF IP set.
    
    Args:
        ip_set_id: The ID of the IP set
        ip_set_name: The name of the IP set
        scope: The scope of the IP set ('REGIONAL' or 'CLOUDFRONT')
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with detailed IP set information
    """
    logger.info(f"Getting WAF IP set details for: {ip_set_name} ({ip_set_id})")
    
    ip_set = await waf.get_ip_set(
        ip_set_id=ip_set_id,
        ip_set_name=ip_set_name,
        scope=scope,
        session_context=session_context
    )
    
    return format_waf_ip_set_json(ip_set)


@register_tool()
async def list_waf_rule_groups(
    scope: str = 'REGIONAL',
    limit: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List AWS WAF rule groups.
    
    Args:
        scope: The scope of the rule groups to retrieve ('REGIONAL' or 'CLOUDFRONT')
        limit: Maximum number of rule groups to return
        next_token: Pagination token for fetching the next set of rule groups
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with rule group information
    """
    logger.info(f"Listing WAF rule groups with scope: {scope}, limit: {limit}")
    
    result = await waf.list_rule_groups(
        scope=scope,
        max_items=limit,
        next_marker=next_token,
        session_context=session_context
    )
    
    # Format the response
    formatted_rule_groups = []
    for rule_group in result.get('rule_groups', []):
        formatted_rule_groups.append(format_waf_rule_group_json(rule_group))
    
    return {
        "rule_groups": formatted_rule_groups,
        "next_token": result.get('next_marker'),
        "has_more": result.get('has_more', False),
        "total_count": len(formatted_rule_groups)
    }


@register_tool()
async def get_waf_rule_group_details(
    rule_group_id: str,
    rule_group_name: str,
    scope: str = 'REGIONAL',
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get detailed information about a specific WAF rule group.
    
    Args:
        rule_group_id: The ID of the rule group
        rule_group_name: The name of the rule group
        scope: The scope of the rule group ('REGIONAL' or 'CLOUDFRONT')
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with detailed rule group information
    """
    logger.info(f"Getting WAF rule group details for: {rule_group_name} ({rule_group_id})")
    
    rule_group = await waf.get_rule_group(
        rule_group_id=rule_group_id,
        rule_group_name=rule_group_name,
        scope=scope,
        session_context=session_context
    )
    
    return format_waf_rule_group_json(rule_group)


@register_tool()
async def list_waf_protected_resources(
    web_acl_arn: str,
    resource_type: str = 'APPLICATION_LOAD_BALANCER',
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List resources protected by a WAF Web ACL.
    
    Args:
        web_acl_arn: The ARN of the Web ACL
        resource_type: The type of resource to list ('APPLICATION_LOAD_BALANCER', 'API_GATEWAY', etc.)
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with protected resource information
    """
    logger.info(f"Listing protected resources for Web ACL: {web_acl_arn}")
    
    resource_arns = await waf.list_resources_for_web_acl(
        web_acl_arn=web_acl_arn,
        resource_type=resource_type,
        session_context=session_context
    )
    
    return {
        "web_acl_arn": web_acl_arn,
        "resource_type": resource_type,
        "protected_resources": resource_arns,
        "total_count": len(resource_arns)
    }


# Classic WAF tools (deprecated but kept for backward compatibility)

@register_tool()
async def list_classic_waf_web_acls(
    limit: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List Classic WAF Web ACLs (deprecated - use WAFv2 instead).
    
    Args:
        limit: Maximum number of Web ACLs to return
        next_token: Pagination token for fetching the next set of Web ACLs
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with Classic WAF Web ACL information
    """
    logger.warning("Using deprecated Classic WAF API. Consider migrating to WAFv2.")
    logger.info(f"Listing Classic WAF Web ACLs with limit: {limit}")
    
    result = await waf.list_classic_web_acls(
        max_items=limit,
        next_marker=next_token,
        session_context=session_context
    )
    
    return {
        "web_acls": result.get('web_acls', []),
        "next_token": result.get('next_marker'),
        "has_more": result.get('has_more', False),
        "total_count": len(result.get('web_acls', []))
    }

@register_tool()
async def get_classic_waf_web_acl_details(
    web_acl_id: str,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get detailed information about a specific Classic WAF Web ACL (deprecated).
    
    Args:
        web_acl_id: The ID of the Web ACL
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON object with detailed Classic WAF Web ACL information
    """
    logger.warning("Using deprecated Classic WAF API. Consider migrating to WAFv2.")
    logger.info(f"Getting Classic WAF Web ACL details for: {web_acl_id}")
    
    web_acl = await waf.get_classic_web_acl(
        web_acl_id=web_acl_id,
        session_context=session_context
    )
    
    return web_acl 