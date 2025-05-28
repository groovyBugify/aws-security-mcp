"""WAF service module for AWS Security MCP."""

import logging
from typing import Any, Dict, List, Optional, Union

from botocore.exceptions import ClientError

from aws_security_mcp.services.base import get_client, handle_aws_error, handle_pagination

# Configure logging
logger = logging.getLogger(__name__)

def get_waf_client(session_context: Optional[str] = None, **kwargs: Any) -> any:
    """Get AWS WAF (Classic) client.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized WAF client
    """
    return get_client('waf', session_context=session_context, **kwargs)

def get_wafv2_client(session_context: Optional[str] = None, **kwargs: Any) -> any:
    """Get AWS WAFv2 client.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized WAFv2 client
    """
    return get_client('wafv2', session_context=session_context, **kwargs)

async def list_web_acls(scope: str = 'REGIONAL', max_items: int = 100, next_marker: Optional[str] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List WAFv2 Web ACLs.

    Args:
        scope: The scope of the Web ACL. Valid values are 'REGIONAL' or 'CLOUDFRONT'
        max_items: Maximum number of Web ACLs to return
        next_marker: Token for pagination
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing Web ACLs and pagination information
    """
    try:
        client = get_wafv2_client(session_context=session_context)
        
        params = {
            'Scope': scope,
            'Limit': min(max_items, 100)  # API maximum is 100
        }
        
        if next_marker:
            params['NextMarker'] = next_marker
            
        response = client.list_web_acls(**params)
        
        return {
            'web_acls': response.get('WebACLs', []),
            'next_marker': response.get('NextMarker'),
            'has_more': bool(response.get('NextMarker'))
        }
    except ClientError as e:
        logger.error(f"Error listing WAFv2 Web ACLs: {e}")
        raise

async def list_ip_sets(scope: str = 'REGIONAL', max_items: int = 100, next_marker: Optional[str] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List WAFv2 IP sets.

    Args:
        scope: The scope of the IP set. Valid values are 'REGIONAL' or 'CLOUDFRONT'
        max_items: Maximum number of IP sets to return
        next_marker: Token for pagination
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing IP sets and pagination information
    """
    try:
        client = get_wafv2_client(session_context=session_context)
        
        params = {
            'Scope': scope,
            'Limit': min(max_items, 100)  # API maximum is 100
        }
        
        if next_marker:
            params['NextMarker'] = next_marker
            
        response = client.list_ip_sets(**params)
        
        return {
            'ip_sets': response.get('IPSets', []),
            'next_marker': response.get('NextMarker'),
            'has_more': bool(response.get('NextMarker'))
        }
    except ClientError as e:
        logger.error(f"Error listing WAFv2 IP sets: {e}")
        raise

async def list_rule_groups(scope: str = 'REGIONAL', max_items: int = 100, next_marker: Optional[str] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List WAFv2 rule groups.

    Args:
        scope: The scope of the rule group. Valid values are 'REGIONAL' or 'CLOUDFRONT'
        max_items: Maximum number of rule groups to return
        next_marker: Token for pagination
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing rule groups and pagination information
    """
    try:
        client = get_wafv2_client(session_context=session_context)
        
        params = {
            'Scope': scope,
            'Limit': min(max_items, 100)  # API maximum is 100
        }
        
        if next_marker:
            params['NextMarker'] = next_marker
            
        response = client.list_rule_groups(**params)
        
        return {
            'rule_groups': response.get('RuleGroups', []),
            'next_marker': response.get('NextMarker'),
            'has_more': bool(response.get('NextMarker'))
        }
    except ClientError as e:
        logger.error(f"Error listing WAFv2 rule groups: {e}")
        raise

async def get_web_acl(web_acl_id: Optional[str] = None, web_acl_name: Optional[str] = None, web_acl_arn: Optional[str] = None, scope: str = 'REGIONAL', session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get details of a specific WAFv2 Web ACL.

    Args:
        web_acl_id: The ID of the Web ACL (optional if ARN is provided)
        web_acl_name: The name of the Web ACL (optional if ARN is provided)
        web_acl_arn: The ARN of the Web ACL (alternative to ID/name)
        scope: The scope of the Web ACL. Valid values are 'REGIONAL' or 'CLOUDFRONT'
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing detailed Web ACL information
        
    Raises:
        ValueError: If neither ARN nor both ID and name are provided
    """
    try:
        client = get_wafv2_client(session_context=session_context)
        
        # Build parameters based on what's provided
        params = {'Scope': scope}
        
        if web_acl_arn:
            params['ARN'] = web_acl_arn
        elif web_acl_id and web_acl_name:
            params['Id'] = web_acl_id
            params['Name'] = web_acl_name
        else:
            raise ValueError("Either web_acl_arn must be provided, or both web_acl_id and web_acl_name must be provided")
        
        response = client.get_web_acl(**params)
        return response.get('WebACL', {})
    except ClientError as e:
        logger.error(f"Error getting WAFv2 Web ACL: {e}")
        raise

async def get_ip_set(ip_set_id: Optional[str] = None, ip_set_name: Optional[str] = None, ip_set_arn: Optional[str] = None, scope: str = 'REGIONAL', session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get details of a specific WAFv2 IP set.

    Args:
        ip_set_id: The ID of the IP set (optional if ARN is provided)
        ip_set_name: The name of the IP set (optional if ARN is provided)
        ip_set_arn: The ARN of the IP set (alternative to ID/name)
        scope: The scope of the IP set. Valid values are 'REGIONAL' or 'CLOUDFRONT'
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing detailed IP set information
        
    Raises:
        ValueError: If neither ARN nor both ID and name are provided
    """
    try:
        client = get_wafv2_client(session_context=session_context)
        
        # Build parameters based on what's provided
        params = {'Scope': scope}
        
        if ip_set_arn:
            params['ARN'] = ip_set_arn
        elif ip_set_id and ip_set_name:
            params['Id'] = ip_set_id
            params['Name'] = ip_set_name
        else:
            raise ValueError("Either ip_set_arn must be provided, or both ip_set_id and ip_set_name must be provided")
        
        response = client.get_ip_set(**params)
        return response.get('IPSet', {})
    except ClientError as e:
        logger.error(f"Error getting WAFv2 IP set: {e}")
        raise

async def get_rule_group(rule_group_id: Optional[str] = None, rule_group_name: Optional[str] = None, rule_group_arn: Optional[str] = None, scope: str = 'REGIONAL', session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get details of a specific WAFv2 rule group.

    Args:
        rule_group_id: The ID of the rule group (optional if ARN is provided)
        rule_group_name: The name of the rule group (optional if ARN is provided)
        rule_group_arn: The ARN of the rule group (alternative to ID/name)
        scope: The scope of the rule group. Valid values are 'REGIONAL' or 'CLOUDFRONT'
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing detailed rule group information
        
    Raises:
        ValueError: If neither ARN nor both ID and name are provided
    """
    try:
        client = get_wafv2_client(session_context=session_context)
        
        # Build parameters based on what's provided
        params = {'Scope': scope}
        
        if rule_group_arn:
            params['ARN'] = rule_group_arn
        elif rule_group_id and rule_group_name:
            params['Id'] = rule_group_id
            params['Name'] = rule_group_name
        else:
            raise ValueError("Either rule_group_arn must be provided, or both rule_group_id and rule_group_name must be provided")
        
        response = client.get_rule_group(**params)
        return response.get('RuleGroup', {})
    except ClientError as e:
        logger.error(f"Error getting WAFv2 rule group: {e}")
        raise

async def list_resources_for_web_acl(web_acl_arn: str, resource_type: str = 'APPLICATION_LOAD_BALANCER', session_context: Optional[str] = None) -> List[str]:
    """List resources protected by a WAFv2 Web ACL.

    Args:
        web_acl_arn: The ARN of the Web ACL
        resource_type: The type of resource. Valid values include 'APPLICATION_LOAD_BALANCER', 'API_GATEWAY', 'APPSYNC', etc.
        session_context: Optional session key for cross-account access

    Returns:
        List of resource ARNs associated with the Web ACL
    """
    try:
        client = get_wafv2_client(session_context=session_context)
        
        response = client.list_resources_for_web_acl(
            WebACLArn=web_acl_arn,
            ResourceType=resource_type
        )
        return response.get('ResourceArns', [])
    except ClientError as e:
        logger.error(f"Error listing resources for WAFv2 Web ACL {web_acl_arn}: {e}")
        raise

# Classic WAF methods - these are kept for backward compatibility but are deprecated

async def list_classic_web_acls(max_items: int = 100, next_marker: Optional[str] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List Classic WAF Web ACLs.

    Note: This is a deprecated API. Use WAFv2 methods whenever possible.

    Args:
        max_items: Maximum number of Web ACLs to return
        next_marker: Token for pagination
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing Web ACLs and pagination information
    """
    try:
        client = get_waf_client(session_context=session_context)
        
        params = {
            'Limit': min(max_items, 100)  # API maximum is 100
        }
        
        if next_marker:
            params['NextMarker'] = next_marker
            
        response = client.list_web_acls(**params)
        
        return {
            'web_acls': response.get('WebACLs', []),
            'next_marker': response.get('NextMarker'),
            'has_more': bool(response.get('NextMarker'))
        }
    except ClientError as e:
        logger.error(f"Error listing Classic WAF Web ACLs: {e}")
        raise

async def get_classic_web_acl(web_acl_id: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get details of a specific Classic WAF Web ACL.

    Note: This is a deprecated API. Use WAFv2 methods whenever possible.

    Args:
        web_acl_id: The ID of the Web ACL
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing detailed Web ACL information
    """
    try:
        client = get_waf_client(session_context=session_context)
        
        response = client.get_web_acl(
            WebACLId=web_acl_id
        )
        return response.get('WebACL', {})
    except ClientError as e:
        logger.error(f"Error getting Classic WAF Web ACL {web_acl_id}: {e}")
        raise 