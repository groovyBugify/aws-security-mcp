"""Formatters for AWS WAF resources.

This module provides JSON-based formatting functions for AWS WAF resources
to make them more suitable for API responses and LLM consumption.
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime


def format_waf_web_acl_json(web_acl: Dict[str, Any], scope: str = 'REGIONAL') -> Dict[str, Any]:
    """Format a WAF Web ACL into structured data for JSON output.
    
    Args:
        web_acl: WAF Web ACL data dictionary
        scope: The scope of the Web ACL ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        Dictionary with formatted WAF Web ACL data
    """
    # Get creation time and format it
    creation_time = web_acl.get('CreatedTime')
    if isinstance(creation_time, datetime):
        creation_time = creation_time.isoformat()
    
    # Format rules
    rules = []
    for rule in web_acl.get('Rules', []):
        rules.append({
            "name": rule.get('Name', 'Unknown'),
            "priority": rule.get('Priority'),
            "action": rule.get('Action', {}).get('Block') and 'Block' or rule.get('Action', {}).get('Allow') and 'Allow' or 'Count',
            "statement_type": get_statement_type(rule.get('Statement', {})),
            "visibility_config": {
                "sampled_requests_enabled": rule.get('VisibilityConfig', {}).get('SampledRequestsEnabled', False),
                "cloud_watch_metrics_enabled": rule.get('VisibilityConfig', {}).get('CloudWatchMetricsEnabled', False),
                "metric_name": rule.get('VisibilityConfig', {}).get('MetricName', '')
            }
        })
    
    # Extract ACL details
    return {
        "id": web_acl.get('Id', 'Unknown'),
        "name": web_acl.get('Name', 'Unknown'),
        "description": web_acl.get('Description', ''),
        "arn": web_acl.get('ARN', 'Unknown'),
        "scope": scope,
        "capacity": web_acl.get('Capacity', 0),
        "default_action": web_acl.get('DefaultAction', {}).get('Block') and 'Block' or 'Allow',
        "rules_count": len(rules),
        "rules": rules,
        "visibility_config": {
            "sampled_requests_enabled": web_acl.get('VisibilityConfig', {}).get('SampledRequestsEnabled', False),
            "cloud_watch_metrics_enabled": web_acl.get('VisibilityConfig', {}).get('CloudWatchMetricsEnabled', False),
            "metric_name": web_acl.get('VisibilityConfig', {}).get('MetricName', '')
        },
        "creation_time": creation_time,
        "last_modified_time": web_acl.get('LastModifiedTime').isoformat() if isinstance(web_acl.get('LastModifiedTime'), datetime) else web_acl.get('LastModifiedTime')
    }


def format_waf_ip_set_json(ip_set: Dict[str, Any], scope: str = 'REGIONAL') -> Dict[str, Any]:
    """Format a WAF IP set into structured data for JSON output.
    
    Args:
        ip_set: WAF IP set data dictionary
        scope: The scope of the IP set ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        Dictionary with formatted WAF IP set data
    """
    # Get creation time and format it
    creation_time = ip_set.get('CreatedTime')
    if isinstance(creation_time, datetime):
        creation_time = creation_time.isoformat()
    
    return {
        "id": ip_set.get('Id', 'Unknown'),
        "name": ip_set.get('Name', 'Unknown'),
        "description": ip_set.get('Description', ''),
        "arn": ip_set.get('ARN', 'Unknown'),
        "scope": scope,
        "ip_address_version": ip_set.get('IPAddressVersion', 'Unknown'),
        "addresses": ip_set.get('Addresses', []),
        "addresses_count": len(ip_set.get('Addresses', [])),
        "creation_time": creation_time,
        "last_modified_time": ip_set.get('LastModifiedTime').isoformat() if isinstance(ip_set.get('LastModifiedTime'), datetime) else ip_set.get('LastModifiedTime')
    }


def format_waf_rule_group_json(rule_group: Dict[str, Any], scope: str = 'REGIONAL') -> Dict[str, Any]:
    """Format a WAF rule group into structured data for JSON output.
    
    Args:
        rule_group: WAF rule group data dictionary
        scope: The scope of the rule group ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        Dictionary with formatted WAF rule group data
    """
    # Get creation time and format it
    creation_time = rule_group.get('CreatedTime')
    if isinstance(creation_time, datetime):
        creation_time = creation_time.isoformat()
    
    # Format rules
    rules = []
    for rule in rule_group.get('Rules', []):
        rules.append({
            "name": rule.get('Name', 'Unknown'),
            "priority": rule.get('Priority'),
            "action": rule.get('Action', {}).get('Block') and 'Block' or rule.get('Action', {}).get('Allow') and 'Allow' or 'Count',
            "statement_type": get_statement_type(rule.get('Statement', {})),
            "visibility_config": {
                "sampled_requests_enabled": rule.get('VisibilityConfig', {}).get('SampledRequestsEnabled', False),
                "cloud_watch_metrics_enabled": rule.get('VisibilityConfig', {}).get('CloudWatchMetricsEnabled', False),
                "metric_name": rule.get('VisibilityConfig', {}).get('MetricName', '')
            }
        })
    
    return {
        "id": rule_group.get('Id', 'Unknown'),
        "name": rule_group.get('Name', 'Unknown'),
        "description": rule_group.get('Description', ''),
        "arn": rule_group.get('ARN', 'Unknown'),
        "scope": scope,
        "capacity": rule_group.get('Capacity', 0),
        "rules_count": len(rules),
        "rules": rules,
        "visibility_config": {
            "sampled_requests_enabled": rule_group.get('VisibilityConfig', {}).get('SampledRequestsEnabled', False),
            "cloud_watch_metrics_enabled": rule_group.get('VisibilityConfig', {}).get('CloudWatchMetricsEnabled', False),
            "metric_name": rule_group.get('VisibilityConfig', {}).get('MetricName', '')
        },
        "creation_time": creation_time,
        "last_modified_time": rule_group.get('LastModifiedTime').isoformat() if isinstance(rule_group.get('LastModifiedTime'), datetime) else rule_group.get('LastModifiedTime')
    }


def format_waf_web_acl_summary_json(web_acl: Dict[str, Any], scope: str = 'REGIONAL') -> Dict[str, Any]:
    """Format a WAF Web ACL summary into structured data for JSON output.
    
    Args:
        web_acl: WAF Web ACL summary data dictionary
        scope: The scope of the Web ACL ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        Dictionary with formatted WAF Web ACL summary data
    """
    return {
        "id": web_acl.get('Id', 'Unknown'),
        "name": web_acl.get('Name', 'Unknown'),
        "description": web_acl.get('Description', ''),
        "arn": web_acl.get('ARN', 'Unknown'),
        "scope": scope,
        "lock_token": web_acl.get('LockToken', 'Unknown')
    }


def format_waf_ip_set_summary_json(ip_set: Dict[str, Any], scope: str = 'REGIONAL') -> Dict[str, Any]:
    """Format a WAF IP set summary into structured data for JSON output.
    
    Args:
        ip_set: WAF IP set summary data dictionary
        scope: The scope of the IP set ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        Dictionary with formatted WAF IP set summary data
    """
    return {
        "id": ip_set.get('Id', 'Unknown'),
        "name": ip_set.get('Name', 'Unknown'),
        "description": ip_set.get('Description', ''),
        "arn": ip_set.get('ARN', 'Unknown'),
        "scope": scope,
        "lock_token": ip_set.get('LockToken', 'Unknown')
    }


def format_waf_rule_group_summary_json(rule_group: Dict[str, Any], scope: str = 'REGIONAL') -> Dict[str, Any]:
    """Format a WAF rule group summary into structured data for JSON output.
    
    Args:
        rule_group: WAF rule group summary data dictionary
        scope: The scope of the rule group ('REGIONAL' or 'CLOUDFRONT')
        
    Returns:
        Dictionary with formatted WAF rule group summary data
    """
    return {
        "id": rule_group.get('Id', 'Unknown'),
        "name": rule_group.get('Name', 'Unknown'),
        "description": rule_group.get('Description', ''),
        "arn": rule_group.get('ARN', 'Unknown'),
        "scope": scope,
        "lock_token": rule_group.get('LockToken', 'Unknown')
    }


def format_waf_resources_json(resource_arns: List[str], web_acl_arn: str) -> Dict[str, Any]:
    """Format a list of resource ARNs protected by a WAF Web ACL into structured data for JSON output.
    
    Args:
        resource_arns: List of resource ARNs protected by the Web ACL
        web_acl_arn: The ARN of the Web ACL
        
    Returns:
        Dictionary with formatted WAF resources data
    """
    # Parse resource information from ARNs
    resources = []
    for arn in resource_arns:
        arn_parts = arn.split(':')
        
        service = arn_parts[2] if len(arn_parts) > 2 else 'unknown'
        region = arn_parts[3] if len(arn_parts) > 3 else 'unknown'
        account_id = arn_parts[4] if len(arn_parts) > 4 else 'unknown'
        
        resource_parts = arn_parts[5].split('/') if len(arn_parts) > 5 else []
        resource_type = resource_parts[0] if resource_parts else 'unknown'
        resource_id = '/'.join(resource_parts[1:]) if len(resource_parts) > 1 else ''
        
        resources.append({
            "arn": arn,
            "service": service,
            "region": region,
            "account_id": account_id,
            "resource_type": resource_type,
            "resource_id": resource_id
        })
    
    return {
        "web_acl_arn": web_acl_arn,
        "resource_count": len(resources),
        "resources": resources
    }


def get_statement_type(statement: Dict[str, Any]) -> str:
    """Helper function to determine the type of a WAF rule statement.
    
    Args:
        statement: WAF rule statement dictionary
        
    Returns:
        String indicating the statement type
    """
    statement_keys = statement.keys()
    
    # Check for common statement types
    if 'RateBasedStatement' in statement_keys:
        return 'Rate-based'
    elif 'ByteMatchStatement' in statement_keys:
        return 'Byte match'
    elif 'SqliMatchStatement' in statement_keys:
        return 'SQL injection'
    elif 'XssMatchStatement' in statement_keys:
        return 'XSS'
    elif 'GeoMatchStatement' in statement_keys:
        return 'Geo match'
    elif 'IPSetReferenceStatement' in statement_keys:
        return 'IP set'
    elif 'RegexPatternSetReferenceStatement' in statement_keys:
        return 'Regex pattern'
    elif 'AndStatement' in statement_keys:
        return 'AND'
    elif 'OrStatement' in statement_keys:
        return 'OR'
    elif 'NotStatement' in statement_keys:
        return 'NOT'
    elif 'ManagedRuleGroupStatement' in statement_keys:
        return 'Managed rule group'
    elif 'RuleGroupReferenceStatement' in statement_keys:
        return 'Rule group'
    else:
        return 'Unknown' 