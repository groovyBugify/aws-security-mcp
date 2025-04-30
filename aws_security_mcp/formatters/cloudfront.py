"""Formatters for CloudFront resources."""

import json
from typing import Any, Dict, List, Optional, Union


def format_distribution(distribution: Dict[str, Any]) -> str:
    """Format a CloudFront distribution into a readable string.
    
    Args:
        distribution: CloudFront distribution data dictionary
        
    Returns:
        Formatted string representation of the distribution
    """
    dist_config = distribution.get('DistributionConfig', {})
    origins = dist_config.get('Origins', {}).get('Items', [])
    
    origins_str = "\n  ".join([f"{o.get('Id', 'Unknown')}: {o.get('DomainName', 'Unknown')}" for o in origins])
    if not origins_str:
        origins_str = "None"
    
    return f"""
Distribution ID: {distribution.get('Id', 'Unknown')}
Domain Name: {distribution.get('DomainName', 'Unknown')}
Status: {distribution.get('Status', 'Unknown')}
Enabled: {'Yes' if dist_config.get('Enabled') else 'No'}
Price Class: {dist_config.get('PriceClass', 'Unknown')}
HTTP Version: {dist_config.get('HttpVersion', 'Unknown')}
Default Root Object: {dist_config.get('DefaultRootObject', 'None')}
Origins:
  {origins_str}
SSL Certificate: {dist_config.get('ViewerCertificate', {}).get('CertificateSource', 'Unknown')}
"""


def format_cache_policy(policy: Dict[str, Any]) -> str:
    """Format a CloudFront cache policy into a readable string.
    
    Args:
        policy: CloudFront cache policy data dictionary
        
    Returns:
        Formatted string representation of the cache policy
    """
    cache_policy_config = policy.get('CachePolicyConfig', {})
    
    return f"""
Cache Policy: {cache_policy_config.get('Name', 'Unknown')}
ID: {policy.get('Id', 'Unknown')}
Min TTL: {cache_policy_config.get('MinTTL', 'Unknown')}
Max TTL: {cache_policy_config.get('MaxTTL', 'Unknown')}
Default TTL: {cache_policy_config.get('DefaultTTL', 'Unknown')}
"""


def format_origin_request_policy(policy: Dict[str, Any]) -> str:
    """Format a CloudFront origin request policy into a readable string.
    
    Args:
        policy: CloudFront origin request policy data dictionary
        
    Returns:
        Formatted string representation of the origin request policy
    """
    policy_config = policy.get('OriginRequestPolicyConfig', {})
    
    return f"""
Origin Request Policy: {policy_config.get('Name', 'Unknown')}
ID: {policy.get('Id', 'Unknown')}
Headers Behavior: {policy_config.get('HeadersConfig', {}).get('HeaderBehavior', 'Unknown')}
Cookies Behavior: {policy_config.get('CookiesConfig', {}).get('CookieBehavior', 'Unknown')}
Query Strings Behavior: {policy_config.get('QueryStringsConfig', {}).get('QueryStringBehavior', 'Unknown')}
""" 