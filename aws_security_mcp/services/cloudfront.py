"""CloudFront service client for AWS Security MCP."""

import logging
from typing import Dict, List, Optional, Any, Union

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger(__name__)


def get_cloudfront_client():
    """Get a boto3 CloudFront client."""
    return boto3.client('cloudfront')


def list_distributions(max_items: Union[int, str] = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
    """List CloudFront distributions with pagination support.
    
    Args:
        max_items: Maximum number of distributions to return (can be int or str)
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing distributions and pagination information
        {
            "distributions": [...],  # List of distribution dictionaries
            "next_token": "string",  # Token for next page or None if no more pages
            "is_truncated": bool     # Whether there are more items
        }
    """
    client = get_cloudfront_client()
    distributions = []
    
    try:
        # Convert max_items to int for internal logic
        if isinstance(max_items, str):
            try:
                max_items_int = int(max_items)
            except ValueError:
                logger.warning(f"Invalid max_items value: {max_items}, using default 100")
                max_items_int = 100
        else:
            max_items_int = int(max_items) if max_items is not None else 100
        
        # Set a safe default if conversion failed
        if not isinstance(max_items_int, int):
            max_items_int = 100
        
        # Instead of using paginator, use direct API call
        params = {}
        if next_token:
            params['Marker'] = next_token
        
        # Call the API directly
        response = client.list_distributions(**params)
        distribution_list = response.get('DistributionList', {})
        items = distribution_list.get('Items', [])
        
        if items:
            distributions.extend(items)
        
        # Get pagination info
        is_truncated = distribution_list.get('IsTruncated', False)
        next_marker = distribution_list.get('NextMarker', None) if is_truncated else None
        
        # Return the formatted result directly
        return {
            "distributions": distributions[:max_items_int],
            "next_token": next_marker,
            "is_truncated": is_truncated
        }
        
    except ClientError as e:
        logger.error(f"Error listing CloudFront distributions: {e}")
        return {
            "distributions": [],
            "next_token": None,
            "is_truncated": False
        }
    except Exception as e:
        logger.error(f"Unexpected error listing CloudFront distributions: {e}")
        return {
            "distributions": [],
            "next_token": None,
            "is_truncated": False
        }


def get_distribution(distribution_id: str) -> Dict:
    """Get details for a specific CloudFront distribution.
    
    Args:
        distribution_id: The ID of the distribution
        
    Returns:
        Distribution details dictionary
    """
    client = get_cloudfront_client()
    
    try:
        response = client.get_distribution(Id=distribution_id)
        return response.get('Distribution', {})
    except ClientError as e:
        logger.error(f"Error getting CloudFront distribution {distribution_id}: {e}")
        return {}


def get_distribution_config(distribution_id: str) -> Dict:
    """Get configuration for a specific CloudFront distribution.
    
    Args:
        distribution_id: The ID of the distribution
        
    Returns:
        Distribution configuration dictionary
    """
    client = get_cloudfront_client()
    
    try:
        response = client.get_distribution_config(Id=distribution_id)
        return response.get('DistributionConfig', {})
    except ClientError as e:
        logger.error(f"Error getting CloudFront distribution config {distribution_id}: {e}")
        return {}


def get_distribution_tags(distribution_id: str) -> Dict[str, str]:
    """Get tags for a specific CloudFront distribution.
    
    Args:
        distribution_id: The ID of the distribution
        
    Returns:
        Dictionary of tag key-value pairs
    """
    client = get_cloudfront_client()
    tags = {}
    
    try:
        # Construct the ARN for the distribution
        # CloudFront ARNs have the format: arn:aws:cloudfront::account-id:distribution/distribution-id
        response = client.list_tags_for_resource(Resource=f"arn:aws:cloudfront::{get_account_id()}:distribution/{distribution_id}")
        tag_items = response.get('Tags', {}).get('Items', [])
        
        for tag in tag_items:
            key = tag.get('Key')
            value = tag.get('Value')
            if key and value:
                tags[key] = value
        
        return tags
    except ClientError as e:
        logger.error(f"Error getting CloudFront distribution tags {distribution_id}: {e}")
        return {}


def list_cache_policies(max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
    """List CloudFront cache policies with pagination support.
    
    Args:
        max_items: Maximum number of policies to return
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing policies and pagination information
        {
            "policies": [...],  # List of policy dictionaries
            "next_token": "string",  # Token for next page or None if no more pages
            "is_truncated": bool     # Whether there are more items
        }
    """
    client = get_cloudfront_client()
    policies = []
    
    try:
        # Initial request parameters
        params = {'Type': 'custom', 'MaxItems': str(max_items)}
        
        if next_token:
            params['Marker'] = next_token
            
        response = client.list_cache_policies(**params)
        policy_list = response.get('CachePolicyList', {})
        items = policy_list.get('Items', [])
        policies.extend(items)
        
        # Check if we have more items
        is_truncated = policy_list.get('IsTruncated', False)
        next_marker = policy_list.get('NextMarker')
        
        return {
            "policies": policies,
            "next_token": next_marker if is_truncated else None,
            "is_truncated": is_truncated
        }
    except ClientError as e:
        logger.error(f"Error listing CloudFront cache policies: {e}")
        return {
            "policies": [],
            "next_token": None,
            "is_truncated": False
        }


def list_origin_request_policies(max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
    """List CloudFront origin request policies with pagination support.
    
    Args:
        max_items: Maximum number of policies to return
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing policies and pagination information
        {
            "policies": [...],  # List of policy dictionaries
            "next_token": "string",  # Token for next page or None if no more pages
            "is_truncated": bool     # Whether there are more items
        }
    """
    client = get_cloudfront_client()
    policies = []
    
    try:
        # Initial request parameters
        params = {'Type': 'custom', 'MaxItems': str(max_items)}
        
        if next_token:
            params['Marker'] = next_token
            
        response = client.list_origin_request_policies(**params)
        policy_list = response.get('OriginRequestPolicyList', {})
        items = policy_list.get('Items', [])
        policies.extend(items)
        
        # Check if we have more items
        is_truncated = policy_list.get('IsTruncated', False)
        next_marker = policy_list.get('NextMarker')
        
        return {
            "policies": policies,
            "next_token": next_marker if is_truncated else None,
            "is_truncated": is_truncated
        }
    except ClientError as e:
        logger.error(f"Error listing CloudFront origin request policies: {e}")
        return {
            "policies": [],
            "next_token": None,
            "is_truncated": False
        }


def get_account_id() -> str:
    """Get the current AWS account ID.
    
    Returns:
        AWS account ID string
    """
    try:
        return boto3.client('sts').get_caller_identity().get('Account', '')
    except ClientError as e:
        logger.error(f"Error getting AWS account ID: {e}")
        return ''


def get_all_distributions(max_items: Union[int, str] = '100', next_token: Optional[str] = None) -> Dict[str, Any]:
    """Compatibility wrapper for list_distributions.
    
    Args:
        max_items: Maximum number of distributions to return (as string or int)
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing distributions and pagination information
    """
    # Pass the parameters directly, list_distributions now handles type conversion internally
    return list_distributions(max_items=max_items, next_token=next_token)


def get_cache_policy(policy_id: str) -> Dict:
    """Get details for a specific CloudFront cache policy.
    
    Args:
        policy_id: The ID of the cache policy
        
    Returns:
        Cache policy details dictionary
    """
    client = get_cloudfront_client()
    
    try:
        response = client.get_cache_policy(Id=policy_id)
        return response.get('CachePolicy', {})
    except ClientError as e:
        logger.error(f"Error getting CloudFront cache policy {policy_id}: {e}")
        return {}


def get_origin_request_policy(policy_id: str) -> Dict:
    """Get details for a specific CloudFront origin request policy.
    
    Args:
        policy_id: The ID of the origin request policy
        
    Returns:
        Origin request policy details dictionary
    """
    client = get_cloudfront_client()
    
    try:
        response = client.get_origin_request_policy(Id=policy_id)
        return response.get('OriginRequestPolicy', {})
    except ClientError as e:
        logger.error(f"Error getting CloudFront origin request policy {policy_id}: {e}")
        return {}


def list_response_headers_policies(max_items: Union[int, str] = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
    """List CloudFront response headers policies with pagination support.
    
    Args:
        max_items: Maximum number of policies to return (can be int or str)
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing policies and pagination information
        {
            "policies": [...],  # List of policy dictionaries
            "next_token": "string",  # Token for next page or None if no more pages
            "is_truncated": bool     # Whether there are more items
        }
    """
    client = get_cloudfront_client()
    policies = []
    
    try:
        # Convert max_items to string as expected by the API
        max_items_str = str(max_items)
        
        # Initial request parameters
        params = {'Type': 'custom', 'MaxItems': max_items_str}
        
        if next_token:
            params['Marker'] = next_token
            
        response = client.list_response_headers_policies(**params)
        policy_list = response.get('ResponseHeadersPolicyList', {})
        items = policy_list.get('Items', [])
        policies.extend(items)
        
        # Check if we have more items
        is_truncated = policy_list.get('IsTruncated', False)
        next_marker = policy_list.get('NextMarker')
        
        return {
            "policies": policies,
            "next_token": next_marker if is_truncated else None,
            "is_truncated": is_truncated
        }
    except ClientError as e:
        logger.error(f"Error listing CloudFront response headers policies: {e}")
        return {
            "policies": [],
            "next_token": None,
            "is_truncated": False
        }


def get_response_headers_policy(policy_id: str) -> Dict:
    """Get details for a specific CloudFront response headers policy.
    
    Args:
        policy_id: The ID of the response headers policy
        
    Returns:
        Response headers policy details dictionary
    """
    client = get_cloudfront_client()
    
    try:
        response = client.get_response_headers_policy(Id=policy_id)
        return response.get('ResponseHeadersPolicy', {})
    except ClientError as e:
        logger.error(f"Error getting CloudFront response headers policy {policy_id}: {e}")
        return {}


def search_distribution(identifier: str) -> Dict[str, Any]:
    """Search for a CloudFront distribution by domain name, ID, or alias.
    
    Args:
        identifier: CloudFront domain name (e.g., d1234abcdef8ghi.cloudfront.net),
                  distribution ID, or alias domain
        
    Returns:
        Dictionary containing the distribution details if found, empty dict otherwise
    """
    client = get_cloudfront_client()
    
    try:
        # First try: if the identifier is a distribution ID, get it directly
        if identifier.startswith('E'):  # CloudFront distribution IDs start with 'E'
            try:
                response = client.get_distribution(Id=identifier)
                return response.get('Distribution', {})
            except ClientError as e:
                if 'NoSuchDistribution' not in str(e):
                    logger.error(f"Error getting CloudFront distribution by ID {identifier}: {e}")
        
        # Second try: paginate through all distributions and check domain names and aliases
        paginator = client.get_paginator('list_distributions')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            distribution_list = page.get('DistributionList', {})
            distributions = distribution_list.get('Items', [])
            
            for distribution in distributions:
                # Check if domain name matches
                if distribution.get('DomainName') == identifier:
                    # We found a match by domain name, return complete distribution details
                    return get_distribution(distribution.get('Id'))
                
                # Check if any alias matches
                aliases = distribution.get('Aliases', {}).get('Items', [])
                if identifier in aliases:
                    # We found a match by alias, return complete distribution details
                    return get_distribution(distribution.get('Id'))
        
        # Not found
        logger.info(f"No CloudFront distribution found with identifier: {identifier}")
        return {}
    except ClientError as e:
        logger.error(f"Error searching CloudFront distributions: {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error searching CloudFront distributions: {e}")
        return {} 