"""Helper utilities for AWS Security MCP."""

import logging
from typing import Any, Dict, List, Optional, Union, Callable

# Configure logging
logger = logging.getLogger(__name__)

def paginate_aws_response(
    client: Any,
    method_name: str,
    max_items: int = 1000,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Paginate through AWS responses that support pagination.
    
    Args:
        client: Boto3 client
        method_name: API method name to call
        max_items: Maximum number of items to retrieve
        **kwargs: Additional arguments to pass to the API method
        
    Returns:
        List of items from all pages
    """
    # Get the paginator for the specified method
    paginator = client.get_paginator(method_name)
    
    # Create page iterator with provided parameters
    page_iterator = paginator.paginate(**kwargs)
    
    results = []
    item_count = 0
    
    # Extract common result keys based on service and method
    result_key = get_result_key(method_name)
    
    # Process each page of results
    for page in page_iterator:
        if result_key in page:
            items = page[result_key]
            # Add items up to max_items limit
            results.extend(items[:max_items - item_count])
            item_count += len(items)
            
            # Break if we've reached the maximum
            if item_count >= max_items:
                break
    
    return results

def get_result_key(method_name: str) -> str:
    """Get the result key for a specific AWS API method.
    
    Maps AWS API method names to their corresponding result keys.
    
    Args:
        method_name: The AWS API method name
        
    Returns:
        The result key for the method
    """
    # Common mapping of method names to result keys
    result_keys = {
        # GuardDuty
        "list_findings": "FindingIds",
        "list_detectors": "DetectorIds",
        
        # SecurityHub
        "get_findings": "Findings",
        
        # IAM
        "list_roles": "Roles",
        "list_users": "Users",
        "list_policies": "Policies",
        "list_access_keys": "AccessKeyMetadata",
        
        # EC2
        "describe_instances": "Reservations",
        "describe_security_groups": "SecurityGroups",
        "describe_vpcs": "Vpcs",
        "describe_route_tables": "RouteTables",
        "describe_images": "Images",
        "describe_volumes": "Volumes",
        
        # ELB
        "describe_load_balancers": "LoadBalancers",
        "describe_target_groups": "TargetGroups",
        
        # Lambda
        "list_functions": "Functions",
        
        # ECS
        "list_clusters": "clusterArns",
        "list_services": "serviceArns",
        "list_task_definitions": "taskDefinitionArns",
        
        # ECR
        "describe_repositories": "repositories",
        
        # CloudFront
        "list_distributions": "DistributionList",
        
        # Route53
        "list_hosted_zones": "HostedZones",
        
        # Trusted Advisor
        "describe_trusted_advisor_checks": "checks",
        
        # Access Analyzer
        "list_findings": "findings",
        
        # Default key if not found
        "default": "items"
    }
    
    return result_keys.get(method_name, result_keys["default"])

def filter_results(
    items: List[Dict[str, Any]],
    search_term: str = "",
    filter_func: Optional[Callable[[Dict[str, Any], str], bool]] = None
) -> List[Dict[str, Any]]:
    """Filter results based on search term and custom filter function.
    
    Args:
        items: List of items to filter
        search_term: Search term to match
        filter_func: Custom filter function
        
    Returns:
        Filtered list of items
    """
    if not search_term and not filter_func:
        return items
    
    filtered_items = []
    
    for item in items:
        # Use custom filter function if provided
        if filter_func and filter_func(item, search_term):
            filtered_items.append(item)
        # Otherwise use default filter (string match in any value)
        elif search_term and any(
            isinstance(v, str) and search_term.lower() in v.lower()
            for v in str(item).lower().split()
        ):
            filtered_items.append(item)
    
    return filtered_items

def format_timestamp(timestamp: Any) -> str:
    """Format timestamp to readable string.
    
    Args:
        timestamp: Timestamp (datetime, string, or timestamp)
        
    Returns:
        Formatted timestamp string
    """
    if hasattr(timestamp, "strftime"):
        return timestamp.strftime("%Y-%m-%d %H:%M:%S")
    return str(timestamp) 