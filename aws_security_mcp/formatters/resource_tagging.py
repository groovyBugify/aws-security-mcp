"""
Formatter module for AWS Resource Groups Tagging API responses.

This module provides functions to format the responses from 
ResourceGroupsTaggingAPI into a more readable format.
"""
from typing import Dict, List, Any, Optional
from collections import defaultdict


def format_resource_details(resource: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format a single resource from ResourceGroupsTaggingAPI.
    
    Args:
        resource: Resource information from ResourceGroupsTaggingAPI.
        
    Returns:
        Formatted resource information.
    """
    arn = resource.get('ResourceARN', '')
    tags = resource.get('Tags', [])
    
    # Extract resource type and name from ARN
    resource_parts = arn.split(':')
    resource_type = None
    resource_name = None
    
    if len(resource_parts) >= 6:
        # Example ARN: arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0
        service = resource_parts[2]
        
        # Handle special cases where the resource type information is in a different format
        if service == 'ec2':
            if '/subnet/' in arn:
                resource_type = 'subnet'
            elif '/vpc/' in arn:
                resource_type = 'vpc'
            elif '/security-group/' in arn:
                resource_type = 'security-group'
            elif '/instance/' in arn:
                resource_type = 'instance'
            elif '/volume/' in arn:
                resource_type = 'volume'
            else:
                resource_type = resource_parts[5].split('/')[0] if '/' in resource_parts[5] else resource_parts[5]
            
            resource_name = arn.split('/')[-1] if '/' in arn else None
        elif service == 's3':
            resource_type = 'bucket'
            resource_name = resource_parts[5]
        elif service == 'dynamodb':
            resource_type = resource_parts[5].split('/')[0] if '/' in resource_parts[5] else resource_parts[5]
            resource_name = arn.split('/')[-1] if '/' in arn else None
        elif service == 'lambda':
            resource_type = 'function'
            resource_name = arn.split(':')[-1] if ':' in arn else None
        else:
            resource_type = resource_parts[5].split('/')[0] if '/' in resource_parts[5] else resource_parts[5]
            resource_name = arn.split('/')[-1] if '/' in arn else None
    
    # Format tags as a dictionary
    tags_dict = {tag.get('Key', ''): tag.get('Value', '') for tag in tags}
    
    return {
        'ResourceARN': arn,
        'ResourceType': resource_type,
        'ResourceName': resource_name,
        'Service': resource_parts[2] if len(resource_parts) >= 3 else None,
        'Region': resource_parts[3] if len(resource_parts) >= 4 else None,
        'AccountId': resource_parts[4] if len(resource_parts) >= 5 else None,
        'Tags': tags_dict
    }


def format_resources_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format the response from get_resources_by_tags into a standardized format.

    Args:
        response: The response from the get_resources_by_tags service function

    Returns:
        A dictionary with the resources and pagination information
    """
    # Extract resource mappings and transform them into a more user-friendly format
    resources = []
    
    for resource in response.get("resources", []):
        formatted_resource = format_resource_details(resource)
        
        resources.append({
            "arn": formatted_resource["ResourceARN"],
            "resource_type": f"{formatted_resource['Service']}:{formatted_resource['ResourceType']}" 
                             if formatted_resource['Service'] and formatted_resource['ResourceType'] else "",
            "resource_name": formatted_resource["ResourceName"],
            "region": formatted_resource["Region"],
            "account_id": formatted_resource["AccountId"],
            "tags": formatted_resource["Tags"]
        })
    
    result = {
        "resources": resources,
        "resource_count": len(resources),
        "next_token": response.get("next_token")
    }
    
    # Include any error information
    if "error" in response:
        result["error"] = response["error"]
    
    return result


def format_resources_by_type(response: Dict[str, Any], tag_key: str, tag_value: Optional[str] = None) -> Dict[str, Any]:
    """
    Format the response from get_resources_by_tags into a grouped by resource type format.

    Args:
        response: The response from the get_resources_by_tags service function
        tag_key: The tag key used in the search
        tag_value: The optional tag value used in the search

    Returns:
        A dictionary with resources grouped by their type, with the format:
        {"key": "<tag_key>", "value": "<tag_value>", "resources": {"<service>": [<ARN list>]}}
    """
    # Group resources by service/type (limiting to 25 resources per service)
    grouped_resources = defaultdict(list)
    
    # Keep count of all resources by service type
    resource_counts = defaultdict(int)
    
    # Services for which we'll only provide counts, not full ARN lists
    count_only_services = {
        'cloudwatch',           # CloudWatch alarms aren't relevant for security
        'ecs',                  # ECS tasks aren't needed
        'application-autoscaling', # Auto-scaling resources aren't needed
        'batch'                 # Batch jobs aren't needed
    }
    
    # Maximum number of ARNs to include per service
    MAX_RESOURCES_PER_SERVICE = 25
    
    # Process the raw response from AWS
    for resource in response.get("resources", []):
        # The ResourceTagMappingList contains the ARN directly
        arn = resource.get('ResourceARN', '')
        if not arn:
            continue
            
        arn_parts = arn.split(':')
        if len(arn_parts) >= 3:
            # Get the service name (application-autoscaling, ec2, etc.)
            service = arn_parts[2]
            
            # Increment the count for this service
            resource_counts[service] += 1
            
            # If this is a service where we only want to show counts, don't add to ARN list
            if service.lower() in count_only_services:
                continue
                
            # Only add the ARN if we haven't reached the limit for this service
            if len(grouped_resources[service]) < MAX_RESOURCES_PER_SERVICE:
                grouped_resources[service].append(arn)
    
    # Build the final simplified result structure
    result = {
        "key": tag_key,
        "value": tag_value,
        "resources": dict(grouped_resources),
        "resource_count": len(response.get("resources", [])),
    }
    
    # Add count information for all services
    result["resource_counts"] = {
        service: count for service, count in resource_counts.items() 
        if count > 0
    }
    
    # Add next_token only if present
    if response.get("next_token"):
        result["next_token"] = response.get("next_token")
    
    # Include any error information
    if "error" in response:
        result["error"] = response["error"]
    
    return result


def format_tag_keys_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format the response from get_tag_keys into a standardized format.

    Args:
        response: The response from the get_tag_keys service function

    Returns:
        A dictionary with the tag keys and pagination information
    """
    result = {
        "tag_keys": response.get("tag_keys", []),
        "tag_key_count": response.get("tag_key_count", 0),
        "next_token": response.get("next_token")
    }
    
    # Include any error information
    if "error" in response:
        result["error"] = response["error"]
        
    return result


def format_tag_values_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format the response from get_tag_values into a standardized format.

    Args:
        response: The response from the get_tag_values service function

    Returns:
        A dictionary with the tag key, values, and pagination information
    """
    result = {
        "tag_key": response.get("tag_key", ""),
        "tag_values": response.get("tag_values", []),
        "tag_value_count": response.get("tag_value_count", 0),
        "next_token": response.get("next_token")
    }
    
    # Include any error information
    if "error" in response:
        result["error"] = response["error"]
        
    return result 