"""
Tools module for AWS Resource Groups Tagging API.

This module provides tools to interact with AWS Resource Groups Tagging API.
It includes tools to retrieve resources by tag key-value pairs, tag keys, and tag values.
"""
import json
import logging
from typing import Dict, List, Optional, Any, Union

from aws_security_mcp.formatters.resource_tagging import (
    format_resources_response,
    format_resources_by_type,
    format_tag_keys_response,
    format_tag_values_response
)
from aws_security_mcp.services.resource_tagging import ResourceTaggingService
from aws_security_mcp.tools import register_tool

logger = logging.getLogger(__name__)

# Create singleton service instance
_service = ResourceTaggingService()


@register_tool("search_resources_by_tag")
async def search_resources_by_tag(
    tag_key: str,
    tag_value: Optional[str] = None,
    resource_types: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: Optional[int] = None,
    group_by_type: bool = True,
    session_context: Optional[str] = None
) -> str:
    """
    Search AWS resources by tag key and optional value.
    
    Args:
        tag_key: The tag key to search for
        tag_value: Optional tag value to filter by
        resource_types: Optional list of resource types to filter by (e.g., ['ec2:instance', 's3:bucket'])
        next_token: Token for pagination
        max_items: Maximum number of items to return (no limit if None)
        group_by_type: If True, resources will be grouped by service/resource type
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with resources matching the specified tags and pagination details
    """
    # Log function invocation only
    logger.info(f"Invoked search_resources_by_tag(tag_key={tag_key})")
    
    try:
        # Get resources by tags without hardcoded pagination limits
        result = await _service.get_resources_by_tags(
            tag_key=tag_key,
            tag_value=tag_value,
            resource_types=resource_types,
            next_token=next_token,
            max_items=max_items,
            session_context=session_context
        )
        
        # Format the response based on the grouping preference
        if group_by_type:
            formatted_result = format_resources_by_type(result, tag_key, tag_value)
        else:
            formatted_result = format_resources_response(result)
            
        return json.dumps(formatted_result)
    
    except Exception as e:
        logger.exception("Error searching resources by tag: %s", str(e))
        error_response = {
            "key": tag_key,
            "value": tag_value,
            "resources": {},
            "resource_count": 0,
            "error": f"Error searching resources by tag: {str(e)}"
        } if group_by_type else {
            "resources": [],
            "resource_count": 0,
            "error": f"Error searching resources by tag: {str(e)}"
        }
        return json.dumps(error_response)


@register_tool("get_all_tag_keys")
async def get_all_tag_keys(
    next_token: Optional[str] = None,
    max_items: Optional[int] = None,
    session_context: Optional[str] = None
) -> str:
    """
    Get all tag keys used in the AWS account.
    
    Args:
        next_token: Token for pagination
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with tag keys and pagination details
    """
    # Log function invocation only
    logger.info(f"Invoked get_all_tag_keys()")
    
    try:
        result = await _service.get_tag_keys(
            next_token=next_token, 
            max_items=max_items, 
            session_context=session_context
        )
        formatted_result = format_tag_keys_response(result)
        return json.dumps(formatted_result)
    
    except Exception as e:
        logger.exception("Error getting tag keys: %s", str(e))
        return json.dumps({
            "tag_keys": [],
            "tag_key_count": 0,
            "error": f"Error getting tag keys: {str(e)}"
        })


@register_tool("get_tag_values_for_key")
async def get_tag_values_for_key(
    tag_key: str,
    next_token: Optional[str] = None,
    max_items: Optional[int] = None,
    session_context: Optional[str] = None
) -> str:
    """
    Get all values for a specific tag key in the AWS account.
    
    Args:
        tag_key: The tag key to get values for
        next_token: Token for pagination
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with tag values and pagination details
    """
    # Log function invocation only
    logger.info(f"Invoked get_tag_values_for_key(tag_key={tag_key})")
    
    try:
        # Skip tag key validation and directly get tag values
        result = await _service.get_tag_values(
            tag_key=tag_key, 
            next_token=next_token, 
            max_items=max_items, 
            session_context=session_context
        )
        formatted_result = format_tag_values_response(result)
        return json.dumps(formatted_result)
    
    except Exception as e:
        logger.exception("Error getting tag values for key %s: %s", tag_key, str(e))
        return json.dumps({
            "tag_key": tag_key,
            "tag_values": [],
            "tag_value_count": 0,
            "error": f"Error getting tag values for key '{tag_key}': {str(e)}"
        }) 