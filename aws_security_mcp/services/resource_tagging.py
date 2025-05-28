"""
Service module for AWS Resource Groups Tagging API.

This module provides service functions for interacting with the AWS Resource Groups Tagging API,
which allows for retrieving resources by tags, getting tag keys and values, and validating tags.
"""
import logging
from typing import Dict, List, Optional, Any, Union

import boto3
from botocore.exceptions import ClientError, ParamValidationError

from aws_security_mcp.services.base import get_client

logger = logging.getLogger(__name__)


class ResourceTaggingService:
    """
    Service class for interacting with AWS Resource Groups Tagging API.
    
    This class provides methods to retrieve resources by tags, 
    get tag keys and values, and verify tag existence.
    """
    
    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize the ResourceTaggingService.
        
        Args:
            region: AWS region name (overrides config)
            profile: AWS profile name (overrides config)
        """
        self.region = region
        self.profile = profile
        self._client = None
    
    def get_client(self, session_context: Optional[str] = None):
        """Get the ResourceGroupsTaggingAPI client with optional session context.
        
        Args:
            session_context: Optional session key for cross-account access
            
        Returns:
            boto3.client: The ResourceGroupsTaggingAPI client
        """
        return get_client('resourcegroupstaggingapi', session_context=session_context)
    
    async def get_tag_keys(
        self, 
        next_token: Optional[str] = None, 
        max_items: int = 100, 
        session_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get all tag keys used across AWS resources.

        Args:
            next_token: Token for pagination
            max_items: Maximum number of items to return (defaults to 100)
            session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

        Returns:
            Dict containing tag keys and pagination details
        """
        # Log function invocation only
        logger.info(f"Invoked ResourceTaggingService.get_tag_keys(max_items={max_items})")
        
        try:
            # Get client with session context
            client = self.get_client(session_context=session_context)
            
            # Configure paginator for proper pagination handling
            paginator = client.get_paginator('get_tag_keys')
            
            # Set up pagination configuration
            pagination_config = {
                'MaxItems': max_items,
                'PageSize': min(max_items, 100)  # AWS API page size limit
            }
            
            if next_token:
                pagination_config['StartingToken'] = next_token
            
            # Get a page iterator
            page_iterator = paginator.paginate(PaginationConfig=pagination_config)
            
            # Process the paginated results
            tag_keys = []
            response_next_token = None
            
            for page in page_iterator:
                # Add tag keys from this page
                tag_keys.extend(page.get('TagKeys', []))
                
                # Store next token for pagination
                if hasattr(page_iterator, 'resume_token'):
                    response_next_token = page_iterator.resume_token
                
                # If we've reached max_items, we can stop
                if len(tag_keys) >= max_items:
                    tag_keys = tag_keys[:max_items]
                    break
            
            # Initialize result structure
            result = {
                'tag_keys': tag_keys,
                'tag_key_count': len(tag_keys),
                'next_token': response_next_token
            }
            
            return result
            
        except ClientError as e:
            logger.error(f"Error getting tag keys: {str(e)}")
            return {
                'tag_keys': [],
                'tag_key_count': 0,
                'next_token': None,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"Unexpected error getting tag keys: {str(e)}")
            return {
                'tag_keys': [],
                'tag_key_count': 0,
                'next_token': None,
                'error': str(e)
            }

    async def get_tag_values(
        self, 
        tag_key: str, 
        next_token: Optional[str] = None, 
        max_items: int = 100, 
        session_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get all values for a specific tag key across AWS resources.

        Args:
            tag_key: The tag key to get values for
            next_token: Token for pagination
            max_items: Maximum number of items to return (defaults to 100)
            session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

        Returns:
            Dict containing tag values and pagination details
        """
        # Log function invocation only
        logger.info(f"Invoked ResourceTaggingService.get_tag_values(tag_key={tag_key}, max_items={max_items})")
        
        try:
            # Get client with session context
            client = self.get_client(session_context=session_context)
            
            # Configure paginator for proper pagination handling
            paginator = client.get_paginator('get_tag_values')
            
            # Set up pagination configuration
            pagination_config = {
                'MaxItems': max_items,
                'PageSize': min(max_items, 100)  # AWS API page size limit
            }
            
            if next_token:
                pagination_config['StartingToken'] = next_token
            
            # Get a page iterator
            page_iterator = paginator.paginate(
                Key=tag_key,
                PaginationConfig=pagination_config
            )
            
            # Process the paginated results
            tag_values = []
            response_next_token = None
            
            for page in page_iterator:
                # Add tag values from this page
                tag_values.extend(page.get('TagValues', []))
                
                # Store next token for pagination
                if hasattr(page_iterator, 'resume_token'):
                    response_next_token = page_iterator.resume_token
                
                # If we've reached max_items, we can stop
                if len(tag_values) >= max_items:
                    tag_values = tag_values[:max_items]
                    break
            
            # Initialize result structure
            result = {
                'tag_key': tag_key,
                'tag_values': tag_values,
                'tag_value_count': len(tag_values),
                'next_token': response_next_token
            }
            
            return result
            
        except ClientError as e:
            logger.error(f"Error getting tag values for key '{tag_key}': {str(e)}")
            return {
                'tag_key': tag_key,
                'tag_values': [],
                'tag_value_count': 0,
                'next_token': None,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"Unexpected error getting tag values for key '{tag_key}': {str(e)}")
            return {
                'tag_key': tag_key,
                'tag_values': [],
                'tag_value_count': 0,
                'next_token': None,
                'error': str(e)
            }

    async def get_resources_by_tags(
        self, 
        tag_key: str, 
        tag_value: Optional[str] = None, 
        resource_types: Optional[List[str]] = None,
        next_token: Optional[str] = None, 
        max_items: Optional[int] = None,
        session_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get AWS resources filtered by tag key and optionally by tag value.

        Args:
            tag_key: The tag key to filter by
            tag_value: Optional tag value to filter by
            resource_types: Optional list of resource types to filter by
            next_token: Token for pagination
            max_items: Optional maximum number of items to return (if None, will use AWS default)
            session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

        Returns:
            Dict containing resources and pagination details
        """
        # Log function invocation only
        logger.info(f"Invoked ResourceTaggingService.get_resources_by_tags(tag_key={tag_key})")
        
        try:
            # Get client with session context
            client = self.get_client(session_context=session_context)
            
            # Construct tag filters - always use "Values" (plural) even for a single value
            # This maintains consistency with AWS CLI which uses:
            # aws resourcegroupstaggingapi get-resources --tag-filters "Key=tagkey,Values=tagvalue"
            tag_filters = [{"Key": tag_key}]
            if tag_value:
                tag_filters[0]["Values"] = [tag_value]
            
            # Setup pagination using the paginator
            paginator = client.get_paginator('get_resources')
            
            # IMPORTANT: There's a parameter name mismatch between direct API calls and paginator usage:
            # - Direct AWS API calls use 'PaginationToken' as the parameter name
            # - Boto3 paginator uses 'StartingToken' in PaginationConfig 
            # 
            # The paginator automatically translates 'StartingToken' to the appropriate parameter
            # name ('PaginationToken' in this case) when making the actual API call
            pagination_config = {}
            
            # Only set MaxItems if explicitly provided
            if max_items is not None:
                pagination_config['MaxItems'] = max_items
                # AWS API has a page size limit of 100
                pagination_config['PageSize'] = min(max_items, 100) if max_items else 100
            
            if next_token:
                # When using the paginator, we use 'StartingToken' in the config
                pagination_config['StartingToken'] = next_token
            
            # Prepare paginator parameters
            paginator_kwargs = {
                'TagFilters': tag_filters
            }
            
            # Only add pagination config if we have any settings
            if pagination_config:
                paginator_kwargs['PaginationConfig'] = pagination_config
            
            # Add resource types if specified
            if resource_types:
                paginator_kwargs['ResourceTypeFilters'] = resource_types
                
            # Get a page iterator
            page_iterator = paginator.paginate(**paginator_kwargs)
            
            # Process the paginated results
            resources = []
            response_next_token = None
            
            for page in page_iterator:
                # Add resources from this page
                resources.extend(page.get('ResourceTagMappingList', []))
                
                # Store next token for pagination - this will be the StartingToken
                # for the next paginate call (internally converted to PaginationToken)
                if hasattr(page_iterator, 'resume_token'):
                    response_next_token = page_iterator.resume_token
                
                # If we've reached max_items, we can stop
                if max_items and len(resources) >= max_items:
                    resources = resources[:max_items]
                    break
                    
            # Initialize result structure with token for next request
            result = {
                'resources': resources,
                'resource_count': len(resources),
                'next_token': response_next_token
            }
            
            return result
            
        except ParamValidationError as e:
            error_msg = f"Parameter validation error when searching for resources with tag '{tag_key}': {str(e)}"
            logger.error(error_msg)
            return {
                'resources': [],
                'resource_count': 0,
                'next_token': None,
                'error': error_msg
            }
        except ClientError as e:
            error_msg = f"Error searching for resources with tag '{tag_key}': {str(e)}"
            logger.error(error_msg)
            return {
                'resources': [],
                'resource_count': 0,
                'next_token': None,
                'error': error_msg
            }
        except Exception as e:
            error_msg = f"Unexpected error searching for resources with tag '{tag_key}': {str(e)}"
            logger.error(error_msg)
            return {
                'resources': [],
                'resource_count': 0,
                'next_token': None,
                'error': error_msg
            }


# Create default service instance for backward compatibility with function-based approach
_default_service = ResourceTaggingService()

# Function wrappers for backward compatibility
async def get_tag_keys(
    next_token: Optional[str] = None, 
    max_items: int = 100, 
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Wrapper for ResourceTaggingService.get_tag_keys using default service instance."""
    return await _default_service.get_tag_keys(next_token, max_items, session_context)

async def get_tag_values(
    tag_key: str, 
    next_token: Optional[str] = None, 
    max_items: int = 100, 
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Wrapper for ResourceTaggingService.get_tag_values using default service instance."""
    return await _default_service.get_tag_values(tag_key, next_token, max_items, session_context)

async def get_resources_by_tags(
    tag_key: str,
    tag_value: Optional[str] = None,
    resource_types: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: Optional[int] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Wrapper for ResourceTaggingService.get_resources_by_tags using default service instance."""
    return await _default_service.get_resources_by_tags(
        tag_key, tag_value, resource_types, next_token, max_items, session_context
    ) 