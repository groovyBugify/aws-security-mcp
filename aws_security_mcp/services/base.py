"""Base AWS client functionality."""

import logging
from typing import Any, Dict, Optional, Type, Union, List
from functools import lru_cache
import threading
import time
import atexit

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_security_mcp.config import config

# Configure logging
logger = logging.getLogger(__name__)

# Thread-safe client cache with timestamps
_client_cache: Dict[str, tuple[boto3.client, float]] = {}
_cache_lock = threading.Lock()
_cache_max_age = 3600  # Cache for 1 hour by default

def _cleanup_expired_clients():
    """Remove expired clients from cache."""
    current_time = time.time()
    with _cache_lock:
        expired_keys = [
            key for key, (client, timestamp) in _client_cache.items()
            if current_time - timestamp > _cache_max_age
        ]
        for key in expired_keys:
            del _client_cache[key]
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired AWS clients")

# Register cleanup on exit
atexit.register(lambda: clear_client_cache())

def get_aws_session(
    region: Optional[str] = None,
    profile: Optional[str] = None,
    session_context: Optional[str] = None
) -> boto3.Session:
    """Get an AWS session with the specified configuration.
    
    Args:
        region: AWS region to use (defaults to config region)
        profile: AWS profile to use (defaults to config profile)
        session_context: Session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Configured boto3 Session
    """
    logger = logging.getLogger(__name__)
    
    # If session_context is provided, try to get cross-account session
    if session_context:
        try:
            from aws_security_mcp.services.credentials import get_session_for_account
            cross_account_session = get_session_for_account(session_context)
            if cross_account_session and not cross_account_session.is_expired():
                logger.info(f"Using cross-account session: {session_context} ({cross_account_session.account_name})")
                return cross_account_session.session
            else:
                logger.warning(f"Cross-account session '{session_context}' not found or expired, falling back to default")
        except Exception as e:
            logger.warning(f"Error accessing cross-account session '{session_context}': {e}, falling back to default")
    
    # Use provided or default values
    region = region or config.aws.aws_region
    profile = profile or config.aws.aws_profile
    
    # Build session arguments
    session_kwargs = {"region_name": region}
    
    # Add credentials if available
    if config.aws.has_profile and profile:
        session_kwargs["profile_name"] = profile
        logger.info(f"Using AWS profile: {profile}")
    elif config.aws.has_sts_credentials:
        session_kwargs.update({
            "aws_access_key_id": config.aws.aws_access_key_id,
            "aws_secret_access_key": config.aws.aws_secret_access_key,
            "aws_session_token": config.aws.aws_session_token
        })
        logger.info("Using temporary STS credentials")
    elif config.aws.has_iam_credentials:
        session_kwargs.update({
            "aws_access_key_id": config.aws.aws_access_key_id,
            "aws_secret_access_key": config.aws.aws_secret_access_key
        })
        logger.info("Using IAM access key credentials")
    else:
        # Provide more specific logging for automatic credential resolution
        if config.aws.is_ecs_environment:
            logger.info("Using automatic credential resolution (ECS Task Role detected)")
        elif config.aws.is_ec2_environment:
            logger.info("Using automatic credential resolution (EC2 Instance Profile detected)")
        else:
            logger.info("Using automatic credential resolution (environment variables, AWS config files, or instance profile)")
    
    # Create and return the session
    try:
        session = boto3.Session(**session_kwargs)
        
        # Validate that credentials are available
        if session.get_credentials() is None:
            logger.warning("No AWS credentials found. Functionality may be limited.")
        else:
            # Log the identity using the credentials (but don't expose sensitive info)
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            logger.info(f"AWS Identity: Account={identity['Account']}, ARN={identity['Arn']}")
            
        return session
        
    except Exception as e:
        logger.error(f"Error creating AWS session: {str(e)}")
        # Create a minimal session with just region, let boto3 handle auth errors later
        return boto3.Session(region_name=region)

def get_client(
    service_name: str, 
    region: Optional[str] = None,
    session_context: Optional[str] = None
) -> Any:
    """Get an AWS service client with optional cross-account session context.
    
    Args:
        service_name: AWS service name (e.g., 'ec2', 'iam', 's3')
        region: AWS region to use (defaults to config region)
        session_context: Session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Configured AWS service client
    """
    session = get_aws_session(region=region, session_context=session_context)
    return session.client(service_name)

def get_available_sessions() -> Dict[str, Dict[str, Any]]:
    """Get information about available cross-account sessions.
    
    Returns:
        Dict mapping session keys to session information
    """
    try:
        from aws_security_mcp.services.credentials import get_session_info
        return get_session_info()
    except Exception as e:
        logging.getLogger(__name__).error(f"Error getting session info: {e}")
        return {}

def clear_client_cache():
    """Clear the client cache. Useful for testing or credential rotation."""
    with _cache_lock:
        _client_cache.clear()
        logger.info("Cleared AWS client cache")

async def handle_aws_error(func: callable, *args, **kwargs) -> Dict[str, Any]:
    """Execute an AWS API call with error handling.
    
    Args:
        func: AWS API function to call
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function
        
    Returns:
        Response from the AWS API call
        
    Raises:
        ClientError: If an AWS API error occurs and cannot be handled
    """
    try:
        return func(*args, **kwargs)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", "Unknown error")
        
        # Only log errors, not warnings
        logger.error(f"AWS API error: {error_code} - {error_message}")
        raise

def get_resource(service_name: str, **kwargs: Any) -> boto3.resource:
    """Get a boto3 resource for a specific AWS service.
    
    Args:
        service_name: The AWS service name (e.g., 's3', 'dynamodb')
        **kwargs: Additional arguments to pass to the boto3 resource constructor
        
    Returns:
        boto3.resource: An initialized AWS service resource
    """
    session = get_aws_session()
    return session.resource(service_name, **kwargs)

def handle_pagination(
    operation: Any,
    result_key: str,
    token_key: str = "NextToken",
    token_param: str = "NextToken",
    max_items: Optional[int] = None,
    **operation_kwargs: Any
) -> list:
    """Handle pagination for AWS API calls.
    
    Args:
        operation: The operation function to call
        result_key: The key in the response that contains the results
        token_key: The key in the response that contains the next token
        token_param: The parameter name for the token in the request
        max_items: Maximum number of items to return
        **operation_kwargs: Additional arguments to pass to the operation
        
    Returns:
        list: All results from the paginated operation
    """
    all_results = []
    next_token = None
    
    while True:
        # Add token to operation arguments if available
        if next_token:
            operation_kwargs[token_param] = next_token
        
        # Call operation
        response = operation(**operation_kwargs)
        
        # Get results from response
        if result_key in response:
            results = response[result_key]
            all_results.extend(results)
            
            # Check if we have reached the maximum items
            if max_items is not None and len(all_results) >= max_items:
                all_results = all_results[:max_items]
                break
        
        # Get next token
        next_token = response.get(token_key)
        if not next_token:
            break
    
    return all_results

# Mapping of AWS services to their pagination token names
AWS_PAGINATION_TOKENS = {
    # Services using NextToken
    'ec2': {'token_response': 'NextToken', 'token_request': 'NextToken'},
    'iam': {'token_response': 'Marker', 'token_request': 'Marker'},
    'lambda': {'token_response': 'NextMarker', 'token_request': 'Marker'},
    'cloudwatch': {'token_response': 'NextToken', 'token_request': 'NextToken'},
    'cloudfront': {'token_response': 'NextMarker', 'token_request': 'Marker'},
    'guardduty': {'token_response': 'NextToken', 'token_request': 'NextToken'},
    'securityhub': {'token_response': 'NextToken', 'token_request': 'NextToken'},
    # Route53 uses different token names based on the specific API call
    'route53': {'token_response': 'NextMarker', 'token_request': 'Marker'},
    # Default to NextToken if service is not listed
    'default': {'token_response': 'NextToken', 'token_request': 'NextToken'}
}

def format_pagination_response(items: List[Any], next_token: Optional[str] = None, is_truncated: Optional[bool] = None) -> Dict[str, Any]:
    """Format a standard pagination response for AWS services.
    
    Args:
        items: The items retrieved from the AWS API
        next_token: The pagination token for the next page
        is_truncated: Whether there are more items to retrieve
        
    Returns:
        Dict containing items, pagination info, and metadata
    """
    # If is_truncated is not explicitly provided, infer from next_token
    if is_truncated is None:
        is_truncated = next_token is not None
    
    return {
        'items': items,
        'next_token': next_token,
        'is_truncated': is_truncated,
        'count': len(items)
    }

def get_pagination_tokens(service_name: str) -> Dict[str, str]:
    """Get the appropriate pagination token names for a specific AWS service.
    
    Args:
        service_name: The AWS service name (e.g., 'ec2', 'route53')
        
    Returns:
        Dict containing token_response and token_request keys with appropriate token names
    """
    return AWS_PAGINATION_TOKENS.get(service_name, AWS_PAGINATION_TOKENS['default'])

def parse_pagination_parameters(params: Dict[str, Any], service_name: str = 'default') -> Dict[str, Any]:
    """Parse and prepare pagination parameters for AWS API calls.
    
    Args:
        params: The original parameters dictionary
        service_name: The AWS service name to determine correct token keys
        
    Returns:
        Updated parameters dictionary with correctly formatted pagination tokens
    """
    updated_params = params.copy()
    
    # Get correct token names for this service
    tokens = get_pagination_tokens(service_name)
    token_request = tokens['token_request']  # e.g., 'NextToken', 'Marker'
    
    # Handle next token (normalize from next_token to appropriate AWS param)
    if 'next_token' in updated_params:
        token = updated_params.pop('next_token')
        if token:
            updated_params[token_request] = token
    
    # Handle max items (some services use strings for pagination limits)
    if 'max_items' in updated_params:
        max_items = updated_params.pop('max_items')
        if max_items is not None:
            # Determine the correct parameter name for max items based on service
            max_items_key = 'MaxItems'
            if service_name == 'ec2':
                max_items_key = 'MaxResults'
            
            # Some services require max items as string
            if service_name in ['route53', 'cloudformation']:
                max_items = str(max_items)
            
            updated_params[max_items_key] = max_items
    
    return updated_params 