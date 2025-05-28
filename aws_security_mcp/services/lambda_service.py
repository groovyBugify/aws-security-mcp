"""AWS Lambda service client module.

This module provides functions for interacting with AWS Lambda.
"""

import logging
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime, timezone, timedelta
import json

import boto3
from botocore.exceptions import ClientError

from aws_security_mcp.services.base import get_client, handle_aws_error
from aws_security_mcp.utils.policy_evaluator import evaluate_policy_conditions, evaluate_policy_for_public_access

# Configure logging
logger = logging.getLogger(__name__)

def get_lambda_client(session_context: Optional[str] = None, **kwargs: Any) -> boto3.client:
    """Get AWS Lambda client.
    
    Args:
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized Lambda client
    """
    return get_client('lambda', session_context=session_context, **kwargs)

def list_functions(
    function_version: str = 'ALL',
    marker: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """List Lambda functions.
    
    Args:
        function_version: Version of functions to include (ALL, $LATEST)
        marker: Pagination marker from previous response
        max_items: Maximum number of functions to return
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the list_functions API call
        
    Returns:
        Dict[str, Any]: Response containing Lambda functions
    """
    client = get_lambda_client(session_context=session_context)
    
    params = {
        'FunctionVersion': function_version,
        'MaxItems': max_items,
        **kwargs
    }
    
    if marker:
        params['Marker'] = marker
    
    try:
        return client.list_functions(**params)
    except ClientError as e:
        logger.error(f"Error listing Lambda functions: {e}")
        raise

def get_function(
    function_name: str,
    qualifier: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Get details of a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        qualifier: Version or alias of the function
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the get_function API call
        
    Returns:
        Dict[str, Any]: Response containing Lambda function details
    """
    client = get_lambda_client(session_context=session_context)
    
    params = {
        'FunctionName': function_name,
        **kwargs
    }
    
    if qualifier:
        params['Qualifier'] = qualifier
    
    try:
        return client.get_function(**params)
    except ClientError as e:
        logger.error(f"Error getting Lambda function {function_name}: {e}")
        raise

def get_function_configuration(
    function_name: str,
    qualifier: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Get configuration of a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        qualifier: Version or alias of the function
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the get_function_configuration API call
        
    Returns:
        Dict[str, Any]: Response containing Lambda function configuration
    """
    client = get_lambda_client(session_context=session_context)
    
    params = {
        'FunctionName': function_name,
        **kwargs
    }
    
    if qualifier:
        params['Qualifier'] = qualifier
    
    try:
        return client.get_function_configuration(**params)
    except ClientError as e:
        logger.error(f"Error getting Lambda function configuration for {function_name}: {e}")
        raise

def get_all_functions(
    search_term: str = "",
    marker: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Get all Lambda functions with proper pagination and optional filtering.
    
    Args:
        search_term: Optional search term to filter functions by name
        marker: Pagination token from previous request (used for backward compatibility)
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the client or list_functions API call
        
    Returns:
        Dict containing functions list and pagination marker
    """
    functions = []
    next_marker = None
    
    # Extract client kwargs from kwargs
    client_kwargs = {}
    if 'region_name' in kwargs:
        client_kwargs['region_name'] = kwargs.pop('region_name')
    
    # Get client with region and session context if specified
    client = get_lambda_client(session_context=session_context, **client_kwargs)
    
    # Use the paginator for proper handling of large result sets
    paginator = client.get_paginator('list_functions')
    
    # Create pagination config
    pagination_config = {
        'MaxItems': kwargs.pop('max_items', None),  # Remove max_items if present but maintain for backward compatibility
        'PageSize': 50  # Optimize API calls with reasonable page size
    }
    
    # Add marker if specified (start_token in paginator terminology)
    if marker:
        pagination_config['StartingToken'] = marker
    
    # Set up function version filter
    function_version = kwargs.pop('FunctionVersion', 'ALL')
    
    try:
        # Execute paginated API calls
        page_iterator = paginator.paginate(
            FunctionVersion=function_version,
            PaginationConfig=pagination_config,
            **kwargs
        )
        
        # Process each page
        for page in page_iterator:
            batch_functions = page.get('Functions', [])
            
            # Filter by search term if provided
            if search_term:
                search_term_lower = search_term.lower()
                filtered_functions = []
                
                for function in batch_functions:
                    function_name = function.get('FunctionName', '').lower()
                    function_desc = function.get('Description', '').lower()
                    
                    if (search_term_lower in function_name or
                        search_term_lower in function_desc):
                        filtered_functions.append(function)
                
                batch_functions = filtered_functions
            
            functions.extend(batch_functions)
            
            # Store the marker for the next page if available
            if hasattr(page_iterator, 'resume_token'):
                next_marker = page_iterator.resume_token
    except ClientError as e:
        logger.error(f"Error getting Lambda functions: {e}")
    
    return {
        'functions': functions,
        'marker': next_marker
    }

def get_function_environment_variables(
    function_name: str,
    qualifier: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, str]:
    """Get environment variables for a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        qualifier: Version or alias of the function
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict[str, str]: Dictionary of environment variables
    """
    try:
        config = get_function_configuration(function_name, qualifier, session_context=session_context)
        return config.get('Environment', {}).get('Variables', {})
    except Exception as e:
        logger.error(f"Error getting environment variables for Lambda function {function_name}: {e}")
        return {}

def scan_function_environment_variables(
    function: Dict[str, Any],
    keyword: str = ""
) -> List[Dict[str, str]]:
    """Scan environment variables of a function for a keyword.
    
    Args:
        function: Lambda function object
        keyword: Keyword to search for
        
    Returns:
        List[Dict[str, str]]: List of matching environment variables
    """
    matches = []
    
    # Get environment variables
    env_vars = function.get('Environment', {}).get('Variables', {})
    
    if not env_vars:
        return matches
    
    # Check each environment variable for the keyword
    for key, value in env_vars.items():
        if not keyword or keyword.lower() in key.lower() or keyword.lower() in str(value).lower():
            matches.append({
                'key': key,
                'value': value
            })
    
    return matches

def scan_all_functions_for_env_variables(
    keyword: str = "",
    session_context: Optional[str] = None
) -> Dict[str, List[Dict[str, str]]]:
    """Scan all Lambda functions for environment variables containing a keyword.
    
    Args:
        keyword: Keyword to search for in environment variables
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict[str, List[Dict[str, str]]]: Dictionary of function names to matching variables
    """
    results = {}
    functions_response = get_all_functions(session_context=session_context)
    functions = functions_response.get('functions', [])
    
    for function in functions:
        function_name = function.get('FunctionName', 'Unknown')
        matches = scan_function_environment_variables(function, keyword)
        
        if matches:
            results[function_name] = matches
    
    return results

def get_function_tags(function_name: str, session_context: Optional[str] = None) -> Dict[str, str]:
    """Get tags for a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict[str, str]: Dictionary of tags (key-value pairs)
    """
    client = get_lambda_client(session_context=session_context)
    
    try:
        response = client.list_tags(Resource=function_name)
        return response.get('Tags', {})
    except ClientError as e:
        logger.error(f"Error getting tags for Lambda function {function_name}: {e}")
        return {}

def get_policy(function_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get the resource policy for a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict[str, Any]: Policy document and metadata
    """
    client = get_lambda_client(session_context=session_context)
    
    try:
        response = client.get_policy(FunctionName=function_name)
        return response
    except ClientError as e:
        # ResourceNotFoundException is expected if there's no policy
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.info(f"No policy found for Lambda function {function_name}")
            return {}
        logger.error(f"Error getting policy for Lambda function {function_name}: {e}")
        return {}

def list_versions(function_name: str, session_context: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get a list of versions for a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        List[Dict[str, Any]]: List of version configurations
    """
    client = get_lambda_client(session_context=session_context)
    
    try:
        response = client.list_versions_by_function(FunctionName=function_name)
        return response.get('Versions', [])
    except ClientError as e:
        logger.error(f"Error listing versions for Lambda function {function_name}: {e}")
        return []

def list_aliases(function_name: str, session_context: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get a list of aliases for a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        List[Dict[str, Any]]: List of alias configurations
    """
    client = get_lambda_client(session_context=session_context)
    
    try:
        response = client.list_aliases(FunctionName=function_name)
        return response.get('Aliases', [])
    except ClientError as e:
        logger.error(f"Error listing aliases for Lambda function {function_name}: {e}")
        return []

def list_event_source_mappings(function_name: str, session_context: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get a list of event source mappings for a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        List[Dict[str, Any]]: List of event source mappings
    """
    client = get_lambda_client(session_context=session_context)
    
    try:
        response = client.list_event_source_mappings(FunctionName=function_name)
        return response.get('EventSourceMappings', [])
    except ClientError as e:
        logger.error(f"Error listing event source mappings for Lambda function {function_name}: {e}")
        return []

def get_recent_invocations(function_name: str, limit: int = 10, session_context: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get recent invocations of a Lambda function from CloudWatch Logs.
    
    Args:
        function_name: Name or ARN of the Lambda function
        limit: Maximum number of invocations to return
        session_context: Optional session key for cross-account access
        
    Returns:
        List[Dict[str, Any]]: List of recent invocations with metadata
    """
    # Get CloudWatch Logs client to query Lambda logs
    logs_client = get_client('logs', session_context=session_context)
    
    # Lambda log group name pattern
    log_group_name = f"/aws/lambda/{function_name}"
    
    invocations = []
    
    try:
        # First check if the log group exists
        try:
            logs_client.describe_log_groups(logGroupNamePrefix=log_group_name, limit=1)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.info(f"No log group found for Lambda function {function_name}")
                return []
            raise
        
        # Define the time range (last 24 hours)
        end_time = int(datetime.now(timezone.utc).timestamp() * 1000)
        start_time = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp() * 1000)
        
        # Query for REPORT lines which contain invocation summaries
        query = 'fields @timestamp, @message | filter @message like "REPORT RequestId:" | sort @timestamp desc | limit ' + str(limit)
        
        # Start the query
        start_query_response = logs_client.start_query(
            logGroupName=log_group_name,
            startTime=start_time,
            endTime=end_time,
            queryString=query
        )
        
        query_id = start_query_response['queryId']
        
        # Wait for query to complete
        response = None
        while response is None or response['status'] == 'Running':
            response = logs_client.get_query_results(queryId=query_id)
            if response['status'] == 'Running':
                import time
                time.sleep(1)  # Short delay before checking again
        
        # Process results
        for result in response.get('results', []):
            # Extract data from the REPORT line
            report_line = next((field['value'] for field in result if field['field'] == '@message'), '')
            timestamp_str = next((field['value'] for field in result if field['field'] == '@timestamp'), '')
            
            if report_line and 'REPORT RequestId:' in report_line:
                # Parse the REPORT line to extract details
                parts = report_line.split('\t')
                request_id = parts[0].replace('REPORT RequestId: ', '').strip()
                
                # Initialize invocation data
                invocation = {
                    'timestamp': datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')),
                    'request_id': request_id,
                    'status': 'Completed',  # Assumption based on REPORT line existence
                    'duration': 'Unknown',
                    'memory_used': 'Unknown'
                }
                
                # Extract duration and memory information
                for part in parts:
                    if 'Duration:' in part:
                        try:
                            duration_ms = float(part.replace('Duration:', '').replace('ms', '').strip())
                            invocation['duration'] = duration_ms
                        except (ValueError, TypeError):
                            pass
                    
                    if 'Memory Size:' in part and 'Max Memory Used:' in parts[-1]:
                        try:
                            memory_used = float(parts[-1].replace('Max Memory Used:', '').replace('MB', '').strip())
                            invocation['memory_used'] = memory_used
                        except (ValueError, TypeError):
                            pass
                
                invocations.append(invocation)
        
        return invocations
        
    except ClientError as e:
        logger.error(f"Error getting recent invocations for Lambda function {function_name}: {e}")
        return []

def get_function_url_config(function_name: str, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get the function URL configuration for a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict[str, Any] or None: Function URL configuration or None if not configured
    """
    client = get_lambda_client(session_context=session_context)
    
    try:
        response = client.get_function_url_config(FunctionName=function_name)
        return response
    except ClientError as e:
        # ResourceNotFoundException is expected if there's no function URL
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.info(f"No function URL configured for Lambda function {function_name}")
            return None
        logger.error(f"Error getting function URL configuration for Lambda function {function_name}: {e}")
        return None
        
def check_policy_for_public_access(function_policy: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Check if a Lambda function policy allows public access.

    This function uses the policy_evaluator utility to determine if a Lambda function policy
    allows public access, and provides details about any public statements.

    Args:
        function_policy: The Lambda function policy as a dictionary

    Returns:
        Tuple of (is_public, details) where details contains assessment results
    """
    # If policy is empty or None, it doesn't allow public access
    if not function_policy:
        return False, {}
    
    # If the policy is a string format, convert it to a dictionary
    if isinstance(function_policy, str):
        try:
            function_policy = json.loads(function_policy)
        except json.JSONDecodeError:
            logger.error("Failed to parse Lambda function policy JSON")
            return False, {}
    
    # Use the policy evaluator utility for consistent policy assessment
    evaluation_result = evaluate_policy_for_public_access(function_policy)
    
    is_public = evaluation_result.get("allows_public_access", False)
    has_unmitigated_public_access = evaluation_result.get("has_unmitigated_public_access", False)
    
    # Create a detailed assessment
    details = {
        "is_public": is_public,
        "has_unmitigated_public_access": has_unmitigated_public_access,
        "public_statements": evaluation_result.get("public_statements", []),
        "has_condition_mitigations": evaluation_result.get("has_condition_mitigations", False),
        "condition_mitigations": evaluation_result.get("condition_mitigations", []),
        "policy_document": function_policy
    }
    
    return is_public, details

def check_function_url_discrepancy(function_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Check if there's a discrepancy between function URL configuration and policy.
    
    This function checks if:
    1. A function URL exists but no policy grants access to it
    2. A policy grants access to function URL but no function URL is configured
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict with discrepancy information
    """
    result = {
        'function_name': function_name,
        'has_function_url': False,
        'has_function_url_policy': False,
        'discrepancy': False,
        'discrepancy_type': None,
        'function_url': None,
        'auth_type': None,
        'policy_analysis': None,
        'policy_condition_details': []
    }
    
    # Check if function URL is configured
    try:
        url_config = get_function_url_config(function_name, session_context=session_context)
        if url_config:
            result['has_function_url'] = True
            result['function_url'] = url_config.get('FunctionUrl')
            result['auth_type'] = url_config.get('AuthType')
    except Exception as e:
        logger.error(f"Error checking function URL for {function_name}: {e}")
    
    # Check if policy has function URL permissions
    try:
        policy_response = get_policy(function_name, session_context=session_context)
        if policy_response and 'Policy' in policy_response:
            policy_json = json.loads(policy_response['Policy'])
            
            # Use the policy evaluator for comprehensive analysis
            is_public, policy_analysis = check_policy_for_public_access(policy_json)
            result['policy_analysis'] = policy_analysis
            
            # Additionally, check specifically for function URL permissions
            statements = policy_json.get('Statement', [])
            for statement in statements:
                # Check for function URL related permissions
                if statement.get('Effect') == 'Allow':
                    # Function URL invocation typically uses lambda:InvokeFunctionUrl action
                    action = statement.get('Action')
                    invoke_url_action_found = False
                    
                    # Check if action includes InvokeFunctionUrl
                    if isinstance(action, str) and 'lambda:InvokeFunctionUrl' in action:
                        invoke_url_action_found = True
                    elif isinstance(action, list) and 'lambda:InvokeFunctionUrl' in action:
                        invoke_url_action_found = True
                    
                    if invoke_url_action_found:
                        result['has_function_url_policy'] = True
                        
                        # Use the policy_evaluator to analyze conditions in the statement
                        condition_analysis = evaluate_policy_conditions(statement)
                        result['policy_condition_details'].append(condition_analysis)
    except Exception as e:
        logger.error(f"Error checking function URL policy for {function_name}: {e}")
    
    # Check for discrepancies
    if result['has_function_url'] and not result['has_function_url_policy']:
        result['discrepancy'] = True
        result['discrepancy_type'] = 'MISSING_POLICY'
    elif not result['has_function_url'] and result['has_function_url_policy']:
        result['discrepancy'] = True
        result['discrepancy_type'] = 'MISSING_URL'
    
    return result

def check_function_public_access(function_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Check if a Lambda function allows public access through its policy.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict with public access assessment results
    """
    result = {
        'function_name': function_name,
        'is_public': False,
        'policy_analysis': None,
        'error': None
    }
    
    try:
        # Get the function policy
        policy_response = get_policy(function_name, session_context=session_context)
        
        # If no policy exists, the function is not publicly accessible
        if not policy_response or 'Policy' not in policy_response:
            return result
        
        # Parse the policy JSON
        policy_json = json.loads(policy_response['Policy'])
        
        # Use the policy evaluator to check for public access
        is_public, policy_analysis = check_policy_for_public_access(policy_json)
        
        result['is_public'] = is_public
        result['policy_analysis'] = policy_analysis
        
        return result
    except Exception as e:
        error_message = str(e)
        logger.error(f"Error checking public access for Lambda function {function_name}: {error_message}")
        result['error'] = error_message
        return result

def check_function_security(function_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Perform a comprehensive security assessment of a Lambda function.
    
    This function evaluates multiple security aspects of a Lambda function:
    1. Public access through policy
    2. Function URL configuration and discrepancies
    3. Environment variables for sensitive information
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict with comprehensive security assessment results
    """
    result = {
        'function_name': function_name,
        'public_access': None,
        'function_url': None,
        'environment_variables': None,
        'error': None
    }
    
    try:
        # Get function details first
        try:
            function_details = get_function(function_name, session_context=session_context)
            function_config = function_details.get('Configuration', {})
        except Exception as e:
            logger.error(f"Error getting function details for {function_name}: {e}")
            result['error'] = f"Function not found or access denied: {str(e)}"
            return result
        
        # Check for public access
        public_access_result = check_function_public_access(function_name, session_context=session_context)
        result['public_access'] = public_access_result
        
        # Check function URL configuration
        function_url_result = check_function_url_discrepancy(function_name, session_context=session_context)
        result['function_url'] = function_url_result
        
        # Check environment variables
        env_vars = get_function_environment_variables(function_name, session_context=session_context)
        sensitive_env_var_patterns = [
            'key', 'secret', 'token', 'password', 'credential', 'auth', 
            'cert', 'private', 'api_key', 'apikey'
        ]
        
        potentially_sensitive_vars = {}
        for key, value in env_vars.items():
            for pattern in sensitive_env_var_patterns:
                if pattern.lower() in key.lower():
                    potentially_sensitive_vars[key] = value
                    break
        
        result['environment_variables'] = {
            'total_count': len(env_vars),
            'has_potentially_sensitive': len(potentially_sensitive_vars) > 0,
            'potentially_sensitive_count': len(potentially_sensitive_vars),
            'potentially_sensitive_keys': list(potentially_sensitive_vars.keys()),
            'all_keys': list(env_vars.keys())
        }
        
        # Add role information
        role_arn = function_config.get('Role', '')
        result['role'] = {
            'arn': role_arn,
            'name': role_arn.split('/')[-1] if '/' in role_arn else role_arn.split(':')[-1]
        }
        
        # Runtime information
        result['runtime'] = function_config.get('Runtime')
        
        # Add tags
        try:
            tags = get_function_tags(function_name, session_context=session_context)
            result['tags'] = tags
        except Exception as e:
            logger.warning(f"Error getting tags for {function_name}: {e}")
            result['tags'] = {}
        
        return result
    except Exception as e:
        error_message = str(e)
        logger.error(f"Error performing security assessment for Lambda function {function_name}: {error_message}")
        result['error'] = error_message
        return result 