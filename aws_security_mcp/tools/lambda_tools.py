"""Lambda tools for AWS Security MCP."""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union

from aws_security_mcp.services import lambda_service
from aws_security_mcp.tools import register_tool
from aws_security_mcp.utils.policy_evaluator import evaluate_policy_conditions
# Import lambda formatters from the correct module
from aws_security_mcp.formatters.lambda_formatter import (
    format_lambda_function_json,
    format_lambda_functions_summary_json,
    format_lambda_alias_json,
    format_lambda_event_source_mapping_json,
    format_lambda_layer_json,
    format_function_url_config_json,
    format_function_url_discrepancy_json
)

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
async def list_functions(region: Optional[str] = None, search_term: str = "", next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List Lambda functions in the AWS account.
    
    Args:
        region: Optional region to filter functions
        search_term: Optional search term to filter functions by name
        next_token: Pagination token for fetching the next set of functions (optional)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with Lambda functions
    """
    logger.info(f"Listing Lambda functions in region {region if region else 'all regions'} (search_term='{search_term}', next_token={next_token})")
    
    try:
        # Create client kwargs dictionary
        client_kwargs = {}
        if region:
            client_kwargs['region_name'] = region
        if session_context:
            client_kwargs['session_context'] = session_context
        
        # Get functions with optional region - now automatically includes all functions with pagination
        functions_response = lambda_service.get_all_functions(
            search_term=search_term, 
            marker=next_token,
            **client_kwargs
        )
        
        functions = functions_response['functions']
        marker = functions_response['marker']
        
        if not functions:
            return json.dumps({
                "count": 0,
                "summary": f"No Lambda functions found{' matching ' + search_term if search_term else ''}",
                "functions": [],
                "pagination": {
                    "next_token": None,
                    "is_truncated": False
                }
            })
        
        # Format each function using the JSON formatter
        formatted_functions = [format_lambda_function_json(function) for function in functions]
        
        # Create summary information
        summary_data = format_lambda_functions_summary_json(functions)
        
        # Prepare response
        formatted_data = {
            "count": len(functions),
            "summary": summary_data,
            "functions": formatted_functions,
            "pagination": {
                "next_token": marker,
                "is_truncated": marker is not None
            }
        }
        
        # Add region information if provided
        if region:
            formatted_data["region"] = region
        
        # Add search term if provided
        if search_term:
            formatted_data["search_term"] = search_term
            formatted_data["description"] = f"Found {len(functions)} Lambda function(s) matching '{search_term}'"
        
        return json.dumps(formatted_data, default=lambda o: o.isoformat() if hasattr(o, 'isoformat') else str(o))
        
    except Exception as e:
        logger.error(f"Error listing Lambda functions: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing Lambda functions: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def get_function_details(function_name: Union[str, List[str]], session_context: Optional[str] = None) -> str:
    """Get detailed information about one or more Lambda functions.
    
    Args:
        function_name: Name/ARN of the Lambda function, or a list of function names/ARNs
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with Lambda function details
        
    Examples:
        # Single account (default)
        get_function_details("my-function")
        
        # Cross-account access
        get_function_details("my-function", session_context="123456789012_aws_dev")
    """
    # Handle single function name vs list of names
    if isinstance(function_name, str):
        logger.info(f"Getting details for Lambda function: {function_name}")
        single_function = True
        function_names = [function_name]
    else:
        logger.info(f"Getting details for multiple Lambda functions: {function_name}")
        single_function = False
        function_names = function_name
        
    all_results = []
    
    for fn_name in function_names:
        try:
            # Get function details
            function = lambda_service.get_function(fn_name, session_context=session_context)
            
            if not function:
                result = {
                    "function_name": fn_name,
                    "error": f"Lambda function '{fn_name}' not found"
                }
                all_results.append(result)
                continue
            
            # Extract function configuration
            config = function.get('Configuration', {})
            
            # Use the JSON formatter for better structured output
            formatted_data = format_lambda_function_json(config)
            
            # Add code location if available
            code_info = function.get('Code', {})
            location = code_info.get('Location')
            if location:
                formatted_data["code_location"] = location
            
            # Get policy and add to result
            policy_json = None
            try:
                policy = lambda_service.get_policy(fn_name, session_context=session_context)
                if policy:
                    policy_document = policy.get('Policy', '{}')
                    
                    # Parse the policy
                    try:
                        policy_json = json.loads(policy_document)
                        formatted_data["resource_policy"] = policy_json
                        
                        # Add detailed policy analysis
                        policy_analysis = {
                            "has_policy": True,
                            "statement_count": 0,
                            "statements_analyzed": []
                        }
                        
                        # Analyze each statement in the policy
                        statements = policy_json.get('Statement', [])
                        if isinstance(statements, dict):
                            statements = [statements]
                            
                        policy_analysis["statement_count"] = len(statements)
                        has_conditions = False
                        has_function_url_permissions = False
                        
                        for statement in statements:
                            statement_info = {
                                "sid": statement.get('Sid', 'No SID'),
                                "effect": statement.get('Effect', 'Unknown'),
                                "principal": statement.get('Principal', {}),
                                "action": statement.get('Action', []),
                                "resource": statement.get('Resource', []),
                            }
                            
                            # Check if statement relates to function URL
                            action = statement.get('Action')
                            invoke_url_action_found = False
                            
                            if isinstance(action, str) and 'lambda:InvokeFunctionUrl' in action:
                                invoke_url_action_found = True
                                has_function_url_permissions = True
                            elif isinstance(action, list) and 'lambda:InvokeFunctionUrl' in action:
                                invoke_url_action_found = True
                                has_function_url_permissions = True
                            
                            statement_info["is_function_url_related"] = invoke_url_action_found
                            
                            # Analyze conditions in the statement
                            conditions = statement.get('Condition', {})
                            if conditions:
                                has_conditions = True
                                # Use the policy_evaluator utility for condition analysis
                                condition_analysis = evaluate_policy_conditions(statement)
                                statement_info["conditions"] = condition_analysis
                                statement_info["has_strong_restrictions"] = condition_analysis.get('restriction_level') == 'Strong'
                                statement_info["potential_public_access"] = condition_analysis.get('potential_public_access', True)
                            else:
                                statement_info["has_conditions"] = False
                            
                            policy_analysis["statements_analyzed"].append(statement_info)
                        
                        policy_analysis["has_conditional_statements"] = has_conditions
                        policy_analysis["has_function_url_permissions"] = has_function_url_permissions
                        
                        formatted_data["policy_analysis"] = policy_analysis
                        
                    except json.JSONDecodeError:
                        formatted_data["resource_policy"] = {
                            "error": "Failed to parse policy document",
                            "raw_policy": policy_document
                        }
                        formatted_data["policy_analysis"] = {
                            "has_policy": True,
                            "error": "Failed to parse policy document for analysis"
                        }
                else:
                    formatted_data["policy_analysis"] = {
                        "has_policy": False,
                        "message": "No resource policy found for this function"
                    }
            except Exception as policy_error:
                formatted_data["resource_policy"] = {
                    "error": f"Error retrieving policy: {str(policy_error)}"
                }
                formatted_data["policy_analysis"] = {
                    "has_policy": False,
                    "error": f"Error retrieving policy: {str(policy_error)}"
                }
            
            # Function URL security analysis
            formatted_data["function_url_security"] = {}
            url_security = formatted_data["function_url_security"]
            
            try:
                # Get function URL configuration if available
                url_config = lambda_service.get_function_url_config(fn_name, session_context=session_context)
                
                if url_config:
                    url_security["has_function_url"] = True
                    url_security["function_url"] = url_config.get('FunctionUrl')
                    url_security["auth_type"] = url_config.get('AuthType')
                    
                    # Format the full URL config
                    formatted_data["function_url_config"] = format_function_url_config_json(url_config)
                    
                    # Check for potential discrepancies between function URL and policy
                    discrepancy_check = lambda_service.check_function_url_discrepancy(fn_name, session_context=session_context)
                    formatted_discrepancy = format_function_url_discrepancy_json(discrepancy_check)
                    
                    # Add detailed security assessment
                    # Check security implications
                    if url_config.get('AuthType') == 'NONE':
                        url_security["security_level"] = "High"
                        url_security["security_issue"] = True
                        url_security["description"] = "Function URL is publicly accessible without authentication"
                        url_security["recommendation"] = "Consider changing AuthType to AWS_IAM or implement custom authorization"
                    else:
                        url_security["security_level"] = "Low"
                        url_security["security_issue"] = False
                        url_security["description"] = "Function URL requires AWS IAM authentication"
                    
                    # Policy conditions analysis
                    has_policy_conditions = False
                    has_strong_conditions = False
                    
                    if discrepancy_check.get('policy_condition_details'):
                        for condition in discrepancy_check.get('policy_condition_details', []):
                            if condition.get('has_conditions'):
                                has_policy_conditions = True
                                if condition.get('restriction_level') == 'Strong':
                                    has_strong_conditions = True
                                    break
                    
                    url_security["has_policy_conditions"] = has_policy_conditions
                    url_security["has_strong_conditions"] = has_strong_conditions
                    
                    if has_policy_conditions:
                        url_security["policy_conditions"] = formatted_discrepancy.get("policy_conditions", {})
                        
                        # Update security assessment if strong conditions exist
                        if has_strong_conditions and url_config.get('AuthType') == 'NONE':
                            url_security["security_level"] = "Medium"
                            url_security["description"] += " (mitigated by strong policy conditions)"
                    
                    # Add discrepancy information if detected
                    if discrepancy_check and discrepancy_check.get('discrepancy'):
                        url_security["discrepancy_detected"] = True
                        url_security["discrepancy_type"] = discrepancy_check.get('discrepancy_type')
                        url_security["discrepancy_details"] = formatted_discrepancy
                        
                        if discrepancy_check.get('discrepancy_type') == 'MISSING_URL':
                            url_security["security_level"] = "Medium"
                            url_security["security_issue"] = True
                            url_security["recommendation"] = "Remove unused function URL permissions from the resource policy"
                        elif discrepancy_check.get('discrepancy_type') == 'MISSING_POLICY':
                            if discrepancy_check.get('auth_type') == 'NONE':
                                url_security["note"] = "Function URL is public but no explicit policy exists - this is normal with AuthType=NONE"
                            else:
                                url_security["security_level"] = "Low"
                                url_security["recommendation"] = "Consider adding an explicit resource policy for the function URL"
                    else:
                        url_security["discrepancy_detected"] = False
                else:
                    url_security["has_function_url"] = False
                    url_security["description"] = "No function URL configured for this Lambda function"
                    
                    # Check if policy grants function URL permissions without URL configured
                    if policy_json:
                        statements = policy_json.get('Statement', [])
                        has_function_url_permissions = False
                        
                        for statement in statements:
                            action = statement.get('Action')
                            if isinstance(action, str) and 'lambda:InvokeFunctionUrl' in action:
                                has_function_url_permissions = True
                                break
                            elif isinstance(action, list) and 'lambda:InvokeFunctionUrl' in action:
                                has_function_url_permissions = True
                                break
                        
                        if has_function_url_permissions:
                            url_security["security_issue"] = True
                            url_security["security_level"] = "Low"
                            url_security["description"] = "Policy grants function URL permissions, but no function URL is configured"
                            url_security["recommendation"] = "Remove unused function URL permissions from resource policy"
                
                # Add consolidated security assessment 
                security_assessment = {
                    "security_level": url_security.get("security_level", "Low"),
                    "issues": [],
                    "recommendations": []
                }
                
                # Collect identified issues
                if url_security.get("security_issue"):
                    security_assessment["issues"].append(url_security.get("description", ""))
                
                # Add recommendation if present
                if url_security.get("recommendation"):
                    security_assessment["recommendations"].append(url_security.get("recommendation"))
                
                formatted_data["security_assessment"] = security_assessment
                
            except Exception as url_error:
                url_security["error"] = f"Error analyzing function URL: {str(url_error)}"
            
            all_results.append(formatted_data)
            
        except Exception as e:
            logger.error(f"Error getting Lambda function details: {e}")
            all_results.append({
                "function_name": fn_name,
                "error": {
                    "message": f"Error getting Lambda function details: {str(e)}",
                    "type": type(e).__name__
                }
            })
    
    # Return single result or list depending on input
    if single_function:
        return json.dumps(all_results[0], default=lambda o: o.isoformat() if hasattr(o, 'isoformat') else str(o))
    else:
        return json.dumps(all_results, default=lambda o: o.isoformat() if hasattr(o, 'isoformat') else str(o))


@register_tool()
async def get_function_policy(function_name: Union[str, List[str]], session_context: Optional[str] = None) -> str:
    """Get the resource policy for one or more Lambda functions.
    
    Args:
        function_name: Name or ARN of the Lambda function, or a list of function names/ARNs
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with Lambda function policies
        
    Examples:
        # Single account (default)
        get_function_policy("my-function")
        
        # Cross-account access
        get_function_policy("my-function", session_context="123456789012_aws_dev")
    """
    # If a single function name is provided, convert to list for consistent processing
    if isinstance(function_name, str):
        function_names = [function_name]
        logger.info(f"Getting policy for Lambda function: {function_name}")
    else:
        function_names = function_name
        logger.info(f"Getting policies for {len(function_names)} Lambda functions")
    
    results = []
    
    for fn_name in function_names:
        try:
            policy = lambda_service.get_policy(fn_name, session_context=session_context)
            
            result = {
                "functionName": fn_name,
                "result": "success" if policy else "no_policy",
                "policy": None
            }
            
            if policy:
                policy_document = policy.get('Policy', '{}')
                revision_id = policy.get('RevisionId', 'Unknown')
                
                # Parse and format the policy
                try:
                    policy_json = json.loads(policy_document)
                    result["policy"] = policy_json
                    result["revision_id"] = revision_id
                except json.JSONDecodeError:
                    result["result"] = "parse_error"
                    result["error"] = "Invalid JSON in policy document"
                    result["raw_policy"] = policy_document
            
            results.append(result)
        except Exception as e:
            logger.error(f"Error getting policy for Lambda function '{fn_name}': {e}")
            results.append({
                "functionName": fn_name,
                "result": "error",
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    # If only one function was requested, return just that result for backwards compatibility
    if len(results) == 1 and isinstance(function_name, str):
        return json.dumps(results[0], indent=2)
    
    # Otherwise return the array of results
    return json.dumps(results, indent=2)


@register_tool()
async def list_function_permissions(function_name: str, session_context: Optional[str] = None) -> str:
    """List permissions granted to invoke a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with Lambda function permissions
        
    Examples:
        # Single account (default)
        list_function_permissions("my-function")
        
        # Cross-account access
        list_function_permissions("my-function", session_context="123456789012_aws_dev")
    """
    logger.info(f"Listing permissions for Lambda function: {function_name}")
    
    try:
        policy = lambda_service.get_policy(function_name, session_context=session_context)
        
        if not policy or 'Policy' not in policy:
            return json.dumps({
                "function_name": function_name,
                "count": 0,
                "permissions": [],
                "summary": f"No permissions found for Lambda function '{function_name}'"
            })
        
        policy_document = policy.get('Policy', '{}')
        
        # Parse the policy
        try:
            policy_json = json.loads(policy_document)
            statements = policy_json.get('Statement', [])
            
            permissions = []
            for statement in statements:
                sid = statement.get('Sid', '')
                effect = statement.get('Effect', 'Unknown')
                principal = statement.get('Principal', {})
                action = statement.get('Action', 'Unknown')
                condition = statement.get('Condition', {})
                
                # Format the principal for better readability
                principal_formatted = {}
                if isinstance(principal, dict):
                    principal_formatted = principal
                else:
                    principal_formatted = {"Value": str(principal)}
                
                permission = {
                    "sid": sid,
                    "effect": effect,
                    "principal": principal_formatted,
                    "action": action
                }
                
                if condition:
                    permission["condition"] = condition
                    
                permissions.append(permission)
            
            result = {
                "function_name": function_name,
                "count": len(permissions),
                "permissions": permissions,
                "summary": f"Found {len(permissions)} permission(s) for Lambda function '{function_name}'"
            }
            
            return json.dumps(result, default=lambda o: o.isoformat() if hasattr(o, 'isoformat') else str(o))
        except json.JSONDecodeError:
            return json.dumps({
                "error": {
                    "message": f"Error parsing policy for Lambda function '{function_name}': Invalid JSON",
                    "raw_policy": policy_document
                }
            })
    except Exception as e:
        logger.error(f"Error listing Lambda function permissions: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing permissions for Lambda function '{function_name}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def list_function_layers(function_name: str, session_context: Optional[str] = None) -> str:
    """List layers used by a Lambda function.
    
    Args:
        function_name: Name or ARN of the Lambda function
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Formatted string with Lambda function layers
        
    Examples:
        # Single account (default)
        list_function_layers("my-function")
        
        # Cross-account access
        list_function_layers("my-function", session_context="123456789012_aws_dev")
    """
    logger.info(f"Listing layers for Lambda function: {function_name}")
    
    try:
        function = lambda_service.get_function(function_name, session_context=session_context)
        
        if not function:
            return f"Lambda function '{function_name}' not found"
        
        config = function.get('Configuration', {})
        layers = config.get('Layers', [])
        
        if not layers:
            return f"No layers found for Lambda function '{function_name}'"
        
        results = []
        for layer in layers:
            layer_arn = layer.get('Arn', 'Unknown')
            layer_name = layer_arn.split(':layer:')[1].split(':')[0] if ':layer:' in layer_arn else 'Unknown'
            layer_version = layer.get('Version', 'Unknown')
            code_size = layer.get('CodeSize', 0)
            
            # Format result
            result = f"Layer: {layer_name}\n"
            result += f"ARN: {layer_arn}\n"
            result += f"Version: {layer_version}\n"
            
            # Format code size
            if code_size:
                if code_size < 1024:
                    result += f"Code Size: {code_size} B\n"
                elif code_size < 1024 * 1024:
                    result += f"Code Size: {code_size / 1024:.2f} KB\n"
                else:
                    result += f"Code Size: {code_size / (1024 * 1024):.2f} MB\n"
            
            results.append(result)
        
        return f"Layers for Lambda function '{function_name}':\n\n" + "\n\n".join(results)
    except Exception as e:
        logger.error(f"Error listing Lambda function layers: {e}")
        return f"Error listing layers for Lambda function '{function_name}': {str(e)}"


@register_tool()
async def list_invocations(function_name: str, limit: int = 10, session_context: Optional[str] = None) -> str:
    """Get recent invocations of a Lambda function from CloudWatch logs.
    
    Args:
        function_name: Name or ARN of the Lambda function
        limit: Maximum number of invocations to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Formatted string with recent Lambda function invocations
        
    Examples:
        # Single account (default)
        list_invocations("my-function", limit=5)
        
        # Cross-account access
        list_invocations("my-function", limit=5, session_context="123456789012_aws_dev")
    """
    logger.info(f"Getting recent invocations for Lambda function: {function_name} (limit={limit})")
    
    try:
        invocations = lambda_service.get_recent_invocations(function_name, limit=limit, session_context=session_context)
        
        if not invocations:
            return f"No recent invocations found for Lambda function '{function_name}'"
        
        results = []
        for invocation in invocations:
            timestamp = invocation.get('timestamp')
            request_id = invocation.get('request_id', 'Unknown')
            status = invocation.get('status', 'Unknown')
            duration = invocation.get('duration', 'Unknown')
            memory_used = invocation.get('memory_used', 'Unknown')
            
            # Format timestamp
            if isinstance(timestamp, datetime):
                formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            else:
                formatted_time = str(timestamp)
            
            # Format result
            result = f"Invocation Time: {formatted_time}\n"
            result += f"Request ID: {request_id}\n"
            result += f"Status: {status}\n"
            
            if duration != 'Unknown':
                result += f"Duration: {duration:.2f} ms\n"
            
            if memory_used != 'Unknown':
                result += f"Memory Used: {memory_used:.2f} MB\n"
            
            results.append(result)
        
        return f"Recent invocations for Lambda function '{function_name}':\n\n" + "\n\n".join(results)
    except Exception as e:
        logger.error(f"Error getting Lambda function invocations: {e}")
        return f"Error getting recent invocations for Lambda function '{function_name}': {str(e)}" 