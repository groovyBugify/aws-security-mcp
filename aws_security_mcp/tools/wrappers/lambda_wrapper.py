"""Lambda Service Wrapper for AWS Security MCP.

This wrapper consolidates all AWS Lambda operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union

from aws_security_mcp.tools import register_tool

# Import existing lambda functions to reuse them
from aws_security_mcp.tools.lambda_tools import (
    list_functions as _list_functions,
    get_function_details as _get_function_details,
    get_function_policy as _get_function_policy,
    list_function_permissions as _list_function_permissions,
    list_function_layers as _list_function_layers,
    list_invocations as _list_invocations
)

logger = logging.getLogger(__name__)

@register_tool()
async def lambda_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """Lambda Operations Hub - Serverless function security analysis and management.
    
    🔍 FUNCTION DISCOVERY:
    - list_functions: List Lambda functions with optional filtering and pagination
    - get_function_details: Get comprehensive details about specific functions
    
    🔐 POLICY ANALYSIS:
    - get_function_policy: Retrieve resource policies for Lambda functions
    - list_function_permissions: List permissions granted to invoke functions
    
    📦 DEPENDENCY INSPECTION:
    - list_function_layers: List layers used by Lambda functions
    
    📊 MONITORING & LOGS:
    - list_invocations: Get recent function invocations from CloudWatch logs
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🔍 List all Lambda functions:
    lambda_security_operations(operation="list_functions")
    
    🔍 Search for specific functions:
    lambda_security_operations(operation="list_functions", search_term="api", region="us-east-1")
    
    🔐 Get function details with security analysis:
    lambda_security_operations(operation="get_function_details", function_name="my-function")
    
    🔐 Analyze function policies:
    lambda_security_operations(operation="get_function_policy", function_name=["func1", "func2"])
    
    📦 Check function dependencies:
    lambda_security_operations(operation="list_function_layers", function_name="my-function")
    
    📊 Monitor recent invocations:
    lambda_security_operations(operation="list_invocations", function_name="my-function", limit=20)
    
    🌐 CROSS-ACCOUNT ACCESS:
    All operations support cross-account access using session_context parameter:
    lambda_security_operations(operation="list_functions", session_context="123456789012_aws_dev")
    
    Args:
        operation: The Lambda operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
        # Function parameters:
        function_name: Name/ARN of Lambda function (str or list for batch operations)
        region: AWS region for function listing
        search_term: Search term to filter functions by name
        
        # Pagination parameters:
        next_token: Pagination token for continued results
        limit: Maximum number of items to return
        
        # Monitoring parameters:
        limit: Number of recent invocations to retrieve (for list_invocations)
        
    Returns:
        JSON formatted response with operation results and Lambda insights
        
    Examples:
        # Single account operations
        lambda_security_operations(operation="list_functions", search_term="api")
        lambda_security_operations(operation="get_function_details", function_name="my-function")
        
        # Cross-account operations
        lambda_security_operations(operation="list_functions", session_context="123456789012_aws_dev")
        lambda_security_operations(operation="get_function_policy", function_name="my-function", session_context="123456789012_aws_dev")
    """
    
    logger.info(f"Lambda operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_functions":
            region = params.get("region")
            search_term = params.get("search_term", "")
            next_token = params.get("next_token")
            
            return await _list_functions(
                region=region,
                search_term=search_term,
                next_token=next_token,
                session_context=session_context
            )
            
        elif operation == "get_function_details":
            function_name = params.get("function_name")
            if not function_name:
                return json.dumps({
                    "error": "function_name parameter is required for get_function_details",
                    "usage": "operation='get_function_details', function_name='my-function'"
                })
            
            return await _get_function_details(
                function_name=function_name,
                session_context=session_context
            )
            
        elif operation == "get_function_policy":
            function_name = params.get("function_name")
            if not function_name:
                return json.dumps({
                    "error": "function_name parameter is required for get_function_policy",
                    "usage": "operation='get_function_policy', function_name='my-function'"
                })
            
            return await _get_function_policy(
                function_name=function_name,
                session_context=session_context
            )
            
        elif operation == "list_function_permissions":
            function_name = params.get("function_name")
            if not function_name:
                return json.dumps({
                    "error": "function_name parameter is required for list_function_permissions",
                    "usage": "operation='list_function_permissions', function_name='my-function'"
                })
            
            return await _list_function_permissions(
                function_name=function_name,
                session_context=session_context
            )
            
        elif operation == "list_function_layers":
            function_name = params.get("function_name")
            if not function_name:
                return json.dumps({
                    "error": "function_name parameter is required for list_function_layers",
                    "usage": "operation='list_function_layers', function_name='my-function'"
                })
            
            return await _list_function_layers(
                function_name=function_name,
                session_context=session_context
            )
            
        elif operation == "list_invocations":
            function_name = params.get("function_name")
            if not function_name:
                return json.dumps({
                    "error": "function_name parameter is required for list_invocations",
                    "usage": "operation='list_invocations', function_name='my-function'"
                })
            
            limit = params.get("limit", 10)
            
            return await _list_invocations(
                function_name=function_name,
                limit=limit,
                session_context=session_context
            )
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_functions", "get_function_details", "get_function_policy",
                "list_function_permissions", "list_function_layers", "list_invocations"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_functions": "operation='list_functions', search_term='api'",
                    "get_function_details": "operation='get_function_details', function_name='my-function'",
                    "get_function_policy": "operation='get_function_policy', function_name='my-function'",
                    "list_invocations": "operation='list_invocations', function_name='my-function', limit=20"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in Lambda operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing Lambda operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_lambda_operations() -> str:
    """Discover all available Lambda operations with detailed usage examples.
    
    This tool provides comprehensive documentation of Lambda operations available
    through the lambda_security_operations tool, including parameter requirements
    and practical usage examples.
    
    Returns:
        Detailed catalog of Lambda operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Lambda",
        "description": "Serverless function security analysis and management",
        "wrapper_tool": "lambda_security_operations",
        "cross_account_support": True,
        "operation_categories": {
            "function_discovery": {
                "list_functions": {
                    "description": "List Lambda functions with optional filtering and pagination",
                    "parameters": {
                        "region": {"type": "str", "description": "AWS region to filter functions"},
                        "search_term": {"type": "str", "description": "Search term to filter functions by name"},
                        "next_token": {"type": "str", "description": "Pagination token for continued results"},
                        "session_context": {"type": "str", "description": "Cross-account session key"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='list_functions')",
                        "lambda_security_operations(operation='list_functions', search_term='api')",
                        "lambda_security_operations(operation='list_functions', region='us-east-1')",
                        "lambda_security_operations(operation='list_functions', session_context='123456789012_aws_dev')"
                    ]
                },
                "get_function_details": {
                    "description": "Get comprehensive details about Lambda functions including security analysis",
                    "parameters": {
                        "function_name": {"type": "str|list", "required": True, "description": "Function name/ARN or list of names"},
                        "session_context": {"type": "str", "description": "Cross-account session key"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='get_function_details', function_name='my-function')",
                        "lambda_security_operations(operation='get_function_details', function_name=['func1', 'func2'])",
                        "lambda_security_operations(operation='get_function_details', function_name='my-function', session_context='123456789012_aws_dev')"
                    ]
                }
            },
            "policy_analysis": {
                "get_function_policy": {
                    "description": "Retrieve resource policies for Lambda functions",
                    "parameters": {
                        "function_name": {"type": "str|list", "required": True, "description": "Function name/ARN or list of names"},
                        "session_context": {"type": "str", "description": "Cross-account session key"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='get_function_policy', function_name='my-function')",
                        "lambda_security_operations(operation='get_function_policy', function_name=['func1', 'func2'])"
                    ]
                },
                "list_function_permissions": {
                    "description": "List permissions granted to invoke Lambda functions",
                    "parameters": {
                        "function_name": {"type": "str", "required": True, "description": "Function name or ARN"},
                        "session_context": {"type": "str", "description": "Cross-account session key"}
                    },
                    "example": "lambda_security_operations(operation='list_function_permissions', function_name='my-function')"
                }
            },
            "dependency_inspection": {
                "list_function_layers": {
                    "description": "List layers used by Lambda functions",
                    "parameters": {
                        "function_name": {"type": "str", "required": True, "description": "Function name or ARN"},
                        "session_context": {"type": "str", "description": "Cross-account session key"}
                    },
                    "example": "lambda_security_operations(operation='list_function_layers', function_name='my-function')"
                }
            },
            "monitoring_and_logs": {
                "list_invocations": {
                    "description": "Get recent function invocations from CloudWatch logs",
                    "parameters": {
                        "function_name": {"type": "str", "required": True, "description": "Function name or ARN"},
                        "limit": {"type": "int", "description": "Maximum number of invocations to return"},
                        "session_context": {"type": "str", "description": "Cross-account session key"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='list_invocations', function_name='my-function')",
                        "lambda_security_operations(operation='list_invocations', function_name='my-function', limit=20)"
                    ]
                }
            }
        },
        "lambda_insights": {
            "common_operations": [
                "List all functions: operation='list_functions'",
                "Search functions: operation='list_functions', search_term='api'",
                "Analyze function security: operation='get_function_details', function_name='my-function'",
                "Check function policies: operation='get_function_policy', function_name='my-function'",
                "Monitor invocations: operation='list_invocations', function_name='my-function'"
            ],
            "security_best_practices": [
                "Regularly audit function resource policies for public access",
                "Monitor function URLs for proper authentication settings", 
                "Review environment variables for sensitive data exposure",
                "Check function execution roles for least privilege",
                "Analyze function invocation patterns for anomalies"
            ],
            "cross_account_patterns": [
                "Use session_context for cross-account function analysis",
                "Batch analyze functions across multiple accounts",
                "Compare function configurations between environments",
                "Audit cross-account function access patterns"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 