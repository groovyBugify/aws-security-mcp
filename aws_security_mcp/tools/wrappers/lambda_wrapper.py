"""Lambda Service Wrapper for AWS Security MCP.

This wrapper consolidates all Lambda operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing Lambda functions to reuse them
from aws_security_mcp.tools.lambda_tools import (
    list_functions as _list_functions,
    get_function_details as _get_function_details,
    get_function_policy as _get_function_policy,
    list_function_permissions as _list_function_permissions,
    list_function_layers as _list_function_layers,
    list_invocations as _list_invocations
)

logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects."""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def safe_json_dumps(data: Any, **kwargs) -> str:
    """Safely serialize data to JSON, handling datetime objects."""
    return json.dumps(data, cls=DateTimeEncoder, **kwargs)

@register_tool()
async def lambda_security_operations(operation: str, **params) -> str:
    """Lambda Security Operations Hub - Comprehensive serverless function security monitoring.
    
    🔍 FUNCTION DISCOVERY:
    - list_functions: List Lambda functions with optional filtering and pagination
    - get_function_details: Get detailed information about specific Lambda function(s)
    
    🔐 SECURITY ANALYSIS:
    - get_function_policy: Get resource policy for Lambda function(s)
    - list_function_permissions: List permissions granted to invoke a Lambda function
    
    📦 DEPENDENCY ANALYSIS:
    - list_function_layers: List layers used by a Lambda function
    
    📊 ACTIVITY MONITORING:
    - list_invocations: Get recent invocations of a Lambda function from CloudWatch logs
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🔍 List all functions:
    operation="list_functions"
    
    🔍 List functions with search:
    operation="list_functions", search_term="api"
    
    🔍 List functions in specific region:
    operation="list_functions", region="us-west-2"
    
    🔍 List functions with pagination:
    operation="list_functions", next_token="previous_token"
    
    📋 Get function details:
    operation="get_function_details", function_name="my-lambda-function"
    
    📋 Get multiple function details:
    operation="get_function_details", function_name=["function1", "function2", "function3"]
    
    🔐 Get function policy:
    operation="get_function_policy", function_name="my-lambda-function"
    
    🔐 Get multiple function policies:
    operation="get_function_policy", function_name=["function1", "function2"]
    
    🔐 List function permissions:
    operation="list_function_permissions", function_name="my-lambda-function"
    
    📦 List function layers:
    operation="list_function_layers", function_name="my-lambda-function"
    
    📊 Get recent invocations:
    operation="list_invocations", function_name="my-lambda-function"
    
    📊 Get limited invocations:
    operation="list_invocations", function_name="my-lambda-function", limit=5
    
    Args:
        operation: The Lambda operation to perform (see descriptions above)
        
        # Function identification parameters:
        function_name: Lambda function name/ARN (required for function-specific operations)
                      Can be a string for single function or list for multiple functions
        
        # Function discovery parameters:
        region: Optional region to filter functions
        search_term: Optional search term to filter functions by name
        next_token: Pagination token for fetching the next set of functions
        
        # Activity monitoring parameters:
        limit: Maximum number of invocations to return (default: 10)
        
    Returns:
        JSON formatted response with operation results and Lambda security insights
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
            
            result = await _list_functions(
                region=region,
                search_term=search_term,
                next_token=next_token
            )
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        elif operation == "get_function_details":
            function_name = params.get("function_name")
            if not function_name:
                return safe_json_dumps({
                    "error": "function_name parameter is required for get_function_details",
                    "usage": "operation='get_function_details', function_name='my-lambda-function'"
                })
            
            result = await _get_function_details(function_name=function_name)
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        elif operation == "get_function_policy":
            function_name = params.get("function_name")
            if not function_name:
                return safe_json_dumps({
                    "error": "function_name parameter is required for get_function_policy",
                    "usage": "operation='get_function_policy', function_name='my-lambda-function'"
                })
            
            result = await _get_function_policy(function_name=function_name)
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        elif operation == "list_function_permissions":
            function_name = params.get("function_name")
            if not function_name:
                return safe_json_dumps({
                    "error": "function_name parameter is required for list_function_permissions",
                    "usage": "operation='list_function_permissions', function_name='my-lambda-function'"
                })
            
            result = await _list_function_permissions(function_name=function_name)
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        elif operation == "list_function_layers":
            function_name = params.get("function_name")
            if not function_name:
                return safe_json_dumps({
                    "error": "function_name parameter is required for list_function_layers",
                    "usage": "operation='list_function_layers', function_name='my-lambda-function'"
                })
            
            # This returns a formatted string, not JSON, so handle differently
            result = await _list_function_layers(function_name=function_name)
            
            return safe_json_dumps({
                "function_name": function_name,
                "layers_info": result,
                "operation": "list_function_layers"
            })
            
        elif operation == "list_invocations":
            function_name = params.get("function_name")
            if not function_name:
                return safe_json_dumps({
                    "error": "function_name parameter is required for list_invocations",
                    "usage": "operation='list_invocations', function_name='my-lambda-function'"
                })
            
            limit = params.get("limit", 10)
            
            # This returns a formatted string, not JSON, so handle differently
            result = await _list_invocations(function_name=function_name, limit=limit)
            
            return safe_json_dumps({
                "function_name": function_name,
                "limit": limit,
                "invocations_info": result,
                "operation": "list_invocations"
            })
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_functions", "get_function_details", "get_function_policy",
                "list_function_permissions", "list_function_layers", "list_invocations"
            ]
            
            return safe_json_dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_functions": "operation='list_functions'",
                    "get_function_details": "operation='get_function_details', function_name='my-lambda-function'",
                    "get_function_policy": "operation='get_function_policy', function_name='my-lambda-function'",
                    "list_function_permissions": "operation='list_function_permissions', function_name='my-lambda-function'",
                    "list_function_layers": "operation='list_function_layers', function_name='my-lambda-function'",
                    "list_invocations": "operation='list_invocations', function_name='my-lambda-function'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in Lambda operation '{operation}': {e}")
        return safe_json_dumps({
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
    and practical usage examples for serverless function security monitoring.
    
    Returns:
        Detailed catalog of Lambda operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Lambda (Serverless Computing)",
        "description": "Serverless function security monitoring and analysis",
        "wrapper_tool": "lambda_security_operations",
        "supported_features": {
            "function_discovery": "Find and list Lambda functions with filtering capabilities",
            "security_analysis": "Analyze function policies, permissions, and access controls",
            "dependency_analysis": "Examine function layers and dependencies",
            "activity_monitoring": "Monitor function invocations and performance",
            "policy_evaluation": "Deep analysis of resource policies and permissions",
            "vulnerability_assessment": "Identify security risks and misconfigurations"
        },
        "operation_categories": {
            "function_discovery": {
                "list_functions": {
                    "description": "List Lambda functions with optional filtering and pagination",
                    "parameters": {
                        "region": {"type": "str", "description": "Optional region to filter functions"},
                        "search_term": {"type": "str", "default": "", "description": "Optional search term to filter functions by name"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching the next set of functions"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='list_functions')",
                        "lambda_security_operations(operation='list_functions', search_term='api')",
                        "lambda_security_operations(operation='list_functions', region='us-west-2')",
                        "lambda_security_operations(operation='list_functions', next_token='previous_token')"
                    ]
                },
                "get_function_details": {
                    "description": "Get detailed information about specific Lambda function(s)",
                    "parameters": {
                        "function_name": {"type": "str or List[str]", "required": True, "description": "Lambda function name/ARN or list of function names/ARNs"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='get_function_details', function_name='my-lambda-function')",
                        "lambda_security_operations(operation='get_function_details', function_name=['function1', 'function2', 'function3'])",
                        "lambda_security_operations(operation='get_function_details', function_name='arn:aws:lambda:us-east-1:123456789012:function:MyFunction')"
                    ]
                }
            },
            "security_analysis": {
                "get_function_policy": {
                    "description": "Get resource policy for Lambda function(s)",
                    "parameters": {
                        "function_name": {"type": "str or List[str]", "required": True, "description": "Lambda function name/ARN or list of function names/ARNs"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='get_function_policy', function_name='my-lambda-function')",
                        "lambda_security_operations(operation='get_function_policy', function_name=['function1', 'function2'])"
                    ]
                },
                "list_function_permissions": {
                    "description": "List permissions granted to invoke a Lambda function",
                    "parameters": {
                        "function_name": {"type": "str", "required": True, "description": "Lambda function name/ARN"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='list_function_permissions', function_name='my-lambda-function')",
                        "lambda_security_operations(operation='list_function_permissions', function_name='api-gateway-function')"
                    ]
                }
            },
            "dependency_analysis": {
                "list_function_layers": {
                    "description": "List layers used by a Lambda function",
                    "parameters": {
                        "function_name": {"type": "str", "required": True, "description": "Lambda function name/ARN"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='list_function_layers', function_name='my-lambda-function')",
                        "lambda_security_operations(operation='list_function_layers', function_name='data-processing-function')"
                    ]
                }
            },
            "activity_monitoring": {
                "list_invocations": {
                    "description": "Get recent invocations of a Lambda function from CloudWatch logs",
                    "parameters": {
                        "function_name": {"type": "str", "required": True, "description": "Lambda function name/ARN"},
                        "limit": {"type": "int", "default": 10, "description": "Maximum number of invocations to return"}
                    },
                    "examples": [
                        "lambda_security_operations(operation='list_invocations', function_name='my-lambda-function')",
                        "lambda_security_operations(operation='list_invocations', function_name='my-lambda-function', limit=5)",
                        "lambda_security_operations(operation='list_invocations', function_name='monitoring-function', limit=20)"
                    ]
                }
            }
        },
        "lambda_security_insights": {
            "common_operations": [
                "List all functions: operation='list_functions'",
                "Get function details: operation='get_function_details', function_name='my-function'",
                "Get function policy: operation='get_function_policy', function_name='my-function'",
                "Check function permissions: operation='list_function_permissions', function_name='my-function'"
            ],
            "security_monitoring_patterns": [
                "Audit function resource policies and cross-account access",
                "Monitor function URL configurations and authentication settings",
                "Review IAM execution roles and their permissions",
                "Check for functions with overly permissive policies",
                "Analyze function environment variables for sensitive data",
                "Monitor function invocation patterns and anomalies",
                "Review function layers for security vulnerabilities",
                "Check function VPC configurations and network access"
            ],
            "security_best_practices": [
                "Use least privilege IAM roles for function execution",
                "Avoid storing sensitive data in environment variables",
                "Enable function-level concurrent execution limits",
                "Use VPC configurations for functions accessing private resources",
                "Implement proper authentication for function URLs",
                "Regularly update function runtime versions",
                "Use AWS Secrets Manager for sensitive configuration",
                "Monitor function logs for security events",
                "Implement proper error handling to prevent information leakage",
                "Use resource-based policies for fine-grained access control"
            ],
            "compliance_considerations": [
                "Ensure functions comply with data residency requirements",
                "Implement proper audit logging for compliance tracking",
                "Review function access patterns for regulatory compliance",
                "Ensure sensitive data is properly encrypted at rest and in transit",
                "Implement proper data retention policies for function logs",
                "Monitor for unauthorized function modifications",
                "Ensure proper segregation of duties in function management",
                "Implement compliance monitoring for function configurations"
            ],
            "vulnerability_assessment": [
                "Check for functions with public access (AuthType=NONE)",
                "Identify functions with overly broad resource policies",
                "Monitor for functions using deprecated runtime versions",
                "Check for hardcoded credentials in function code",
                "Identify functions with excessive IAM permissions",
                "Monitor for functions exposed through insecure triggers",
                "Check for functions with disabled CloudTrail logging",
                "Identify functions with weak or missing authentication"
            ],
            "performance_and_cost": [
                "Monitor function memory and timeout configurations",
                "Analyze function invocation patterns for optimization",
                "Review function cold start performance",
                "Monitor function cost and usage patterns",
                "Check for unused or idle functions",
                "Analyze function layer usage and optimization opportunities",
                "Monitor function concurrent execution limits",
                "Review function provisioned concurrency settings"
            ],
            "integration_security": [
                "Monitor API Gateway integration security",
                "Review S3 trigger configurations and permissions",
                "Check EventBridge rule configurations",
                "Analyze SQS and SNS trigger security settings",
                "Review CloudWatch Events integration",
                "Monitor DynamoDB stream trigger configurations",
                "Check Kinesis stream integration security",
                "Review Application Load Balancer target configurations"
            ]
        }
    }
    
    return safe_json_dumps(operations_catalog, indent=2) 