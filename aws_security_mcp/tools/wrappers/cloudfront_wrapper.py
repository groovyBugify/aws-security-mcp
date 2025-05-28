"""CloudFront Service Wrapper for AWS Security MCP.

This wrapper consolidates all CloudFront operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing CloudFront functions to reuse them
from aws_security_mcp.tools.cloudfront_tools import (
    list_distributions as _list_distributions,
    get_distribution_details as _get_distribution_details,
    list_cache_policies as _list_cache_policies,
    list_origin_request_policies as _list_origin_request_policies,
    list_response_headers_policies as _list_response_headers_policies,
    get_distribution_invalidations as _get_distribution_invalidations,
    search_distribution as _search_distribution
)

logger = logging.getLogger(__name__)

@register_tool()
async def cloudfront_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """CloudFront Operations Hub - Comprehensive content delivery network management and monitoring.
    
    ☁️ DISTRIBUTION DISCOVERY:
    - list_distributions: List all CloudFront distributions with optional pagination
    - get_distribution_details: Get detailed information about a specific distribution
    - search_distribution: Search for distributions by domain, ID, or alias
    
    📋 POLICY MANAGEMENT:
    - list_cache_policies: List available cache policies
    - list_origin_request_policies: List origin request policies
    - list_response_headers_policies: List response headers policies
    
    🔄 INVALIDATION MONITORING:
    - get_distribution_invalidations: Get invalidation history for a distribution
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    ☁️ List all distributions:
    operation="list_distributions"
    
    🔍 Search for specific distribution:
    operation="search_distribution", identifier="example.com"
    
    📊 Get distribution details:
    operation="get_distribution_details", distribution_id="E1A2B3C4D5E6F7"
    
    📋 List cache policies:
    operation="list_cache_policies"
    
    🔄 Get distribution invalidations:
    operation="get_distribution_invalidations", distribution_id="E1A2B3C4D5E6F7"
    
    🔍 Search by CloudFront domain:
    operation="search_distribution", identifier="d1234abcdef8ghi.cloudfront.net"
    
    📊 Get detailed distribution info by domain:
    operation="get_distribution_details", distribution_id="d1234abcdef8ghi.cloudfront.net"
    
    🌐 Cross-account operations:
    operation="list_distributions", session_context="123456789012_aws_dev"
    
    Args:
        operation: The CloudFront operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
        # Distribution parameters:
        distribution_id: ID of the CloudFront distribution (or domain name)
        identifier: Search term (domain name, distribution ID, or alias)
        
        # Pagination parameters:
        limit: Maximum number of items to return
        next_token: Pagination token for continued results
        
    Returns:
        JSON formatted response with operation results and CloudFront insights
        
    Examples:
        # Single account (default)
        cloudfront_operations(operation="list_distributions")
        
        # Cross-account access
        cloudfront_operations(operation="list_distributions", session_context="123456789012_aws_dev")
    """
    
    logger.info(f"CloudFront operation requested: {operation} (session_context={session_context})")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_distributions":
            limit = params.get("limit", 1000)
            next_token = params.get("next_token")
            
            return await _list_distributions(
                limit=limit,
                next_token=next_token,
                session_context=session_context
            )
            
        elif operation == "get_distribution_details":
            distribution_id = params.get("distribution_id")
            if not distribution_id:
                return json.dumps({
                    "error": "distribution_id parameter is required for get_distribution_details",
                    "usage": "operation='get_distribution_details', distribution_id='E1A2B3C4D5E6F7'"
                })
            
            return await _get_distribution_details(
                distribution_id=distribution_id,
                session_context=session_context
            )
            
        elif operation == "search_distribution":
            identifier = params.get("identifier")
            if not identifier:
                return json.dumps({
                    "error": "identifier parameter is required for search_distribution",
                    "usage": "operation='search_distribution', identifier='example.com'"
                })
            
            return await _search_distribution(
                identifier=identifier,
                session_context=session_context
            )
            
        elif operation == "list_cache_policies":
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            return await _list_cache_policies(
                limit=limit,
                next_token=next_token,
                session_context=session_context
            )
            
        elif operation == "list_origin_request_policies":
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            return await _list_origin_request_policies(
                limit=limit,
                next_token=next_token,
                session_context=session_context
            )
            
        elif operation == "list_response_headers_policies":
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            return await _list_response_headers_policies(
                limit=limit,
                next_token=next_token,
                session_context=session_context
            )
            
        elif operation == "get_distribution_invalidations":
            distribution_id = params.get("distribution_id")
            if not distribution_id:
                return json.dumps({
                    "error": "distribution_id parameter is required for get_distribution_invalidations",
                    "usage": "operation='get_distribution_invalidations', distribution_id='E1A2B3C4D5E6F7'"
                })
            
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            return await _get_distribution_invalidations(
                distribution_id=distribution_id,
                limit=limit,
                next_token=next_token,
                session_context=session_context
            )
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_distributions", "get_distribution_details", "search_distribution",
                "list_cache_policies", "list_origin_request_policies", 
                "list_response_headers_policies", "get_distribution_invalidations"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_distributions": "operation='list_distributions'",
                    "search_distribution": "operation='search_distribution', identifier='example.com'",
                    "get_distribution_details": "operation='get_distribution_details', distribution_id='E1A2B3C4D5E6F7'",
                    "cross_account": "operation='list_distributions', session_context='123456789012_aws_dev'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in CloudFront operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing CloudFront operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params,
                "session_context": session_context
            }
        })

@register_tool()
async def discover_cloudfront_operations(session_context: Optional[str] = None) -> str:
    """Discover all available CloudFront operations with detailed usage examples.
    
    This tool provides comprehensive documentation of CloudFront operations available
    through the cloudfront_operations tool, including parameter requirements
    and practical usage examples.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
    
    Returns:
        Detailed catalog of CloudFront operations with examples and parameter descriptions
        
    Examples:
        # Single account (default)
        discover_cloudfront_operations()
        
        # Cross-account access
        discover_cloudfront_operations(session_context="123456789012_aws_dev")
    """
    
    operations_catalog = {
        "service": "AWS CloudFront",
        "description": "Content Delivery Network (CDN) distribution management and monitoring",
        "wrapper_tool": "cloudfront_operations",
        "session_context_support": True,
        "cross_account_access": {
            "description": "All operations support cross-account access via session_context parameter",
            "usage": "session_context='123456789012_aws_dev'",
            "examples": [
                "cloudfront_operations(operation='list_distributions', session_context='123456789012_aws_dev')",
                "cloudfront_operations(operation='get_distribution_details', distribution_id='E1A2B3C4D5E6F7', session_context='123456789012_aws_dev')"
            ]
        },
        "supported_features": {
            "distributions": "Manage and monitor CloudFront distributions",
            "policies": "Cache, origin request, and response headers policies",
            "invalidations": "Content invalidation management",
            "origins": "Origin server configuration and monitoring",
            "behaviors": "Cache behavior and routing rules"
        },
        "operation_categories": {
            "distribution_discovery": {
                "list_distributions": {
                    "description": "List all CloudFront distributions with optional pagination",
                    "parameters": {
                        "limit": {"type": "int", "default": 1000, "description": "Maximum number of distributions to return"},
                        "next_token": {"type": "str", "description": "Pagination token for continued results"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "cloudfront_operations(operation='list_distributions')",
                        "cloudfront_operations(operation='list_distributions', limit=50)",
                        "cloudfront_operations(operation='list_distributions', session_context='123456789012_aws_dev')"
                    ]
                },
                "get_distribution_details": {
                    "description": "Get detailed information about a specific CloudFront distribution",
                    "parameters": {
                        "distribution_id": {"type": "str", "required": True, "description": "Distribution ID or CloudFront domain name"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "cloudfront_operations(operation='get_distribution_details', distribution_id='E1A2B3C4D5E6F7')",
                        "cloudfront_operations(operation='get_distribution_details', distribution_id='d1234abcdef8ghi.cloudfront.net')",
                        "cloudfront_operations(operation='get_distribution_details', distribution_id='E1A2B3C4D5E6F7', session_context='123456789012_aws_dev')"
                    ]
                },
                "search_distribution": {
                    "description": "Search for distributions by domain name, distribution ID, or alias",
                    "parameters": {
                        "identifier": {"type": "str", "required": True, "description": "Domain name, distribution ID, or alias to search for"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "cloudfront_operations(operation='search_distribution', identifier='example.com')",
                        "cloudfront_operations(operation='search_distribution', identifier='E1A2B3C4D5E6F7')",
                        "cloudfront_operations(operation='search_distribution', identifier='example.com', session_context='123456789012_aws_dev')"
                    ]
                }
            },
            "policy_management": {
                "list_cache_policies": {
                    "description": "List available CloudFront cache policies",
                    "parameters": {
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of policies to return"},
                        "next_token": {"type": "str", "description": "Pagination token for continued results"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "cloudfront_operations(operation='list_cache_policies')",
                        "cloudfront_operations(operation='list_cache_policies', limit=20)",
                        "cloudfront_operations(operation='list_cache_policies', session_context='123456789012_aws_dev')"
                    ]
                },
                "list_origin_request_policies": {
                    "description": "List CloudFront origin request policies",
                    "parameters": {
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of policies to return"},
                        "next_token": {"type": "str", "description": "Pagination token for continued results"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "cloudfront_operations(operation='list_origin_request_policies')",
                        "cloudfront_operations(operation='list_origin_request_policies', limit=20)",
                        "cloudfront_operations(operation='list_origin_request_policies', session_context='123456789012_aws_dev')"
                    ]
                },
                "list_response_headers_policies": {
                    "description": "List CloudFront response headers policies",
                    "parameters": {
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of policies to return"},
                        "next_token": {"type": "str", "description": "Pagination token for continued results"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "cloudfront_operations(operation='list_response_headers_policies')",
                        "cloudfront_operations(operation='list_response_headers_policies', limit=20)",
                        "cloudfront_operations(operation='list_response_headers_policies', session_context='123456789012_aws_dev')"
                    ]
                }
            },
            "invalidation_monitoring": {
                "get_distribution_invalidations": {
                    "description": "Get invalidation history for a specific CloudFront distribution",
                    "parameters": {
                        "distribution_id": {"type": "str", "required": True, "description": "Distribution ID"},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of invalidations to return"},
                        "next_token": {"type": "str", "description": "Pagination token for continued results"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "cloudfront_operations(operation='get_distribution_invalidations', distribution_id='E1A2B3C4D5E6F7')",
                        "cloudfront_operations(operation='get_distribution_invalidations', distribution_id='E1A2B3C4D5E6F7', limit=10)",
                        "cloudfront_operations(operation='get_distribution_invalidations', distribution_id='E1A2B3C4D5E6F7', session_context='123456789012_aws_dev')"
                    ]
                }
            }
        },
        "cloudfront_insights": {
            "common_operations": [
                "List all distributions: operation='list_distributions'",
                "Find distribution by domain: operation='search_distribution', identifier='example.com'",
                "Get distribution details: operation='get_distribution_details', distribution_id='E1A2B3C4D5E6F7'",
                "Check invalidations: operation='get_distribution_invalidations', distribution_id='E1A2B3C4D5E6F7'"
            ],
            "cross_account_examples": [
                "List distributions in dev account: operation='list_distributions', session_context='123456789012_aws_dev'",
                "Get distribution details in prod account: operation='get_distribution_details', distribution_id='E1A2B3C4D5E6F7', session_context='987654321098_aws_prod'",
                "Search distribution in staging account: operation='search_distribution', identifier='staging.example.com', session_context='456789012345_aws_staging'"
            ],
            "monitoring_best_practices": [
                "Regularly review distribution configurations for security compliance",
                "Monitor cache hit ratios and origin request patterns",
                "Check SSL/TLS certificate configurations and expiration dates",
                "Review origin access identity (OAI) configurations for S3 origins",
                "Monitor invalidation patterns for content freshness"
            ],
            "security_considerations": [
                "Ensure HTTPS-only viewer protocol policies for sensitive content",
                "Review and validate custom domain SSL certificates",
                "Monitor for distributions with public S3 origins without OAI",
                "Check WAF integration for application protection",
                "Audit geographic restrictions and access controls",
                "Review cache behaviors for sensitive data handling"
            ],
            "cost_optimization": [
                "Monitor price class settings for geographic distribution needs",
                "Review cache behaviors to optimize origin requests",
                "Analyze invalidation frequency to reduce costs",
                "Check compression settings for bandwidth optimization"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 