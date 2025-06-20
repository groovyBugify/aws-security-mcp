"""ECR Service Wrapper for AWS Security MCP.

This wrapper consolidates all ECR operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing ECR functions to reuse them
from aws_security_mcp.tools.ecr_tools import (
    list_ecr_repositories as _list_ecr_repositories,
    get_ecr_repository_policy as _get_ecr_repository_policy,
    get_ecr_image_scan_findings as _get_ecr_image_scan_findings,
    get_ecr_repository_images as _get_ecr_repository_images,
    search_ecr_repositories as _search_ecr_repositories
)

logger = logging.getLogger(__name__)

@register_tool()
async def ecr_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """ECR Security Operations Hub - Comprehensive container registry security analysis.
    
    🐳 REPOSITORY DISCOVERY:
    - list_repositories: List all ECR repositories in the account
    
    🔍 REPOSITORY SEARCH:
    - search_repositories: Search for specific repositories with detailed information
    
    🔐 POLICY ANALYSIS:
    - get_repository_policy: Get IAM policy for an ECR repository
    
    🖼️ IMAGE MANAGEMENT:
    - get_repository_images: Get information about all images in a repository
    
    🛡️ VULNERABILITY SCANNING:
    - get_image_scan_findings: Get vulnerability scan findings for container images
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🐳 List all repositories:
    operation="list_repositories"
    
    🔍 Search specific repository:
    operation="search_repositories", repository_name="my-app"
    
    🔍 Search multiple repositories:
    operation="search_repositories", repository_names=["app1", "app2"]
    
    🔍 Get all repository details:
    operation="search_repositories"
    
    🔐 Get repository policy:
    operation="get_repository_policy", repository_name="my-app"
    
    🖼️ Get repository images:
    operation="get_repository_images", repository_name="my-app"
    
    🛡️ Get vulnerability scan (latest):
    operation="get_image_scan_findings", repository_name="my-app"
    
    🛡️ Get vulnerability scan (specific tag):
    operation="get_image_scan_findings", repository_name="my-app", image_tag="v1.0.0"
    
    Args:
        operation: The ECR operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
        # Repository identification:
        repository_name: Name of the ECR repository (required for most operations)
        repository_names: List of repository names for bulk operations
        
        # Image identification:
        image_tag: Tag of the image to analyze (default: "latest")
        
    Returns:
        JSON formatted response with operation results and ECR security insights
    """
    
    logger.info(f"ECR operation requested: {operation} (session_context={session_context})")
    logger.info(f"Parameters received: {params}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_repositories":
            result = await _list_ecr_repositories(session_context=session_context)
            return json.dumps(result, default=str)
            
        elif operation == "search_repositories":
            repository_name = params.get("repository_name")
            repository_names = params.get("repository_names")
            
            result = await _search_ecr_repositories(
                repository_name=repository_name,
                repository_names=repository_names,
                session_context=session_context
            )
            return json.dumps(result, default=str)
            
        elif operation == "get_repository_policy":
            # Try multiple ways to get repository_name to handle different parameter formats
            repository_name = (
                params.get("repository_name") or
                params.get("repositoryName") or  
                params.get("repo_name") or
                params.get("name")
            )
            
            logger.info(f"Extracted repository_name: '{repository_name}' from params: {params}")
            
            if not repository_name:
                return json.dumps({
                    "error": "repository_name parameter is required for get_repository_policy",
                    "received_params": params,
                    "usage": "operation='get_repository_policy', repository_name='my-app'"
                })
            
            result = await _get_ecr_repository_policy(repository_name, session_context=session_context)
            return json.dumps(result, default=str)
            
        elif operation == "get_repository_images":
            # Try multiple ways to get repository_name to handle different parameter formats
            repository_name = (
                params.get("repository_name") or
                params.get("repositoryName") or  
                params.get("repo_name") or
                params.get("name")
            )
            
            logger.info(f"Extracted repository_name: '{repository_name}' from params: {params}")
            
            if not repository_name:
                return json.dumps({
                    "error": "repository_name parameter is required for get_repository_images",
                    "received_params": params,
                    "usage": "operation='get_repository_images', repository_name='my-app'"
                })
            
            result = await _get_ecr_repository_images(repository_name, session_context=session_context)
            return json.dumps(result, default=str)
            
        elif operation == "get_image_scan_findings":
            # Try multiple ways to get repository_name to handle different parameter formats
            repository_name = (
                params.get("repository_name") or
                params.get("repositoryName") or  
                params.get("repo_name") or
                params.get("name")
            )
            
            # Try multiple ways to get image_tag
            image_tag = (
                params.get("image_tag") or
                params.get("imageTag") or
                params.get("tag") or
                "latest"
            )
            
            logger.info(f"Extracted repository_name: '{repository_name}', image_tag: '{image_tag}' from params: {params}")
            
            if not repository_name:
                return json.dumps({
                    "error": "repository_name parameter is required for get_image_scan_findings",
                    "received_params": params,
                    "usage": "operation='get_image_scan_findings', repository_name='my-app', image_tag='latest'"
                })
            
            result = await _get_ecr_image_scan_findings(
                repository_name, 
                image_tag, 
                session_context=session_context
            )
            return json.dumps(result, default=str)
            
        else:
            return json.dumps({
                "error": f"Unknown ECR operation: {operation}",
                "available_operations": [
                    "list_repositories",
                    "search_repositories", 
                    "get_repository_policy",
                    "get_repository_images",
                    "get_image_scan_findings"
                ],
                "usage": "Use discover_ecr_operations() to see detailed usage examples"
            })
            
    except Exception as e:
        logger.error(f"Error in ECR operation '{operation}': {e}")
        return json.dumps({
            "error": str(e),
            "operation": operation,
            "parameters": params
        })

@register_tool()
async def discover_ecr_operations() -> str:
    """Discover all available ECR operations with detailed usage examples.
    
    This tool provides comprehensive documentation of ECR operations available
    through the ecr_security_operations tool, including parameter requirements
    and practical usage examples.
    
    Returns:
        Detailed catalog of ECR operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "Amazon ECR",
        "description": "Elastic Container Registry management and security analysis",
        "wrapper_tool": "ecr_security_operations",
        "operation_categories": {
            "repository_discovery": {
                "list_repositories": {
                    "description": "List all ECR repositories in the AWS account",
                    "parameters": {
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecr_security_operations(operation='list_repositories')",
                        "ecr_security_operations(operation='list_repositories', session_context='123456789012_aws_dev')"
                    ],
                    "returns": [
                        "List of repository names",
                        "Repository count", 
                        "Scan timestamp"
                    ]
                }
            },
            "repository_search": {
                "search_repositories": {
                    "description": "Search for ECR repositories with detailed information",
                    "parameters": {
                        "repository_name": {"type": "str", "description": "Single repository name to search"},
                        "repository_names": {"type": "list", "description": "List of repository names to search"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecr_security_operations(operation='search_repositories')",
                        "ecr_security_operations(operation='search_repositories', repository_name='my-app')",
                        "ecr_security_operations(operation='search_repositories', repository_names=['app1', 'app2'])",
                        "ecr_security_operations(operation='search_repositories', session_context='123456789012_aws_dev')"
                    ],
                    "returns": [
                        "Detailed repository information",
                        "Repository policies",
                        "Recent images and tags",
                        "Repository configuration"
                    ]
                }
            },
            "policy_analysis": {
                "get_repository_policy": {
                    "description": "Get IAM policy for an ECR repository",
                    "parameters": {
                        "repository_name": {"type": "str", "required": True, "description": "Name of the ECR repository"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecr_security_operations(operation='get_repository_policy', repository_name='my-app')",
                        "ecr_security_operations(operation='get_repository_policy', repository_name='my-app', session_context='123456789012_aws_dev')"
                    ],
                    "returns": [
                        "Repository IAM policy document",
                        "Policy statements and permissions",
                        "Access controls"
                    ]
                }
            },
            "image_management": {
                "get_repository_images": {
                    "description": "Get information about all images in an ECR repository",
                    "parameters": {
                        "repository_name": {"type": "str", "required": True, "description": "Name of the ECR repository"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecr_security_operations(operation='get_repository_images', repository_name='my-app')",
                        "ecr_security_operations(operation='get_repository_images', repository_name='my-app', session_context='123456789012_aws_dev')"
                    ],
                    "returns": [
                        "List of container images",
                        "Image tags and digests",
                        "Image metadata",
                        "Push timestamps"
                    ]
                }
            },
            "vulnerability_scanning": {
                "get_image_scan_findings": {
                    "description": "Get vulnerability scan findings for container images",
                    "parameters": {
                        "repository_name": {"type": "str", "required": True, "description": "Name of the ECR repository"},
                        "image_tag": {"type": "str", "default": "latest", "description": "Tag of the image to scan"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecr_security_operations(operation='get_image_scan_findings', repository_name='my-app')",
                        "ecr_security_operations(operation='get_image_scan_findings', repository_name='my-app', image_tag='v1.0.0')",
                        "ecr_security_operations(operation='get_image_scan_findings', repository_name='my-app', session_context='123456789012_aws_dev')"
                    ],
                    "returns": [
                        "Vulnerability findings",
                        "Severity levels",
                        "CVE details",
                        "Scan status and results"
                    ]
                }
            }
        },
        "security_insights": {
            "container_security": [
                "Identify repositories with vulnerable images",
                "Check for exposed registry permissions",
                "Monitor for unscanned or outdated images",
                "Validate repository access policies"
            ],
            "compliance_checks": [
                "Repository encryption status",
                "Image scanning compliance",
                "Access control validation",
                "Lifecycle policy configuration"
            ]
        },
        "best_practices": [
            "Enable automatic vulnerability scanning",
            "Use least-privilege repository policies", 
            "Implement image lifecycle policies",
            "Monitor for critical vulnerabilities",
            "Use immutable image tags in production"
        ]
    }
    
    return json.dumps(operations_catalog, indent=2) 