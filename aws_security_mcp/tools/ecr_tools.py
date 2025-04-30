"""ECR tools module for AWS Security MCP.

This module provides tools for retrieving and analyzing ECR information
for security assessment purposes.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from aws_security_mcp.services import ecr
from aws_security_mcp.formatters.ecr import extract_repository_uris, extract_repository_names, format_repository_search_results
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)

@register_tool()
async def list_ecr_repositories() -> Dict[str, Any]:
    """List all ECR repositories in the AWS account.

    Returns:
        Dict containing list of ECR repository names
    """
    try:
        logger.info("Listing ECR repositories")
        
        # Get repositories from the service
        result = await ecr.get_repositories()
        
        if not result.get("success", False):
            return {
                "error": result.get("error", "Unknown error"),
                "repository_names": [],
                "count": 0,
                "scan_timestamp": datetime.utcnow().isoformat()
            }
        
        # Extract only the repository names as requested
        repository_names = extract_repository_names(result.get("repositories", []))
        
        return {
            "repository_names": repository_names,
            "count": len(repository_names),
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error listing ECR repositories: {str(e)}")
        return {
            "repository_names": [],
            "count": 0,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool()
async def get_ecr_repository_policy(repository_name: str) -> Dict[str, Any]:
    """Get the IAM policy for an ECR repository.
    
    This tool retrieves the repository policy for the specified ECR repository.
    
    Args:
        repository_name: Name of the ECR repository
        
    Returns:
        Dict containing repository policy information
    """
    logger.info(f"Getting policy for ECR repository: {repository_name}")
    result = await ecr.get_repository_policy(repository_name)
    return result

@register_tool()
async def get_ecr_image_scan_findings(repository_name: str, image_tag: str = 'latest') -> Dict[str, Any]:
    """Get vulnerability scan findings for a container image.
    
    This tool retrieves scan findings for the specified container image.
    
    Args:
        repository_name: Name of the ECR repository
        image_tag: Tag of the image to check, defaults to 'latest'
        
    Returns:
        Dict containing vulnerability scan findings information
    """
    logger.info(f"Getting scan findings for ECR image: {repository_name}:{image_tag}")
    result = await ecr.get_repository_scan_findings(repository_name, image_tag)
    return result

@register_tool()
async def get_ecr_repository_images(repository_name: str) -> Dict[str, Any]:
    """Get information about all images in an ECR repository.
    
    This tool retrieves details about all container images in the specified repository.
    
    Args:
        repository_name: Name of the ECR repository
        
    Returns:
        Dict containing repository images information
    """
    logger.info(f"Getting images for ECR repository: {repository_name}")
    result = await ecr.get_repository_images(repository_name)
    return result

@register_tool()
async def search_ecr_repositories(repository_name: Optional[str] = None, repository_names: Optional[List[str]] = None) -> Dict[str, Any]:
    """Search for ECR repositories and get detailed information.
    
    This tool allows searching for repositories by exact name match and 
    returns detailed information about the matched repositories, including
    policy information and recent images.
    
    Args:
        repository_name: Optional single repository name to search for exactly
        repository_names: Optional list of repository names to search for exactly
                         If neither parameter is provided, details for all repositories will be returned.
        
    Returns:
        Dict containing detailed information about matching repositories
    """
    try:
        if repository_name:
            logger.info(f"Searching ECR repository with exact name: {repository_name}")
        elif repository_names:
            logger.info(f"Searching ECR repositories with exact names: {', '.join(repository_names)}")
        else:
            logger.info("Fetching details for all ECR repositories")
        
        # Get repository search results from the service using exact name matching
        search_results = await ecr.search_repositories(
            repository_name=repository_name, 
            repository_names=repository_names
        )
        
        if not search_results.get("success", False):
            return {
                "error": search_results.get("error", "Unknown error"),
                "repositories": [],
                "count": 0,
                "search_term": repository_name or (', '.join(repository_names) if repository_names else 'ALL'),
                "scan_timestamp": datetime.utcnow().isoformat()
            }
        
        # Format the search results
        formatted_results = format_repository_search_results(search_results)
        
        return formatted_results
    
    except Exception as e:
        logger.error(f"Error searching ECR repositories: {str(e)}")
        return {
            "repositories": [],
            "count": 0,
            "search_term": repository_name or (', '.join(repository_names) if repository_names else 'ALL'),
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        } 