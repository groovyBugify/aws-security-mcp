"""ECR formatter module for AWS Security MCP.

This module provides functions to format ECR information
for better readability and security assessment.
"""

import logging
from typing import Any, Dict, List
import json
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

def format_repository_simple(repository: Dict[str, Any]) -> Dict[str, Any]:
    """Format a repository into a simplified representation.
    
    Args:
        repository: Raw repository data from AWS
    
    Returns:
        Dict containing simplified repository representation
    """
    try:
        return {
            'name': repository.get('repositoryName'),
            'uri': repository.get('repositoryUri'),
            'arn': repository.get('repositoryArn'),
            'created_at': repository.get('createdAt').isoformat() if repository.get('createdAt') else None
        }
    except Exception as e:
        logger.error(f"Error formatting repository info: {str(e)}")
        return repository  # Return original data if formatting fails

def extract_repository_uris(repositories: List[Dict[str, Any]]) -> List[str]:
    """Extract only repository URIs from repository data.
    
    Args:
        repositories: List of repository data from AWS
    
    Returns:
        List containing only repository URIs
    """
    try:
        return [repo.get('repositoryUri', '') for repo in repositories if repo.get('repositoryUri')]
    except Exception as e:
        logger.error(f"Error extracting repository URIs: {str(e)}")
        return []  # Return empty list if extraction fails

def extract_repository_names(repositories: List[Dict[str, Any]]) -> List[str]:
    """Extract only repository names from repository data.
    
    Args:
        repositories: List of repository data from AWS
    
    Returns:
        List containing only repository names
    """
    try:
        return [repo.get('repositoryName', '') for repo in repositories if repo.get('repositoryName')]
    except Exception as e:
        logger.error(f"Error extracting repository names: {str(e)}")
        return []  # Return empty list if extraction fails

def format_repository_detail(repository: Dict[str, Any]) -> Dict[str, Any]:
    """Format a repository with detailed information.
    
    Args:
        repository: Raw repository data with extended details
    
    Returns:
        Dict containing formatted repository details
    """
    try:
        # Format basic repository information
        formatted = {
            'name': repository.get('repositoryName'),
            'uri': repository.get('repositoryUri'),
            'arn': repository.get('repositoryArn'),
            'created_at': repository.get('createdAt').isoformat() if repository.get('createdAt') else None,
            'images_count': repository.get('images_count', 0)
        }
        
        # Format policy information
        policy = repository.get('policy')
        if policy:
            try:
                # Policy might be a string or already parsed
                if isinstance(policy, str):
                    policy_json = json.loads(policy)
                else:
                    policy_json = policy
                    
                formatted['policy'] = {
                    'version': policy_json.get('Version'),
                    'statements': policy_json.get('Statement', [])
                }
            except Exception as e:
                logger.warning(f"Error parsing repository policy: {str(e)}")
                formatted['policy'] = {'raw': policy}
        else:
            formatted['policy'] = None
        
        # Format image information
        latest_images = repository.get('latest_images', [])
        formatted_images = []
        
        for image in latest_images:
            try:
                image_tags = image.get('imageTags', [])
                formatted_image = {
                    'digest': image.get('imageDigest'),
                    'tags': image_tags,
                    'pushed_at': image.get('imagePushedAt').isoformat() if image.get('imagePushedAt') else None,
                    'size_in_mb': round(image.get('imageSizeInBytes', 0) / (1024 * 1024), 2) if image.get('imageSizeInBytes') else 0,
                    'scan_status': image.get('imageScanStatus', {}).get('status', 'UNKNOWN'),
                    'scan_findings': image.get('imageScanFindingsSummary', {}).get('findingSeverityCounts', {})
                }
                formatted_images.append(formatted_image)
            except Exception as e:
                logger.error(f"Error formatting image: {str(e)}")
        
        formatted['latest_images'] = formatted_images
        
        return formatted
    except Exception as e:
        logger.error(f"Error formatting repository details: {str(e)}")
        return repository  # Return original data if formatting fails

def format_repository_search_results(search_results: Dict[str, Any]) -> Dict[str, Any]:
    """Format repository search results.
    
    Args:
        search_results: Raw search results from ECR service
    
    Returns:
        Dict containing formatted search results
    """
    try:
        repositories = search_results.get('repositories', [])
        formatted_repositories = [format_repository_detail(repo) for repo in repositories]
        
        return {
            'search_term': search_results.get('search_term'),
            'repositories': formatted_repositories,
            'count': len(formatted_repositories),
            'scan_timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error formatting repository search results: {str(e)}")
        return search_results  # Return original data if formatting fails 