"""AWS ECR (Elastic Container Registry) service for container image security."""

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import boto3
from botocore.exceptions import ClientError

from aws_security_mcp.config import config
from aws_security_mcp.services.base import get_client

logger = logging.getLogger(__name__)

async def get_repositories(session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve all ECR repositories.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
    
    Returns:
        Dict containing ECR repositories or error information
    """
    try:
        client = get_client('ecr', session_context=session_context)
        
        # Use paginator to handle pagination
        paginator = client.get_paginator('describe_repositories')
        
        all_repositories = []
        
        # Iterate through pages
        for page in paginator.paginate():
            repositories = page.get('repositories', [])
            all_repositories.extend(repositories)
        
        return {
            "success": True,
            "repositories": all_repositories,
            "count": len(all_repositories)
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECR repositories: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "repositories": [],
            "count": 0
        }

async def get_repository_policy(repository_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve the policy for an ECR repository.
    
    Args:
        repository_name: Name of the ECR repository
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing repository policy or error information
    """
    try:
        client = get_client('ecr', session_context=session_context)
        
        response = client.get_repository_policy(
            repositoryName=repository_name
        )
        
        return {
            "success": True,
            "policy": response.get('policyText', '{}'),
            "registry_id": response.get('registryId'),
            "repository_name": repository_name
        }
    
    except ClientError as e:
        error_code = getattr(e, 'response', {}).get('Error', {}).get('Code')
        
        # Policy not found is not an error for our purposes
        if error_code == 'RepositoryPolicyNotFoundException':
            return {
                "success": True,
                "policy": None,
                "repository_name": repository_name,
                "message": "Repository does not have a policy attached"
            }
        
        logger.error(f"Error retrieving ECR repository policy: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "repository_name": repository_name,
            "policy": None
        }

async def get_repository_scan_findings(repository_name: str, image_tag: str = 'latest', session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve vulnerability scan findings for an ECR repository image.
    
    Args:
        repository_name: Name of the ECR repository
        image_tag: Tag of the image to check, defaults to 'latest'
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing scan findings or error information
    """
    try:
        client = get_client('ecr', session_context=session_context)
        
        # First, get the image digest for the specified tag
        response = client.describe_images(
            repositoryName=repository_name,
            imageIds=[{'imageTag': image_tag}]
        )
        
        if not response.get('imageDetails'):
            return {
                "success": False,
                "error": f"Image with tag '{image_tag}' not found in repository '{repository_name}'",
                "findings": [],
                "repository_name": repository_name,
                "image_tag": image_tag
            }
        
        image_digest = response['imageDetails'][0]['imageDigest']
        
        # Get scan findings using the image digest
        scan_findings = client.describe_image_scan_findings(
            repositoryName=repository_name,
            imageId={'imageDigest': image_digest}
        )
        
        # Check if scan is complete or in progress
        scan_status = scan_findings.get('imageScanStatus', {}).get('status')
        
        if scan_status != 'COMPLETE':
            return {
                "success": True,
                "scan_status": scan_status,
                "repository_name": repository_name,
                "image_tag": image_tag,
                "findings": [],
                "findings_count": 0,
                "message": f"Scan is in '{scan_status}' state. Try again later."
            }
        
        # Process paginated findings
        all_findings = []
        current_findings = scan_findings.get('imageScanFindings', {}).get('findings', [])
        all_findings.extend(current_findings)
        
        while 'nextToken' in scan_findings:
            next_token = scan_findings['nextToken']
            scan_findings = client.describe_image_scan_findings(
                repositoryName=repository_name,
                imageId={'imageDigest': image_digest},
                nextToken=next_token
            )
            current_findings = scan_findings.get('imageScanFindings', {}).get('findings', [])
            all_findings.extend(current_findings)
        
        # Get vulnerability counts by severity
        severity_counts = scan_findings.get('imageScanFindings', {}).get('findingSeverityCounts', {})
        
        return {
            "success": True,
            "scan_status": scan_status,
            "repository_name": repository_name,
            "image_tag": image_tag,
            "image_digest": image_digest,
            "findings": all_findings,
            "findings_count": len(all_findings),
            "severity_counts": severity_counts,
            "scan_completed_at": scan_findings.get('imageScanFindings', {}).get('imageScanCompletedAt')
        }
    
    except ClientError as e:
        error_code = getattr(e, 'response', {}).get('Error', {}).get('Code')
        
        # Handle case where scanning might not be enabled
        if error_code == 'ScanNotFoundException':
            return {
                "success": False,
                "error": "Image scanning is not enabled or no scan has been performed",
                "repository_name": repository_name,
                "image_tag": image_tag,
                "findings": [],
                "findings_count": 0,
            }
        
        logger.error(f"Error retrieving ECR image scan findings: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "repository_name": repository_name,
            "image_tag": image_tag,
            "findings": [],
            "findings_count": 0
        }

async def get_repository_images(repository_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve images from an ECR repository.
    
    Args:
        repository_name: Name of the ECR repository
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing repository images or error information
    """
    try:
        client = get_client('ecr', session_context=session_context)
        
        # Use paginator to handle pagination
        paginator = client.get_paginator('describe_images')
        
        all_images = []
        
        # Iterate through pages
        for page in paginator.paginate(repositoryName=repository_name):
            images = page.get('imageDetails', [])
            all_images.extend(images)
        
        return {
            "success": True,
            "images": all_images,
            "count": len(all_images),
            "repository_name": repository_name
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECR repository images: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "images": [],
            "count": 0,
            "repository_name": repository_name
        }

async def search_repositories(repository_name: Optional[str] = None, repository_names: Optional[List[str]] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Search for ECR repositories by exact name match using the AWS ECR describe_repositories API.
    
    Args:
        repository_name: Optional single repository name to search for
        repository_names: Optional list of repository names to search for
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing matching repositories or error information
    """
    try:
        client = get_client('ecr', session_context=session_context)
        
        # Prepare repository names list for API call
        repos_to_search = []
        if repository_name:
            repos_to_search = [repository_name]
        elif repository_names:
            repos_to_search = repository_names
            
        # If specific repositories are requested, use the repositoryNames parameter
        if repos_to_search:
            try:
                # Use describe_repositories with specific repository names
                response = client.describe_repositories(
                    repositoryNames=repos_to_search
                )
                matching_repositories = response.get('repositories', [])
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code')
                # Handle case where repository doesn't exist
                if error_code == 'RepositoryNotFoundException':
                    return {
                        "success": False,
                        "error": f"One or more repositories not found: {repos_to_search}",
                        "repositories": [],
                        "count": 0
                    }
                raise  # Re-raise other client errors
        else:
            # If no names provided, get all repositories
            all_repositories_result = await get_repositories(session_context=session_context)
            if not all_repositories_result.get("success", False):
                return all_repositories_result
            matching_repositories = all_repositories_result.get("repositories", [])
        
        # Get additional details for each repository
        detailed_repositories = []
        for repo in matching_repositories:
            repo_name = repo.get('repositoryName')
            
            # Get repository policy
            policy_result = await get_repository_policy(repo_name, session_context=session_context)
            repo_policy = policy_result.get("policy")
            
            # Get repository images
            images_result = await get_repository_images(repo_name, session_context=session_context)
            repo_images = images_result.get("images", [])
            
            # Create detailed repository info
            detailed_repo = {
                **repo,  # Include all original repository information
                "policy": repo_policy,
                "images_count": len(repo_images),
                "latest_images": repo_images[:5] if repo_images else []  # Include only the latest 5 images
            }
            
            detailed_repositories.append(detailed_repo)
        
        return {
            "success": True,
            "search_term": repository_name or (', '.join(repository_names) if repository_names else 'ALL'),
            "repositories": detailed_repositories,
            "count": len(detailed_repositories)
        }
    
    except ClientError as e:
        logger.error(f"Error searching ECR repositories: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "search_term": repository_name or (', '.join(repository_names) if repository_names else 'ALL'),
            "repositories": [],
            "count": 0
        } 