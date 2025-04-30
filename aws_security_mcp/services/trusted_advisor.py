"""AWS Trusted Advisor service for security checks and recommendations."""

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import boto3
from botocore.exceptions import ClientError

from aws_security_mcp.config import config
from aws_security_mcp.services.base import get_client

logger = logging.getLogger(__name__)

# Security check categories - we'll filter for these
SECURITY_CATEGORIES = ["security", "fault_tolerance"]

async def get_security_checks() -> Dict[str, Any]:
    """Retrieve all security-related checks from Trusted Advisor.
    
    Returns:
        Dict containing security checks or error information
    """
    try:
        client = get_client('trustedadvisor')
        
        # Get all checks and filter for security categories
        paginator = client.get_paginator('list_checks')
        
        all_checks = []
        
        # Handle pagination
        for page in paginator.paginate():
            checks = page.get('checks', [])
            # Filter for security-related checks only
            security_checks = [
                check for check in checks 
                if check.get('category', '').lower() in SECURITY_CATEGORIES
            ]
            all_checks.extend(security_checks)
        
        return {
            "success": True,
            "checks": all_checks,
            "count": len(all_checks)
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving Trusted Advisor security checks: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "checks": [],
            "count": 0
        }

async def get_recommendation_details(recommendation_id: str) -> Dict[str, Any]:
    """Get details for a specific security recommendation.
    
    Args:
        recommendation_id: The ID of the recommendation
        
    Returns:
        Dict containing recommendation details or error information
    """
    try:
        client = get_client('trustedadvisor')
        
        response = client.get_recommendation(
            recommendationId=recommendation_id
        )
        
        return {
            "success": True,
            "recommendation": response.get('recommendation', {})
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving Trusted Advisor recommendation details: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "recommendation": {}
        }

async def list_security_recommendations() -> Dict[str, Any]:
    """List all security recommendations from Trusted Advisor.
    
    Returns:
        Dict containing security recommendations or error information
    """
    try:
        client = get_client('trustedadvisor')
        
        # Use the paginator to handle large result sets
        paginator = client.get_paginator('list_recommendations')
        
        all_recommendations = []
        
        # Handle pagination
        for page in paginator.paginate():
            recommendations = page.get('recommendations', [])
            # Filter for security-related recommendations
            security_recommendations = [
                rec for rec in recommendations 
                if any(cat.lower() in SECURITY_CATEGORIES for cat in rec.get('categories', []))
            ]
            all_recommendations.extend(security_recommendations)
        
        return {
            "success": True,
            "recommendations": all_recommendations,
            "count": len(all_recommendations)
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving Trusted Advisor security recommendations: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "recommendations": [],
            "count": 0
        }

async def list_recommendation_resources(recommendation_id: str) -> Dict[str, Any]:
    """List all resources affected by a specific security recommendation.
    
    Args:
        recommendation_id: The ID of the recommendation
        
    Returns:
        Dict containing affected resources or error information
    """
    try:
        client = get_client('trustedadvisor')
        
        # Use the paginator to handle large result sets
        paginator = client.get_paginator('list_recommendation_resources')
        
        all_resources = []
        
        # Handle pagination
        for page in paginator.paginate(recommendationId=recommendation_id):
            resources = page.get('resources', [])
            all_resources.extend(resources)
        
        return {
            "success": True,
            "resources": all_resources,
            "count": len(all_resources)
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving resources for recommendation {recommendation_id}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "resources": [],
            "count": 0
        } 