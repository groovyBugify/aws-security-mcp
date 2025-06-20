"""AWS Trusted Advisor service for security checks and recommendations.

NOTE: Trusted Advisor is a GLOBAL service that only operates in us-east-1 region.
All API calls are automatically routed to us-east-1 regardless of session context region.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import boto3
from botocore.exceptions import ClientError

from aws_security_mcp.config import config
from aws_security_mcp.services.base import get_client, get_aws_session

logger = logging.getLogger(__name__)

# Security check categories - we'll filter for these
SECURITY_CATEGORIES = ["security", "fault_tolerance"]

# Trusted Advisor is a global service - must use us-east-1
TRUSTED_ADVISOR_REGION = "us-east-1"

def _get_trusted_advisor_client(session_context: Optional[str] = None):
    """Get a Trusted Advisor client configured for us-east-1 region.
    
    Args:
        session_context: Optional session key for cross-account access
        
    Returns:
        Trusted Advisor client configured for us-east-1
    """
    # Get the session first (may have wrong region for cross-account)
    session = get_aws_session(session_context=session_context)
    
    # Force us-east-1 region for Trusted Advisor by creating client directly
    # This bypasses any region configuration in the session
    logger.debug(f"Creating Trusted Advisor client with forced region: {TRUSTED_ADVISOR_REGION}")
    return session.client('trustedadvisor', region_name=TRUSTED_ADVISOR_REGION)

async def get_security_checks(session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve all security-related checks from Trusted Advisor.
    
    Args:
        session_context: Optional session key for cross-account access
    
    Returns:
        Dict containing security checks or error information
    """
    try:
        client = _get_trusted_advisor_client(session_context=session_context)
        
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
            "count": len(all_checks),
            "region": TRUSTED_ADVISOR_REGION
        }
    
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'Unknown error')
        
        # Check for common Trusted Advisor access issues
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            logger.warning(f"Trusted Advisor access denied - may require Business/Enterprise support: {error_message}")
            return {
                "success": False,
                "error": f"Access denied - Trusted Advisor requires AWS Business or Enterprise support tier. Error: {error_message}",
                "error_code": error_code,
                "checks": [],
                "count": 0,
                "region": TRUSTED_ADVISOR_REGION,
                "support_tier_required": "Business or Enterprise"
            }
        else:
            logger.error(f"Error retrieving Trusted Advisor security checks: {error_code} - {error_message}")
            return {
                "success": False,
                "error": f"{error_code}: {error_message}",
                "error_code": error_code,
                "checks": [],
                "count": 0,
                "region": TRUSTED_ADVISOR_REGION
            }
    except Exception as e:
        logger.error(f"Unexpected error retrieving Trusted Advisor security checks: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "checks": [],
            "count": 0,
            "region": TRUSTED_ADVISOR_REGION
        }

async def get_recommendation_details(recommendation_id: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get details for a specific security recommendation.
    
    Args:
        recommendation_id: The ID of the recommendation
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict containing recommendation details or error information
    """
    try:
        client = _get_trusted_advisor_client(session_context=session_context)
        
        response = client.get_recommendation(
            recommendationId=recommendation_id
        )
        
        return {
            "success": True,
            "recommendation": response.get('recommendation', {}),
            "region": TRUSTED_ADVISOR_REGION
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving Trusted Advisor recommendation details: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "recommendation": {},
            "region": TRUSTED_ADVISOR_REGION
        }

async def list_security_recommendations(session_context: Optional[str] = None) -> Dict[str, Any]:
    """List all security recommendations from Trusted Advisor.
    
    Args:
        session_context: Optional session key for cross-account access
    
    Returns:
        Dict containing security recommendations or error information
    """
    try:
        client = _get_trusted_advisor_client(session_context=session_context)
        
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
            "count": len(all_recommendations),
            "region": TRUSTED_ADVISOR_REGION
        }
    
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'Unknown error')
        
        # Check for common Trusted Advisor access issues
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            logger.warning(f"Trusted Advisor access denied - may require Business/Enterprise support: {error_message}")
            return {
                "success": False,
                "error": f"Access denied - Trusted Advisor requires AWS Business or Enterprise support tier. Error: {error_message}",
                "error_code": error_code,
                "recommendations": [],
                "count": 0,
                "region": TRUSTED_ADVISOR_REGION,
                "support_tier_required": "Business or Enterprise"
            }
        elif error_code == 'SubscriptionRequiredException':
            logger.warning(f"Trusted Advisor subscription required: {error_message}")
            return {
                "success": False,
                "error": f"Trusted Advisor access requires AWS Business or Enterprise support subscription. Error: {error_message}",
                "error_code": error_code,
                "recommendations": [],
                "count": 0,
                "region": TRUSTED_ADVISOR_REGION,
                "support_tier_required": "Business or Enterprise"
            }
        else:
            logger.error(f"Error retrieving Trusted Advisor security recommendations: {error_code} - {error_message}")
            return {
                "success": False,
                "error": f"{error_code}: {error_message}",
                "error_code": error_code,
                "recommendations": [],
                "count": 0,
                "region": TRUSTED_ADVISOR_REGION
            }
    except Exception as e:
        # Check if this is an endpoint connection error (which we fixed)
        error_str = str(e)
        if "Could not connect to the endpoint URL" in error_str:
            logger.error(f"Endpoint connection error (region issue): {error_str}")
            return {
                "success": False,
                "error": f"Endpoint connection error - this should be fixed with us-east-1 routing. Error: {error_str}",
                "recommendations": [],
                "count": 0,
                "region": TRUSTED_ADVISOR_REGION,
                "troubleshooting": "If you still see this error, please report it as the us-east-1 fix may not be working correctly"
            }
        else:
            logger.error(f"Unexpected error retrieving Trusted Advisor security recommendations: {error_str}")
            return {
                "success": False,
                "error": error_str,
                "recommendations": [],
                "count": 0,
                "region": TRUSTED_ADVISOR_REGION
            }

async def list_recommendation_resources(recommendation_id: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List all resources affected by a specific security recommendation.
    
    Args:
        recommendation_id: The ID of the recommendation
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict containing affected resources or error information
    """
    try:
        client = _get_trusted_advisor_client(session_context=session_context)
        
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
            "count": len(all_resources),
            "region": TRUSTED_ADVISOR_REGION
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving resources for recommendation {recommendation_id}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "resources": [],
            "count": 0,
            "region": TRUSTED_ADVISOR_REGION
        } 