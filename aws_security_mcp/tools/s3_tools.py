"""S3 tools module for AWS Security MCP.

This module provides tools for retrieving and analyzing S3 bucket information
for security assessment purposes.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from aws_security_mcp.services import s3
from aws_security_mcp.formatters import s3_formatter
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)

@register_tool("list_s3_buckets")
async def list_s3_buckets(session_context: Optional[str] = None) -> Dict[str, Any]:
    """List all S3 buckets in the AWS account with basic information.

    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

    Returns:
        Dict containing list of buckets with basic information
    """
    try:
        logger.info("Listing S3 buckets")
        
        # Get buckets from the service
        buckets = s3.list_buckets(session_context=session_context)
        
        # Format bucket information
        formatted_buckets = [
            s3_formatter.format_bucket_simple(bucket) for bucket in buckets
        ]
        
        return {
            "buckets": formatted_buckets,
            "count": len(formatted_buckets),
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error listing S3 buckets: {str(e)}")
        return {
            "buckets": [],
            "count": 0,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool("get_s3_bucket_details")
async def get_s3_bucket_details(
    bucket_name: str,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get detailed information about a specific S3 bucket.

    Args:
        bucket_name: Name of the S3 bucket to get details for
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

    Returns:
        Dict containing detailed bucket information
    """
    try:
        logger.info(f"Getting details for S3 bucket: {bucket_name}")
        
        # Get bucket details from the service
        bucket_details = await get_bucket_details_async(bucket_name, session_context)
        
        # Format bucket details
        formatted_details = s3_formatter.format_bucket_details(bucket_details)
        
        return {
            "bucket_details": formatted_details,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting S3 bucket details: {str(e)}")
        return {
            "bucket_details": {
                "name": bucket_name,
                "error": str(e)
            },
            "scan_timestamp": datetime.utcnow().isoformat()
        }

async def get_bucket_details_async(bucket_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Async wrapper for get_bucket_details.
    
    Args:
        bucket_name: Name of the S3 bucket
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with comprehensive bucket details
    """
    # Get the basic details synchronously
    bucket_details = s3.get_bucket_details(bucket_name, session_context=session_context)
    
    # If public_access_block requires async, add it separately
    try:
        # Make sure to await the coroutine here
        public_access_block = await s3.get_bucket_public_access_block(bucket_name, session_context=session_context)
        
        # The public_access_block is now directly the configuration dict, not a coroutine
        bucket_details['PublicAccessBlock'] = {
            'PublicAccessBlockConfiguration': public_access_block
        }
    except Exception as e:
        logger.warning(f"Error getting public access block asynchronously: {str(e)}")
    
    return bucket_details

@register_tool("analyze_s3_bucket_security")
async def analyze_s3_bucket_security(
    bucket_name: str,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Analyze the security configuration of an S3 bucket.

    Args:
        bucket_name: Name of the S3 bucket to analyze
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

    Returns:
        Dict containing security analysis for the bucket
    """
    try:
        logger.info(f"Analyzing security for S3 bucket: {bucket_name}")
        
        # Get bucket details from the service with async handling
        bucket_details = await get_bucket_details_async(bucket_name, session_context)
        
        # Check if bucket is public
        is_public, assessment = s3.is_bucket_public(bucket_name, session_context=session_context)
        
        # Format bucket details for security analysis
        formatted_details = s3_formatter.format_bucket_details(bucket_details)
        security_rating = formatted_details.get('security_rating', {})
        
        # Extract public access block settings - safely handle nested dictionaries
        public_access_block = bucket_details.get('PublicAccessBlock', {})
        
        # Extract the configuration directly instead of trying to access it as a coroutine
        public_access_config = {}
        if public_access_block and isinstance(public_access_block, dict):
            public_access_config = public_access_block.get('PublicAccessBlockConfiguration', {})
        
        # Get account-level public access block
        account_block = bucket_details.get('account_public_access_block')
        account_block_config = None
        if account_block and isinstance(account_block, dict):
            account_block_config = account_block.get('PublicAccessBlockConfiguration')
        
        # Create the security analysis response
        security_analysis = {
            "bucket_name": bucket_name,
            "is_public": is_public,
            "public_access_reasons": {
                "acl_public": assessment.get('acl_public', False),
                "policy_public": assessment.get('policy_public', False),
                "errors": assessment.get('errors', [])
            },
            "security_rating": security_rating,
            "public_access_block": formatted_details.get('public_access_block'),
            "account_public_access_block": account_block_config
        }
        
        return {
            "security_analysis": security_analysis,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error analyzing S3 bucket security: {str(e)}")
        return {
            "security_analysis": {
                "bucket_name": bucket_name,
                "error": str(e)
            },
            "scan_timestamp": datetime.utcnow().isoformat()
        }

@register_tool("find_public_buckets")
async def find_public_buckets(session_context: Optional[str] = None) -> Dict[str, Any]:
    """Find all public S3 buckets in the AWS account.

    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

    Returns:
        Dict containing assessment of public buckets
    """
    try:
        logger.info("Finding public S3 buckets")
        
        # First list all buckets to ensure we get the full list
        all_buckets = s3.list_buckets(session_context=session_context)
        if not all_buckets:
            logger.warning("No S3 buckets found in the account or unable to list buckets")
            return {
                "assessment": {
                    "summary": {
                        "total_buckets": 0,
                        "public_buckets": 0,
                        "percentage_public": 0,
                        "account_protected": False,
                        "scan_timestamp": datetime.utcnow().isoformat()
                    },
                    "public_buckets": [],
                    "all_buckets": []
                }
            }
        
        # Get public buckets from the service
        public_buckets_data = s3.find_public_buckets(session_context=session_context)
        
        # Format the public buckets assessment
        formatted_assessment = s3_formatter.format_public_buckets_assessment(public_buckets_data)
        
        # Ensure the result includes the raw bucket data for MCP client
        if "all_buckets" not in formatted_assessment:
            formatted_assessment["all_buckets"] = [
                s3_formatter.format_bucket_simple(bucket) for bucket in all_buckets
            ]
        
        return {
            "assessment": formatted_assessment
        }
    
    except Exception as e:
        logger.error(f"Error finding public S3 buckets: {str(e)}")
        return {
            "assessment": {
                "error": str(e),
                "summary": {
                    "total_buckets": 0,
                    "public_buckets": 0,
                    "percentage_public": 0,
                    "account_protected": False,
                    "scan_timestamp": datetime.utcnow().isoformat()
                },
                "public_buckets": [],
                "all_buckets": []
            }
        } 