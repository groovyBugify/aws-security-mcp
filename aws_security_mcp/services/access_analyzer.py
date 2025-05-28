"""AWS IAM Access Analyzer service client module.

This module provides functions for interacting with AWS IAM Access Analyzer.
"""

import logging
from typing import Any, Dict, List, Optional, Union, Tuple

import boto3
from botocore.exceptions import ClientError

from aws_security_mcp.services.base import get_client, handle_aws_error

# Configure logging
logger = logging.getLogger(__name__)

def get_access_analyzer_client(session_context: Optional[str] = None, **kwargs: Any) -> boto3.client:
    """Get AWS IAM Access Analyzer client.
    
    Args:
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized IAM Access Analyzer client
    """
    return get_client("accessanalyzer", session_context=session_context, **kwargs)

def list_analyzers(
    max_results: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """List IAM Access Analyzers.
    
    Args:
        max_results: Maximum number of analyzers to return (1-1000)
        next_token: Token for pagination
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the list_analyzers API call
        
    Returns:
        List[Dict[str, Any]]: List of analyzers
    """
    client = get_access_analyzer_client(session_context)
    
    params = {
        **kwargs
    }
    
    if max_results:
        params['maxResults'] = min(1000, max(1, max_results))
    
    if next_token:
        params['nextToken'] = next_token
    
    try:
        response = client.list_analyzers(**params)
        return response.get('analyzers', [])
    except ClientError as e:
        logger.error(f"Error listing IAM Access Analyzers: {e}")
        raise

def get_analyzer(analyzer_name: str, session_context: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
    """Get details of a specific IAM Access Analyzer.
    
    Args:
        analyzer_name: The name of the analyzer to retrieve
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the get_analyzer API call
        
    Returns:
        Dict[str, Any]: Analyzer details
    """
    client = get_access_analyzer_client(session_context)
    
    try:
        response = client.get_analyzer(
            analyzerName=analyzer_name,
            **kwargs
        )
        return response.get('analyzer', {})
    except ClientError as e:
        logger.error(f"Error getting IAM Access Analyzer details: {e}")
        raise

def list_findings(
    analyzer_arn: str,
    status: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List IAM Access Analyzer findings.
    
    Args:
        analyzer_arn: ARN of the analyzer
        status: Filter findings by status (ACTIVE, ARCHIVED, RESOLVED)
        max_results: Maximum number of findings to return (1-100)
        next_token: Token for pagination
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the list_findings API call
        
    Returns:
        Tuple[List[Dict[str, Any]], Optional[str]]: Tuple containing list of findings and next token for pagination
    """
    client = get_access_analyzer_client(session_context)
    
    params = {
        'analyzerArn': analyzer_arn,
        **kwargs
    }
    
    if max_results:
        params['maxResults'] = min(100, max(1, max_results))
    
    if next_token:
        params['nextToken'] = next_token
    
    if status:
        params['filter'] = create_status_filter(status)
    
    try:
        response = client.list_findings(**params)
        return response.get('findings', []), response.get('nextToken')
    except ClientError as e:
        logger.error(f"Error listing IAM Access Analyzer findings: {e}")
        raise

def get_finding(
    analyzer_arn: str,
    finding_id: str,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Get details of a specific finding.
    
    Args:
        analyzer_arn: ARN of the analyzer
        finding_id: ID of the finding
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the get_finding API call
        
    Returns:
        Dict[str, Any]: Finding details
    """
    client = get_access_analyzer_client(session_context)
    
    try:
        response = client.get_finding(
            analyzerArn=analyzer_arn,
            id=finding_id,
            **kwargs
        )
        return response
    except ClientError as e:
        logger.error(f"Error getting IAM Access Analyzer finding: {e}")
        raise

def list_findings_by_category(
    analyzer_arn: str,
    resource_type: str,
    status: str = "ACTIVE",
    max_results: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List findings filtered by resource type category.
    
    Args:
        analyzer_arn: ARN of the analyzer
        resource_type: Resource type to filter by (e.g., AWS::S3::Bucket, AWS::SQS::Queue)
        status: Filter findings by status (ACTIVE, ARCHIVED, RESOLVED)
        max_results: Maximum number of findings to return (1-100)
        next_token: Token for pagination
        session_context: Optional session key for cross-account access
        **kwargs: Additional arguments to pass to the list_findings API call
        
    Returns:
        Tuple[List[Dict[str, Any]], Optional[str]]: Tuple containing list of findings matching the category and next token for pagination
    """
    client = get_access_analyzer_client(session_context)
    
    # Create combined filter for status and resource type
    filter_criteria = {
        'resourceType': {
            'eq': [resource_type]
        }
    }
    
    if status:
        filter_criteria['status'] = {
            'eq': [status]
        }
    
    params = {
        'analyzerArn': analyzer_arn,
        'filter': filter_criteria,
        **kwargs
    }
    
    if max_results:
        params['maxResults'] = min(100, max(1, max_results))
    
    if next_token:
        params['nextToken'] = next_token
    
    try:
        response = client.list_findings(**params)
        return response.get('findings', []), response.get('nextToken')
    except ClientError as e:
        logger.error(f"Error listing IAM Access Analyzer findings by category: {e}")
        raise

def create_status_filter(status: str) -> Dict[str, Any]:
    """Create a filter for findings based on status.
    
    Args:
        status: Status to filter by (ACTIVE, ARCHIVED, RESOLVED)
        
    Returns:
        Dict[str, Any]: Filter for the specified status
    """
    valid_statuses = ["ACTIVE", "ARCHIVED", "RESOLVED"]
    
    if status not in valid_statuses:
        logger.warning(f"Invalid status: {status}. Using ACTIVE.")
        status = "ACTIVE"
    
    return {
        'status': {
            'eq': [status]
        }
    }

def create_resource_type_filter(resource_type: str) -> Dict[str, Any]:
    """Create a filter for findings based on resource type.
    
    Args:
        resource_type: Resource type to filter by
        
    Returns:
        Dict[str, Any]: Filter for the specified resource type
    """
    return {
        'resourceType': {
            'eq': [resource_type]
        }
    } 