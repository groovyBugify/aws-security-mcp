"""AWS SecurityHub service client module.

This module provides functions for interacting with the AWS SecurityHub service.
"""

import logging
from typing import Any, Dict, List, Optional, Union

import boto3
from botocore.exceptions import ClientError

from aws_security_mcp.services.base import get_client, handle_aws_error

# Configure logging
logger = logging.getLogger(__name__)

def get_securityhub_client(**kwargs: Any) -> boto3.client:
    """Get AWS SecurityHub client.
    
    Args:
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized SecurityHub client
    """
    return get_client('securityhub', **kwargs)

def get_findings(
    filters: Optional[Dict[str, Any]] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Get findings from SecurityHub with specified filters.
    
    Args:
        filters: Dictionary of filters to apply to the findings
        max_results: Maximum number of findings to return (1-100)
        next_token: Token for pagination
        **kwargs: Additional arguments to pass to the get_findings API call
        
    Returns:
        Dict[str, Any]: Response from the get_findings API call
    """
    client = get_securityhub_client()
    
    # Build request parameters
    params = {
        'MaxResults': min(100, max(1, max_results)),  # API limits: 1-100
    }
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    # Add any additional parameters
    params.update(kwargs)
    
    try:
        return client.get_findings(**params)
    except ClientError as e:
        logger.error(f"Error getting SecurityHub findings: {e}")
        raise

def get_all_findings(
    filters: Optional[Dict[str, Any]] = None,
    max_items: int = 1000,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get all findings from SecurityHub with pagination handling.
    
    Args:
        filters: Dictionary of filters to apply to the findings
        max_items: Maximum number of findings to return
        **kwargs: Additional arguments to pass to the get_findings API call
        
    Returns:
        List[Dict[str, Any]]: List of findings
    """
    client = get_securityhub_client()
    findings = []
    next_token = None
    
    # Validate max_items
    max_items = max(1, min(max_items, 10000))  # Reasonable limits
    
    while len(findings) < max_items:
        # Prepare request parameters
        params = {
            'MaxResults': min(100, max_items - len(findings)),  # API max is 100
        }
        
        if filters:
            params['Filters'] = filters
        
        if next_token:
            params['NextToken'] = next_token
            
        # Add any additional parameters
        params.update(kwargs)
        
        try:
            response = client.get_findings(**params)
            batch_findings = response.get('Findings', [])
            
            if not batch_findings:
                logger.debug("No more findings returned from SecurityHub")
                break
                
            findings.extend(batch_findings)
            logger.debug(f"Retrieved {len(batch_findings)} findings, total: {len(findings)}")
            
            # Check if there are more findings
            next_token = response.get('NextToken')
            if not next_token:
                logger.debug("No more pages available")
                break
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"Error getting SecurityHub findings (code: {error_code}): {e}")
            
            # Handle specific error cases
            if error_code == 'InvalidAccessException':
                logger.error("SecurityHub is not enabled or insufficient permissions")
            elif error_code == 'InvalidInputException':
                logger.error("Invalid filter parameters provided")
            
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting SecurityHub findings: {e}")
            raise
    
    logger.info(f"Successfully retrieved {len(findings)} findings from SecurityHub")
    return findings

def filter_findings_by_severity(
    findings: List[Dict[str, Any]],
    severity: str = "ALL"
) -> List[Dict[str, Any]]:
    """Filter findings by severity level.
    
    Args:
        findings: List of findings to filter
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, or ALL)
        
    Returns:
        List[Dict[str, Any]]: Filtered list of findings
    """
    if severity == "ALL":
        return findings
    
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    if severity not in valid_severities:
        raise ValueError(f"Invalid severity level: {severity}")
    
    return [
        finding for finding in findings
        if finding.get('Severity', {}).get('Label') == severity
    ]

def filter_findings_by_text(
    findings: List[Dict[str, Any]],
    search_term: str = ""
) -> List[Dict[str, Any]]:
    """Filter findings by search term.
    
    Args:
        findings: List of findings to filter
        search_term: Term to search for in finding fields
        
    Returns:
        List[Dict[str, Any]]: Filtered list of findings
    """
    if not search_term:
        return findings
    
    search_term_lower = search_term.lower()
    filtered_findings = []
    
    for finding in findings:
        # Check if the search term matches any important fields
        if (search_term_lower in finding.get('ProductName', '').lower() or
            search_term_lower in finding.get('Title', '').lower() or
            search_term_lower in finding.get('Description', '').lower() or
            any(search_term_lower in str(resource).lower() for resource in finding.get('Resources', [])) or
            search_term_lower in finding.get('CompanyName', '').lower()):
            filtered_findings.append(finding)
    
    return filtered_findings

def create_severity_filter(severity: str) -> Dict[str, Any]:
    """Create a filter for findings based on severity.
    
    Args:
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, or ALL)
        
    Returns:
        Dict[str, Any]: Filter dictionary for the specified severity
    """
    if severity == "ALL":
        return {}
    
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    if severity not in valid_severities:
        raise ValueError(f"Invalid severity level: {severity}")
    
    return {
        "SeverityLabel": [{"Value": severity, "Comparison": "EQUALS"}]
    }

def create_search_term_filter(search_term: str) -> Dict[str, Any]:
    """Create a filter for findings based on search term.
    
    Args:
        search_term: Term to search for in finding fields
        
    Returns:
        Dict[str, Any]: Filter dictionary for the specified search term
    """
    if not search_term:
        return {}
    
    # Note: SecurityHub filters don't support OR operations natively
    # We'll filter by Title as the primary search field, then use post-processing
    # for additional fields in the calling code if needed
    return {
        "Title": [{"Value": search_term, "Comparison": "CONTAINS"}]
    } 