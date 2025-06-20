"""AWS GuardDuty service client module.

This module provides functions for interacting with the AWS GuardDuty service.
"""

from typing import Dict, List, Optional, Any
import logging
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from aws_security_mcp.services.base import get_aws_session, get_client, handle_pagination

logger = logging.getLogger(__name__)


def get_guardduty_client(session_context: Optional[str] = None, **kwargs: Any) -> boto3.client:
    """Get AWS GuardDuty client.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized GuardDuty client
    """
    return get_client('guardduty', session_context=session_context, **kwargs)


def list_detectors(max_results: int = 100, session_context: Optional[str] = None, **kwargs: Any) -> List[Dict[str, Any]]:
    """List all GuardDuty detectors in the current region.
    
    Args:
        max_results: Maximum number of detectors to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the list_detectors API call
        
    Returns:
        List[Dict[str, Any]]: List of detector details including DetectorId
    """
    client = get_guardduty_client(session_context=session_context)
    
    # Set up parameters
    params = {
        'MaxResults': min(50, max_results),  # API max is 50
        **kwargs
    }
    
    try:
        # Call the API directly and handle pagination manually
        response = client.list_detectors(**params)
        detector_ids = response.get('DetectorIds', [])
        
        # Handle pagination if there's a next token
        next_token = response.get('NextToken')
        while next_token and len(detector_ids) < max_results:
            params['NextToken'] = next_token
            # Adjust max_results for the next request
            params['MaxResults'] = min(50, max_results - len(detector_ids))
            
            response = client.list_detectors(**params)
            detector_ids.extend(response.get('DetectorIds', []))
            next_token = response.get('NextToken')
            
            # Break if we have enough detectors
            if len(detector_ids) >= max_results:
                break
        
        # Limit the results if we got more than requested
        if len(detector_ids) > max_results:
            detector_ids = detector_ids[:max_results]
        
        # Return list of dictionaries with DetectorId for consistency
        return [{"DetectorId": detector_id} for detector_id in detector_ids]
    
    except NoCredentialsError:
        logger.error("AWS credentials not found for listing GuardDuty detectors")
        return []
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(f"AWS API error listing GuardDuty detectors: {error_code} - {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error listing GuardDuty detectors: {e}")
        return []


def get_detector(detector_id: str, session_context: Optional[str] = None, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Get detailed information about a GuardDuty detector.
    
    Args:
        detector_id: GuardDuty detector ID
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the get_detector API call
        
    Returns:
        Optional[Dict[str, Any]]: Detector details or None if not found
    """
    client = get_guardduty_client(session_context=session_context)
    
    try:
        response = client.get_detector(
            DetectorId=detector_id,
            **kwargs
        )
        
        # Add the DetectorId to the response for consistency
        detector_details = response.copy()
        detector_details['DetectorId'] = detector_id
        
        return detector_details
    
    except NoCredentialsError:
        logger.error(f"AWS credentials not found for getting GuardDuty detector {detector_id}")
        return None
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'BadRequestException':
            logger.warning(f"GuardDuty detector {detector_id} not found")
        else:
            logger.error(f"AWS API error getting GuardDuty detector {detector_id}: {error_code} - {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting GuardDuty detector {detector_id}: {e}")
        return None


def get_detector_id(session_context: Optional[str] = None) -> Optional[str]:
    """Get the first GuardDuty detector ID in the current region.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
    
    Returns:
        Optional[str]: The first detector ID or None if no detectors exist
    """
    detectors = list_detectors(session_context=session_context)
    if detectors:
        return detectors[0].get('DetectorId')
    return None


def list_findings(
    detector_id: Optional[str] = None,
    finding_criteria: Optional[Dict[str, Any]] = None,
    max_results: int = 50,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[str]:
    """List GuardDuty findings based on criteria.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        finding_criteria: Criteria to filter findings
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the list_findings API call
        
    Returns:
        List[str]: List of finding IDs
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id(session_context=session_context)
        if detector_id is None:
            return []
    
    client = get_guardduty_client(session_context=session_context)
    
    # Set up parameters
    params = {
        'DetectorId': detector_id,
        'MaxResults': min(50, max_results),  # API max is 50
        **kwargs
    }
    
    if finding_criteria:
        params['FindingCriteria'] = finding_criteria
    
    try:
        # Call the API directly and handle pagination manually
        response = client.list_findings(**params)
        finding_ids = response.get('FindingIds', [])
        
        # Handle pagination if there's a next token
        next_token = response.get('NextToken')
        while next_token and len(finding_ids) < max_results:
            params['NextToken'] = next_token
            # Adjust max_results for the next request
            params['MaxResults'] = min(50, max_results - len(finding_ids))
            
            response = client.list_findings(**params)
            finding_ids.extend(response.get('FindingIds', []))
            next_token = response.get('NextToken')
            
            # Break if we have enough findings
            if len(finding_ids) >= max_results:
                break
        
        # Limit the results if we got more than requested
        if len(finding_ids) > max_results:
            finding_ids = finding_ids[:max_results]
        
        return finding_ids
    
    except NoCredentialsError:
        logger.error(f"AWS credentials not found for listing GuardDuty findings for detector {detector_id}")
        return []
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(f"AWS API error listing GuardDuty findings for detector {detector_id}: {error_code} - {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error listing GuardDuty findings for detector {detector_id}: {e}")
        return []


def get_findings(
    detector_id: Optional[str] = None,
    finding_ids: Optional[List[str]] = None,
    max_results: int = 50,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get detailed information about GuardDuty findings.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        finding_ids: List of finding IDs to get details for
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the get_findings API call
        
    Returns:
        List[Dict[str, Any]]: List of finding details
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id(session_context=session_context)
        if detector_id is None:
            return []
    
    # If no finding IDs provided, list findings
    if not finding_ids:
        finding_ids = list_findings(detector_id=detector_id, max_results=max_results, session_context=session_context)
    
    if not finding_ids:
        return []
    
    client = get_guardduty_client(session_context=session_context)
    all_findings = []
    
    try:
        # Process finding IDs in batches of 50 (API limitation)
        for i in range(0, len(finding_ids), 50):
            batch_ids = finding_ids[i:i+50]
            
            findings_response = client.get_findings(
                DetectorId=detector_id,
                FindingIds=batch_ids,
                **kwargs
            )
            
            findings = findings_response.get('Findings', [])
            all_findings.extend(findings)
            
            # Check if we have enough findings
            if len(all_findings) >= max_results:
                return all_findings[:max_results]
        
        return all_findings
    
    except NoCredentialsError:
        logger.error(f"AWS credentials not found for getting GuardDuty findings for detector {detector_id}")
        return []
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(f"AWS API error getting GuardDuty findings for detector {detector_id}: {error_code} - {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error getting GuardDuty findings for detector {detector_id}: {e}")
        return []


def get_findings_statistics(
    detector_id: Optional[str] = None,
    finding_statistic_types: Optional[List[str]] = None,
    group_by: Optional[str] = None,
    finding_criteria: Optional[Dict[str, Any]] = None,
    order_by: Optional[str] = None,
    max_results: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Optional[Dict[str, Any]]:
    """Get official AWS-calculated statistics for GuardDuty findings.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        finding_statistic_types: Types of statistics to retrieve (e.g., ['COUNT_BY_SEVERITY'])
        group_by: Group statistics by one of: ACCOUNT, DATE, FINDING_TYPE, RESOURCE, SEVERITY
        finding_criteria: Criteria to filter findings for statistics
        order_by: Sort order: ASC or DESC (only with group_by)
        max_results: Maximum results to return (only with group_by, default 25, max 100)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the get_findings_statistics API call
        
    Returns:
        Optional[Dict[str, Any]]: Official AWS findings statistics or None if error
        
    Note:
        You must provide either finding_statistic_types OR group_by parameter, but not both.
        The order_by and max_results parameters can only be used with group_by.
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id(session_context=session_context)
        if detector_id is None:
            return None
    
    client = get_guardduty_client(session_context=session_context)
    
    # Validate parameters
    if finding_statistic_types and group_by:
        logger.error("Cannot provide both finding_statistic_types and group_by parameters")
        return None
        
    if not finding_statistic_types and not group_by:
        logger.error("Must provide either finding_statistic_types or group_by parameter")
        return None
    
    if (order_by or max_results) and not group_by:
        logger.error("order_by and max_results can only be used with group_by parameter")
        return None
    
    # Set up parameters
    params = {
        'DetectorId': detector_id,
        **kwargs
    }
    
    if finding_statistic_types:
        params['FindingStatisticTypes'] = finding_statistic_types
    
    if group_by:
        params['GroupBy'] = group_by
        
        if order_by:
            params['OrderBy'] = order_by
            
        if max_results:
            params['MaxResults'] = min(100, max_results)  # API max is 100
    
    if finding_criteria:
        params['FindingCriteria'] = finding_criteria
    
    try:
        response = client.get_findings_statistics(**params)
        
        # Add the DetectorId to the response for consistency
        statistics = response.copy()
        statistics['DetectorId'] = detector_id
        
        return statistics
    
    except NoCredentialsError:
        logger.error(f"AWS credentials not found for getting GuardDuty findings statistics for detector {detector_id}")
        return None
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(f"AWS API error getting GuardDuty findings statistics for detector {detector_id}: {error_code} - {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting GuardDuty findings statistics for detector {detector_id}: {e}")
        return None


def list_ip_sets(
    detector_id: Optional[str] = None,
    max_results: int = 50,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """List IP sets for a GuardDuty detector.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the list_ip_sets API call
        
    Returns:
        List[Dict[str, Any]]: List of IP set details
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id(session_context=session_context)
        if detector_id is None:
            return []
    
    client = get_guardduty_client(session_context=session_context)
    
    # Set up parameters
    params = {
        'DetectorId': detector_id,
        'MaxResults': min(50, max_results),  # API max is 50
        **kwargs
    }
    
    try:
        # Call the API directly and handle pagination manually
        response = client.list_ip_sets(**params)
        ip_set_ids = response.get('IpSetIds', [])
        
        # Handle pagination if there's a next token
        next_token = response.get('NextToken')
        while next_token and len(ip_set_ids) < max_results:
            params['NextToken'] = next_token
            # Adjust max_results for the next request
            params['MaxResults'] = min(50, max_results - len(ip_set_ids))
            
            response = client.list_ip_sets(**params)
            ip_set_ids.extend(response.get('IpSetIds', []))
            next_token = response.get('NextToken')
            
            # Break if we have enough IP sets
            if len(ip_set_ids) >= max_results:
                break
        
        # Limit the results if we got more than requested
        if len(ip_set_ids) > max_results:
            ip_set_ids = ip_set_ids[:max_results]
        
        return [{"IpSetId": ip_set_id} for ip_set_id in ip_set_ids]
    
    except NoCredentialsError:
        logger.error(f"AWS credentials not found for listing GuardDuty IP sets for detector {detector_id}")
        return []
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(f"AWS API error listing GuardDuty IP sets for detector {detector_id}: {error_code} - {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error listing GuardDuty IP sets for detector {detector_id}: {e}")
        return []


def list_threat_intel_sets(
    detector_id: Optional[str] = None,
    max_results: int = 50,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """List threat intelligence sets for a GuardDuty detector.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the list_threat_intel_sets API call
        
    Returns:
        List[Dict[str, Any]]: List of threat intel set details
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id(session_context=session_context)
        if detector_id is None:
            return []
    
    client = get_guardduty_client(session_context=session_context)
    
    # Set up parameters
    params = {
        'DetectorId': detector_id,
        'MaxResults': min(50, max_results),  # API max is 50
        **kwargs
    }
    
    try:
        # Call the API directly and handle pagination manually
        response = client.list_threat_intel_sets(**params)
        threat_intel_set_ids = response.get('ThreatIntelSetIds', [])
        
        # Handle pagination if there's a next token
        next_token = response.get('NextToken')
        while next_token and len(threat_intel_set_ids) < max_results:
            params['NextToken'] = next_token
            # Adjust max_results for the next request
            params['MaxResults'] = min(50, max_results - len(threat_intel_set_ids))
            
            response = client.list_threat_intel_sets(**params)
            threat_intel_set_ids.extend(response.get('ThreatIntelSetIds', []))
            next_token = response.get('NextToken')
            
            # Break if we have enough threat intel sets
            if len(threat_intel_set_ids) >= max_results:
                break
        
        # Limit the results if we got more than requested
        if len(threat_intel_set_ids) > max_results:
            threat_intel_set_ids = threat_intel_set_ids[:max_results]
        
        return [{"ThreatIntelSetId": threat_intel_set_id} for threat_intel_set_id in threat_intel_set_ids]
    
    except NoCredentialsError:
        logger.error(f"AWS credentials not found for listing GuardDuty threat intel sets for detector {detector_id}")
        return []
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(f"AWS API error listing GuardDuty threat intel sets for detector {detector_id}: {error_code} - {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error listing GuardDuty threat intel sets for detector {detector_id}: {e}")
        return []


def filter_findings_by_severity(
    findings: List[Dict[str, Any]],
    severity: str = "ALL"
) -> List[Dict[str, Any]]:
    """Filter findings by severity level.
    
    Args:
        findings: List of findings to filter
        severity: Severity level ("LOW", "MEDIUM", "HIGH", or "ALL")
        
    Returns:
        List[Dict[str, Any]]: Filtered list of findings
    """
    if severity == "ALL":
        return findings
    
    severity_ranges = {
        "LOW": (1.0, 3.9),
        "MEDIUM": (4.0, 6.9),
        "HIGH": (7.0, 10.0)
    }
    
    if severity not in severity_ranges:
        raise ValueError(f"Invalid severity level: {severity}")
    
    min_severity, max_severity = severity_ranges[severity]
    
    return [
        finding for finding in findings
        if min_severity <= finding.get('Severity', 0) <= max_severity
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
        if (search_term_lower in finding.get('Id', '').lower() or
            search_term_lower in finding.get('Type', '').lower() or
            search_term_lower in finding.get('Description', '').lower() or
            search_term_lower in str(finding.get('Resource', {})).lower() or
            search_term_lower in finding.get('Title', '').lower()):
            filtered_findings.append(finding)
    
    return filtered_findings 