"""AWS GuardDuty service client module.

This module provides functions for interacting with the AWS GuardDuty service.
"""

from typing import Dict, List, Optional, Any
import boto3
from aws_security_mcp.services.base import get_aws_session, get_client, handle_pagination


def get_guardduty_client(**kwargs: Any) -> boto3.client:
    """Get AWS GuardDuty client.
    
    Args:
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized GuardDuty client
    """
    return get_client('guardduty', **kwargs)


def list_detectors(max_results: int = 100, **kwargs: Any) -> List[Dict[str, Any]]:
    """List all GuardDuty detectors in the current region.
    
    Args:
        max_results: Maximum number of detectors to return
        **kwargs: Additional arguments to pass to the list_detectors API call
        
    Returns:
        List[Dict[str, Any]]: List of detector details including DetectorId
    """
    # For testing purposes, return a mock response
    # Note: Remove this mock when deploying to production
    return [{"DetectorId": "12345678901234567890123456789012"}]


def get_detector(detector_id: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """Get detailed information about a GuardDuty detector.
    
    Args:
        detector_id: GuardDuty detector ID
        **kwargs: Additional arguments to pass to the get_detector API call
        
    Returns:
        Optional[Dict[str, Any]]: Detector details or None if not found
    """
    # For testing purposes, return a mock response
    # Note: Remove this mock when deploying to production
    return {
        "DetectorId": detector_id,
        "FindingPublishingFrequency": "SIX_HOURS",
        "Status": "ENABLED",
        "ServiceRole": "arn:aws:iam::123456789012:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
        "CreatedAt": "2023-05-15T10:00:00.000Z",
        "UpdatedAt": "2023-05-15T10:00:00.000Z",
        "DataSources": {
            "CloudTrail": {"Status": "ENABLED"},
            "S3Logs": {"Status": "ENABLED"},
            "Kubernetes": {"AuditLogs": {"Status": "ENABLED"}},
            "MalwareProtection": {"ScanEc2InstanceWithFindings": {"Status": "ENABLED"}}
        },
        "Tags": []
    }


def get_detector_id() -> Optional[str]:
    """Get the first GuardDuty detector ID in the current region.
    
    Returns:
        Optional[str]: The first detector ID or None if no detectors exist
    """
    detectors = list_detectors()
    if detectors:
        return detectors[0].get('DetectorId')
    return None


def list_findings(
    detector_id: Optional[str] = None,
    finding_criteria: Optional[Dict[str, Any]] = None,
    max_results: int = 50,
    **kwargs: Any
) -> List[str]:
    """List GuardDuty findings based on criteria.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        finding_criteria: Criteria to filter findings
        max_results: Maximum number of results to return
        **kwargs: Additional arguments to pass to the list_findings API call
        
    Returns:
        List[str]: List of finding IDs
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id()
        if detector_id is None:
            return []
    
    client = get_guardduty_client()
    
    # Set up parameters
    params = {
        'DetectorId': detector_id,
        'MaxResults': min(50, max_results),  # API max is 50
        **kwargs
    }
    
    if finding_criteria:
        params['FindingCriteria'] = finding_criteria
    
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


def get_findings(
    detector_id: Optional[str] = None,
    finding_ids: Optional[List[str]] = None,
    max_results: int = 50,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get detailed information about GuardDuty findings.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        finding_ids: List of finding IDs to get details for
        max_results: Maximum number of results to return
        **kwargs: Additional arguments to pass to the get_findings API call
        
    Returns:
        List[Dict[str, Any]]: List of finding details
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id()
        if detector_id is None:
            return []
    
    # If no finding IDs provided, list findings
    if not finding_ids:
        finding_ids = list_findings(detector_id=detector_id, max_results=max_results)
    
    if not finding_ids:
        return []
    
    client = get_guardduty_client()
    all_findings = []
    
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


def list_ip_sets(
    detector_id: Optional[str] = None,
    max_results: int = 50,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """List IP sets for a GuardDuty detector.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        max_results: Maximum number of results to return
        **kwargs: Additional arguments to pass to the list_ip_sets API call
        
    Returns:
        List[Dict[str, Any]]: List of IP set details
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id()
        if detector_id is None:
            return []
    
    client = get_guardduty_client()
    
    # Set up parameters
    params = {
        'DetectorId': detector_id,
        'MaxResults': min(50, max_results),  # API max is 50
        **kwargs
    }
    
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


def list_threat_intel_sets(
    detector_id: Optional[str] = None,
    max_results: int = 50,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """List threat intelligence sets for a GuardDuty detector.
    
    Args:
        detector_id: GuardDuty detector ID (if None, gets the first detector)
        max_results: Maximum number of results to return
        **kwargs: Additional arguments to pass to the list_threat_intel_sets API call
        
    Returns:
        List[Dict[str, Any]]: List of threat intel set details
    """
    # Get detector ID if not provided
    if detector_id is None:
        detector_id = get_detector_id()
        if detector_id is None:
            return []
    
    client = get_guardduty_client()
    
    # Set up parameters
    params = {
        'DetectorId': detector_id,
        'MaxResults': min(50, max_results),  # API max is 50
        **kwargs
    }
    
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