"""GuardDuty tools for AWS Security MCP."""

import logging
import json
from datetime import datetime
from typing import List, Optional, Dict, Any

from aws_security_mcp.services import guardduty
from aws_security_mcp.tools import register_tool
from aws_security_mcp.formatters.guardduty import (
    format_guardduty_detector_json,
    format_guardduty_finding_json,
    format_guardduty_findings_list_statistics_json,
    format_guardduty_findings_statistics_json,
    format_guardduty_detectors_summary_json,
    format_guardduty_ip_set_json,
    format_guardduty_threat_intel_set_json
)

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
async def list_detectors(max_results: int = 100, session_context: Optional[str] = None) -> str:
    """List all GuardDuty detectors in the account.
    
    Args:
        max_results: Maximum number of detectors to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with GuardDuty detectors
    """
    logger.info(f"Listing GuardDuty detectors (session_context={session_context})")
    
    try:
        logger.info("Calling guardduty.list_detectors")
        detectors = guardduty.list_detectors(max_results=max_results, session_context=session_context)
        logger.info(f"Received detectors: {detectors}")
        
        if not detectors:
            return json.dumps({
                "count": 0,
                "summary": "No GuardDuty detectors found in the account",
                "detectors": []
            })
        
        formatted_detectors = []
        detector_details = []
        
        for detector in detectors:
            logger.info(f"Processing detector: {detector}")
            # The detector should be a dictionary with a DetectorId key
            detector_id = detector.get('DetectorId')
            logger.info(f"Detector ID: {detector_id}")
            
            if not detector_id:
                logger.warning(f"Detector without ID found: {detector}")
                continue
                
            try:
                # Get detector details
                logger.info(f"Calling guardduty.get_detector with ID: {detector_id}")
                details = guardduty.get_detector(detector_id, session_context=session_context)
                logger.info(f"Received detector details: {details}")
                
                if details:
                    # Store the details for summary
                    detector_details.append(details)
                    
                    # Format the detector with our JSON formatter
                    logger.info("Formatting detector with format_guardduty_detector_json")
                    formatted_detector = format_guardduty_detector_json(details)
                    logger.info(f"Formatted detector: {formatted_detector}")
                    formatted_detectors.append(formatted_detector)
                else:
                    logger.warning(f"No details found for detector ID: {detector_id}")
                    # Just include the basic detector ID
                    formatted_detectors.append({
                        "detector_id": detector_id,
                        "status": "Unknown",
                        "created_at": None,
                        "updated_at": None,
                        "service_role": None,
                        "features": []
                    })
            except Exception as e:
                logger.warning(f"Error getting details for detector {detector_id}: {e}")
                # Just include the basic detector ID
                formatted_detectors.append({
                    "detector_id": detector_id,
                    "status": "Unknown",
                    "created_at": None,
                    "updated_at": None,
                    "service_role": None,
                    "features": []
                })
        
        # Get a summary of all detectors
        logger.info(f"Creating summary from detector details: {detector_details}")
        if detector_details:
            logger.info("Calling format_guardduty_detectors_summary_json")
            detectors_summary = format_guardduty_detectors_summary_json(detector_details)
            logger.info(f"Detector summary: {detectors_summary}")
        else:
            logger.info("No detector details for summary, using default values")
            detectors_summary = {
                "total_detectors": len(formatted_detectors),
                "enabled_detectors": 0,
                "disabled_detectors": 0,
                "finding_publishing_frequencies": {},
                "total_findings": None,
                "regions_covered": 0
            }
        
        result = {
            "count": len(formatted_detectors),
            "summary": f"Found {len(formatted_detectors)} GuardDuty detector(s)",
            "detectors": formatted_detectors,
            "detectors_summary": detectors_summary
        }
        
        logger.info("Serializing result to JSON")
        return json.dumps(result, default=lambda obj: obj.isoformat() if hasattr(obj, 'isoformat') else str(obj))
    except Exception as e:
        logger.error(f"Error listing GuardDuty detectors: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return json.dumps({
            "error": {
                "message": f"Error listing GuardDuty detectors: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def list_findings(
    detector_id: str, 
    max_results: int = 50, 
    finding_ids: Optional[List[str]] = None,
    severity: Optional[str] = None,
    search_term: Optional[str] = None,
    session_context: Optional[str] = None
) -> str:
    """List GuardDuty findings for a specific detector.
    
    Args:
        detector_id: GuardDuty detector ID
        max_results: Maximum number of findings to return
        finding_ids: Optional list of specific finding IDs to retrieve
        severity: Optional severity filter (LOW, MEDIUM, HIGH, ALL)
        search_term: Optional text search term
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with GuardDuty findings
    """
    logger.info(f"Listing GuardDuty findings for detector {detector_id} (session_context={session_context})")
    
    try:
        # Fetch findings
        if finding_ids:
            findings = guardduty.get_findings(detector_id, finding_ids, max_results=max_results, session_context=session_context)
        else:
            finding_ids = guardduty.list_findings(detector_id, max_results=max_results, session_context=session_context)
            findings = guardduty.get_findings(detector_id, finding_ids, max_results=max_results, session_context=session_context)
        
        if not findings:
            return json.dumps({
                "detector_id": detector_id,
                "count": 0,
                "summary": f"No GuardDuty findings for detector '{detector_id}'",
                "findings": []
            })
        
        # Apply filters if provided
        if severity and severity != "ALL":
            findings = guardduty.filter_findings_by_severity(findings, severity)
        
        if search_term:
            findings = guardduty.filter_findings_by_text(findings, search_term)
        
        # Get a summary of findings
        findings_summary = format_guardduty_findings_list_statistics_json(findings)
        
        # Format each finding
        formatted_findings = []
        for finding in findings:
            formatted_finding = format_guardduty_finding_json(finding)
            formatted_findings.append(formatted_finding)
        
        result = {
            "detector_id": detector_id,
            "count": len(findings),
            "summary": f"Found {len(findings)} GuardDuty finding(s) for detector '{detector_id}'",
            "findings": formatted_findings,
            "severity_distribution": findings_summary.get("severity_distribution", {}),
            "top_finding_types": findings_summary.get("top_finding_types", [])
        }
        
        return json.dumps(result, default=lambda obj: obj.isoformat() if hasattr(obj, 'isoformat') else str(obj))
    except Exception as e:
        logger.error(f"Error listing GuardDuty findings: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing GuardDuty findings for detector '{detector_id}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def get_findings_statistics(
    detector_id: str,
    finding_statistic_types: Optional[List[str]] = None,
    group_by: Optional[str] = None,
    finding_criteria: Optional[Dict[str, Any]] = None,
    order_by: Optional[str] = None,
    max_results: Optional[int] = None,
    session_context: Optional[str] = None
) -> str:
    """Get official AWS-calculated statistics for GuardDuty findings.
    
    Args:
        detector_id: GuardDuty detector ID
        finding_statistic_types: Types of statistics to retrieve (e.g., ['COUNT_BY_SEVERITY'])
        group_by: Group statistics by one of: ACCOUNT, DATE, FINDING_TYPE, RESOURCE, SEVERITY
        finding_criteria: Criteria to filter findings for statistics
        order_by: Sort order: ASC or DESC (only with group_by)
        max_results: Maximum results to return (only with group_by, default 25, max 100)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with official AWS GuardDuty findings statistics
        
    Examples:
        # Get severity count statistics
        finding_statistic_types=['COUNT_BY_SEVERITY']
        
        # Get statistics grouped by finding type
        group_by='FINDING_TYPE', order_by='DESC', max_results=10
        
        # Get statistics with filtering
        finding_criteria={'Criterion': {'severity': {'Gte': 4.0}}}
    """
    logger.info(f"Getting GuardDuty findings statistics for detector {detector_id} (session_context={session_context})")
    
    try:
        # Call the service function
        statistics = guardduty.get_findings_statistics(
            detector_id=detector_id,
            finding_statistic_types=finding_statistic_types,
            group_by=group_by,
            finding_criteria=finding_criteria,
            order_by=order_by,
            max_results=max_results,
            session_context=session_context
        )
        
        if not statistics:
            return json.dumps({
                "detector_id": detector_id,
                "error": "Unable to retrieve findings statistics",
                "statistics": None
            })
        
        # Extract the findings statistics from the response
        finding_statistics = statistics.get('FindingStatistics', {})
        
        # Format the statistics using the existing formatter
        formatted_statistics = format_guardduty_findings_statistics_json(finding_statistics)
        
        result = {
            "detector_id": detector_id,
            "summary": "Official AWS GuardDuty findings statistics",
            "statistics_type": "severity_count" if finding_statistic_types else f"grouped_by_{group_by.lower()}" if group_by else "unknown",
            "official_statistics": formatted_statistics,
            "raw_response": {
                "finding_statistics": finding_statistics,
                "next_token": statistics.get('NextToken')
            }
        }
        
        return json.dumps(result, default=lambda obj: obj.isoformat() if hasattr(obj, 'isoformat') else str(obj))
    except Exception as e:
        logger.error(f"Error getting GuardDuty findings statistics: {e}")
        return json.dumps({
            "error": {
                "message": f"Error getting GuardDuty findings statistics for detector '{detector_id}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def get_finding_details(detector_id: str, finding_id: str, session_context: Optional[str] = None) -> str:
    """Get detailed information about a specific GuardDuty finding.
    
    Args:
        detector_id: GuardDuty detector ID
        finding_id: ID of the finding to retrieve
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with detailed finding information
    """
    logger.info(f"Getting GuardDuty finding details for detector {detector_id}, finding {finding_id} (session_context={session_context})")
    
    try:
        findings = guardduty.get_findings(detector_id, [finding_id], session_context=session_context)
        
        if not findings:
            return json.dumps({
                "error": f"Finding '{finding_id}' not found for detector '{detector_id}'"
            })
        
        finding = findings[0]  # Should only be one finding
        
        # Use the JSON formatter for detailed formatting
        formatted_finding = format_guardduty_finding_json(finding)
        
        result = {
            "detector_id": detector_id,
            "finding": formatted_finding
        }
        
        return json.dumps(result, default=lambda obj: obj.isoformat() if hasattr(obj, 'isoformat') else str(obj))
    except Exception as e:
        logger.error(f"Error retrieving GuardDuty finding details: {e}")
        return json.dumps({
            "error": {
                "message": f"Error retrieving GuardDuty finding details for detector '{detector_id}', finding '{finding_id}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def list_ip_sets(detector_id: str, max_results: int = 50, session_context: Optional[str] = None) -> str:
    """List IP sets for a GuardDuty detector.
    
    Args:
        detector_id: GuardDuty detector ID
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with GuardDuty IP sets
    """
    logger.info(f"Listing GuardDuty IP sets for detector {detector_id} (session_context={session_context})")
    
    try:
        ip_sets_ids = guardduty.list_ip_sets(detector_id, max_results=max_results, session_context=session_context)
        
        if not ip_sets_ids:
            return json.dumps({
                "detector_id": detector_id,
                "count": 0,
                "summary": f"No GuardDuty IP sets for detector '{detector_id}'",
                "ip_sets": []
            })
        
        # Get details for each IP set
        client = guardduty.get_guardduty_client(session_context=session_context)
        formatted_ip_sets = []
        
        for ip_set in ip_sets_ids:
            ip_set_id = ip_set.get('IpSetId')
            try:
                ip_set_details = client.get_ip_set(
                    DetectorId=detector_id,
                    IpSetId=ip_set_id
                )
                # Add the IP set ID to the response if not present
                if 'IpSetId' not in ip_set_details:
                    ip_set_details['IpSetId'] = ip_set_id
                
                formatted_ip_set = format_guardduty_ip_set_json(ip_set_details)
                formatted_ip_sets.append(formatted_ip_set)
            except Exception as e:
                logger.warning(f"Error getting details for IP set {ip_set_id}: {e}")
                # Include a basic entry for the IP set
                formatted_ip_sets.append({
                    "ip_set_id": ip_set_id,
                    "name": "Unknown",
                    "status": "Unknown",
                    "location": "Unknown"
                })
        
        result = {
            "detector_id": detector_id,
            "count": len(formatted_ip_sets),
            "summary": f"Found {len(formatted_ip_sets)} GuardDuty IP set(s) for detector '{detector_id}'",
            "ip_sets": formatted_ip_sets
        }
        
        return json.dumps(result, default=lambda obj: obj.isoformat() if hasattr(obj, 'isoformat') else str(obj))
    except Exception as e:
        logger.error(f"Error listing GuardDuty IP sets: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing GuardDuty IP sets for detector '{detector_id}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def list_threat_intel_sets(detector_id: str, max_results: int = 50, session_context: Optional[str] = None) -> str:
    """List threat intelligence sets for a GuardDuty detector.
    
    Args:
        detector_id: GuardDuty detector ID
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with GuardDuty threat intel sets
    """
    logger.info(f"Listing GuardDuty threat intel sets for detector {detector_id} (session_context={session_context})")
    
    try:
        threat_intel_set_ids = guardduty.list_threat_intel_sets(detector_id, max_results=max_results, session_context=session_context)
        
        if not threat_intel_set_ids:
            return json.dumps({
                "detector_id": detector_id,
                "count": 0,
                "summary": f"No GuardDuty threat intel sets for detector '{detector_id}'",
                "threat_intel_sets": []
            })
        
        # Get details for each threat intel set
        client = guardduty.get_guardduty_client(session_context=session_context)
        formatted_threat_intel_sets = []
        
        for threat_intel_set in threat_intel_set_ids:
            threat_intel_set_id = threat_intel_set.get('ThreatIntelSetId')
            try:
                threat_intel_set_details = client.get_threat_intel_set(
                    DetectorId=detector_id,
                    ThreatIntelSetId=threat_intel_set_id
                )
                # Add the threat intel set ID to the response if not present
                if 'ThreatIntelSetId' not in threat_intel_set_details:
                    threat_intel_set_details['ThreatIntelSetId'] = threat_intel_set_id
                
                formatted_threat_intel_set = format_guardduty_threat_intel_set_json(threat_intel_set_details)
                formatted_threat_intel_sets.append(formatted_threat_intel_set)
            except Exception as e:
                logger.warning(f"Error getting details for threat intel set {threat_intel_set_id}: {e}")
                # Include a basic entry for the threat intel set
                formatted_threat_intel_sets.append({
                    "threat_intel_set_id": threat_intel_set_id,
                    "name": "Unknown",
                    "status": "Unknown",
                    "location": "Unknown"
                })
        
        result = {
            "detector_id": detector_id,
            "count": len(formatted_threat_intel_sets),
            "summary": f"Found {len(formatted_threat_intel_sets)} GuardDuty threat intel set(s) for detector '{detector_id}'",
            "threat_intel_sets": formatted_threat_intel_sets
        }
        
        return json.dumps(result, default=lambda obj: obj.isoformat() if hasattr(obj, 'isoformat') else str(obj))
    except Exception as e:
        logger.error(f"Error listing GuardDuty threat intel sets: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing GuardDuty threat intel sets for detector '{detector_id}': {str(e)}",
                "type": type(e).__name__
            }
        }) 