"""Formatters for AWS GuardDuty resources.

This module provides JSON-based formatting functions for AWS GuardDuty resources
to make them more suitable for API responses and LLM consumption.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime


def format_guardduty_detector_json(detector: Dict[str, Any]) -> Dict[str, Any]:
    """Format a GuardDuty detector into structured data for JSON output.
    
    Args:
        detector: GuardDuty detector data dictionary
        
    Returns:
        Dictionary with formatted GuardDuty detector data
    """
    # Format dates
    created_at = detector.get('CreatedAt')
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    
    updated_at = detector.get('UpdatedAt')
    if isinstance(updated_at, datetime):
        updated_at = updated_at.isoformat()
    
    # Format detector status
    status = detector.get('Status', '')
    status_display = "Enabled" if status == "ENABLED" else "Disabled"
    
    # Format data sources
    data_sources = detector.get('DataSources', {})
    features = []
    
    # CloudTrail
    cloud_trail = data_sources.get('CloudTrail', {})
    if cloud_trail.get('Status') == 'ENABLED':
        features.append("CloudTrail logs")
    
    # S3 logs
    s3_logs = data_sources.get('S3Logs', {})
    if s3_logs.get('Status') == 'ENABLED':
        features.append("S3 data events")
    
    # Kubernetes
    kubernetes = data_sources.get('Kubernetes', {})
    if kubernetes.get('AuditLogs', {}).get('Status') == 'ENABLED':
        features.append("Kubernetes audit logs")
    
    # Malware Protection
    malware_protection = data_sources.get('MalwareProtection', {})
    if malware_protection.get('ScanEc2InstanceWithFindings', {}).get('Status') == 'ENABLED':
        features.append("Malware protection for EC2")
    
    return {
        "detector_id": detector.get('DetectorId', ''),
        "status": status_display,
        "service_role": detector.get('ServiceRole', ''),
        "created_at": created_at,
        "updated_at": updated_at,
        "finding_publishing_frequency": detector.get('FindingPublishingFrequency', '').replace('_', ' ').lower(),
        "enabled_features": features,
        "features_count": len(features),
        "tags": {tag['Key']: tag['Value'] for tag in detector.get('Tags', [])}
    }


def format_guardduty_finding_json(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Format a GuardDuty finding into structured data for JSON output.
    
    Args:
        finding: GuardDuty finding data dictionary
        
    Returns:
        Dictionary with formatted GuardDuty finding data
    """
    # Format dates
    created_at = finding.get('CreatedAt')
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    
    updated_at = finding.get('UpdatedAt')
    if isinstance(updated_at, datetime):
        updated_at = updated_at.isoformat()
    
    # Extract severity information
    severity = finding.get('Severity', 0)
    severity_label = "Low"
    if severity >= 7.0:
        severity_label = "High"
    elif severity >= 4.0:
        severity_label = "Medium"
    
    # Format resource information
    resource = finding.get('Resource', {})
    resource_type = resource.get('ResourceType', '')
    resource_details = {}
    
    if resource_type == 'AccessKey':
        resource_details = {
            "type": "IAM Access Key",
            "user_name": resource.get('AccessKeyDetails', {}).get('UserName', ''),
            "principal_id": resource.get('AccessKeyDetails', {}).get('PrincipalId', '')
        }
    elif resource_type == 'Instance':
        instance_details = resource.get('InstanceDetails', {})
        resource_details = {
            "type": "EC2 Instance",
            "instance_id": instance_details.get('InstanceId', ''),
            "instance_type": instance_details.get('InstanceType', ''),
            "vpc_id": instance_details.get('NetworkInterfaces', [{}])[0].get('VpcId', '') if instance_details.get('NetworkInterfaces') else '',
            "subnet_id": instance_details.get('NetworkInterfaces', [{}])[0].get('SubnetId', '') if instance_details.get('NetworkInterfaces') else '',
            "image_id": instance_details.get('ImageId', '')
        }
    elif resource_type == 'S3Bucket':
        bucket_details = resource.get('S3BucketDetails', [{}])[0] if resource.get('S3BucketDetails') else {}
        resource_details = {
            "type": "S3 Bucket",
            "name": bucket_details.get('Name', ''),
            "arn": bucket_details.get('Arn', ''),
            "is_public": bucket_details.get('PublicAccess', {}).get('EffectivePermission', '') == 'PUBLIC'
        }
    
    # Service affected
    service = finding.get('Service', {})
    service_name = service.get('ServiceName', '')
    
    return {
        "id": finding.get('Id', ''),
        "title": finding.get('Title', ''),
        "description": finding.get('Description', ''),
        "detector_id": finding.get('DetectorId', ''),
        "account_id": finding.get('AccountId', ''),
        "region": finding.get('Region', ''),
        "type": finding.get('Type', ''),
        "created_at": created_at,
        "updated_at": updated_at,
        "severity": {
            "value": severity,
            "label": severity_label
        },
        "confidence": finding.get('Confidence', 0),
        "resource": resource_details,
        "service": {
            "name": service_name,
            "action": service.get('Action', {}).get('ActionType', ''),
            "count": service.get('Count', 0)
        },
        "archived": finding.get('Archived', False)
    }


def format_guardduty_findings_list_statistics_json(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate and format statistics from a list of GuardDuty findings.
    
    Args:
        findings: List of GuardDuty finding data dictionaries
        
    Returns:
        Dictionary with formatted statistics data similar to format_guardduty_findings_statistics_json
    """
    if not findings:
        return {
            "total_findings": 0,
            "by_severity": {
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "severity_distribution": {
                "high_percent": 0,
                "medium_percent": 0,
                "low_percent": 0
            },
            "top_finding_types": []
        }
    
    # Count findings by severity
    high_severity = 0
    medium_severity = 0
    low_severity = 0
    
    # Count findings by type
    type_counts = {}
    
    for finding in findings:
        severity = finding.get('Severity', 0)
        
        # Categorize by severity
        if severity >= 7.0:
            high_severity += 1
        elif severity >= 4.0:
            medium_severity += 1
        else:
            low_severity += 1
        
        # Count by finding type
        finding_type = finding.get('Type', 'Unknown')
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
    
    total_count = len(findings)
    
    # Get top 5 finding types
    top_types = []
    for type_name, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        top_types.append({
            "type": type_name,
            "count": count,
            "percentage": round((count / total_count * 100) if total_count > 0 else 0, 1)
        })
    
    return {
        "total_findings": total_count,
        "by_severity": {
            "high": high_severity,
            "medium": medium_severity,
            "low": low_severity
        },
        "severity_distribution": {
            "high_percent": round((high_severity / total_count * 100) if total_count > 0 else 0, 1),
            "medium_percent": round((medium_severity / total_count * 100) if total_count > 0 else 0, 1),
            "low_percent": round((low_severity / total_count * 100) if total_count > 0 else 0, 1)
        },
        "top_finding_types": top_types
    }


def format_guardduty_findings_statistics_json(statistics: Dict[str, Any]) -> Dict[str, Any]:
    """Format GuardDuty findings statistics into structured data for JSON output.
    
    Args:
        statistics: GuardDuty findings statistics data dictionary
        
    Returns:
        Dictionary with formatted GuardDuty findings statistics data
    """
    # Extract counts by severity
    finding_counts = statistics.get('CountBySeverity', {})
    high_severity = int(finding_counts.get('7-8.9', 0)) + int(finding_counts.get('9+', 0))
    medium_severity = int(finding_counts.get('4-6.9', 0))
    low_severity = int(finding_counts.get('1-3.9', 0))
    
    # Total count
    total_count = high_severity + medium_severity + low_severity
    
    # Count by type
    type_counts = statistics.get('CountByType', {})
    top_types = []
    for type_name, count in sorted(type_counts.items(), key=lambda x: int(x[1]), reverse=True)[:5]:
        top_types.append({
            "type": type_name,
            "count": int(count),
            "percentage": round((int(count) / total_count * 100) if total_count > 0 else 0, 1)
        })
    
    return {
        "total_findings": total_count,
        "by_severity": {
            "high": high_severity,
            "medium": medium_severity,
            "low": low_severity
        },
        "severity_distribution": {
            "high_percent": round((high_severity / total_count * 100) if total_count > 0 else 0, 1),
            "medium_percent": round((medium_severity / total_count * 100) if total_count > 0 else 0, 1),
            "low_percent": round((low_severity / total_count * 100) if total_count > 0 else 0, 1)
        },
        "top_finding_types": top_types
    }


def format_guardduty_ip_set_json(ip_set: Dict[str, Any]) -> Dict[str, Any]:
    """Format a GuardDuty IP set into structured data for JSON output.
    
    Args:
        ip_set: GuardDuty IP set data dictionary
        
    Returns:
        Dictionary with formatted GuardDuty IP set data
    """
    # Get IP set status
    status = ip_set.get('Status', '')
    status_display = "Active" if status == "ACTIVE" else "Inactive"
    
    # Format for IP set type
    format_type = ip_set.get('Format', '')
    format_display = "Plain text IPs (TXT)" if format_type == "TXT" else "Firewall IPs (FIRE_EYE)"
    
    # Format dates
    created_at = ip_set.get('CreatedAt')
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    
    updated_at = ip_set.get('UpdatedAt')
    if isinstance(updated_at, datetime):
        updated_at = updated_at.isoformat()
    
    return {
        "ip_set_id": ip_set.get('IpSetId', ''),
        "name": ip_set.get('Name', ''),
        "status": status_display,
        "location": ip_set.get('Location', ''),
        "format": format_display,
        "created_at": created_at,
        "updated_at": updated_at,
        "is_trusted": ip_set.get('IsTrusted', False),
        "tags": {tag['Key']: tag['Value'] for tag in ip_set.get('Tags', [])}
    }


def format_guardduty_threat_intel_set_json(threat_intel_set: Dict[str, Any]) -> Dict[str, Any]:
    """Format a GuardDuty threat intelligence set into structured data for JSON output.
    
    Args:
        threat_intel_set: GuardDuty threat intelligence set data dictionary
        
    Returns:
        Dictionary with formatted GuardDuty threat intelligence set data
    """
    # Get threat intel set status
    status = threat_intel_set.get('Status', '')
    status_display = "Active" if status == "ACTIVE" else "Inactive"
    
    # Format for threat intel set type
    format_type = threat_intel_set.get('Format', '')
    format_display = "Domain list (TXT)" if format_type == "TXT" else "Structured data (STIX)"
    
    # Format dates
    created_at = threat_intel_set.get('CreatedAt')
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    
    updated_at = threat_intel_set.get('UpdatedAt')
    if isinstance(updated_at, datetime):
        updated_at = updated_at.isoformat()
    
    return {
        "threat_intel_set_id": threat_intel_set.get('ThreatIntelSetId', ''),
        "name": threat_intel_set.get('Name', ''),
        "status": status_display,
        "location": threat_intel_set.get('Location', ''),
        "format": format_display,
        "created_at": created_at,
        "updated_at": updated_at,
        "tags": {tag['Key']: tag['Value'] for tag in threat_intel_set.get('Tags', [])}
    }


def format_guardduty_filter_json(filter_data: Dict[str, Any], filter_name: str) -> Dict[str, Any]:
    """Format a GuardDuty filter into structured data for JSON output.
    
    Args:
        filter_data: GuardDuty filter data dictionary
        filter_name: Name of the filter
        
    Returns:
        Dictionary with formatted GuardDuty filter data
    """
    return {
        "name": filter_name,
        "action": filter_data.get('Action', ''),
        "description": filter_data.get('Description', ''),
        "rank": filter_data.get('Rank', 0),
        "finding_criteria": filter_data.get('FindingCriteria', {}),
        "tags": filter_data.get('Tags', {})
    }


def format_guardduty_detectors_summary_json(
    detectors: List[Dict[str, Any]],
    findings_count: Optional[int] = None
) -> Dict[str, Any]:
    """Format a summary of GuardDuty detectors into structured data for JSON output.
    
    Args:
        detectors: List of GuardDuty detector data dictionaries
        findings_count: Optional count of total findings across all detectors
        
    Returns:
        Dictionary with summary statistics for GuardDuty detectors
    """
    # Calculate enabled/disabled detectors
    total_detectors = len(detectors)
    enabled_detectors = sum(1 for d in detectors if d.get('Status') == 'ENABLED')
    disabled_detectors = total_detectors - enabled_detectors
    
    # Get finding frequencies
    finding_frequencies = {}
    for detector in detectors:
        freq = detector.get('FindingPublishingFrequency', 'UNKNOWN')
        finding_frequencies[freq] = finding_frequencies.get(freq, 0) + 1
    
    return {
        "total_detectors": total_detectors,
        "enabled_detectors": enabled_detectors,
        "disabled_detectors": disabled_detectors,
        "finding_publishing_frequencies": finding_frequencies,
        "total_findings": findings_count,
        "regions_covered": len(set(detector.get('Region', '') for detector in detectors if 'Region' in detector))
    } 