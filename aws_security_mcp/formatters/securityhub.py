"""Formatters for SecurityHub resources.

This module provides both string-based and JSON-based formatting functions for SecurityHub resources
to make them more suitable for human consumption and API responses.
"""

import json
from typing import Any, Dict, List, Optional, Union
from datetime import datetime


def format_finding(finding: Dict[str, Any]) -> str:
    """Format a general finding into a readable string.
    
    Args:
        finding: Finding data dictionary
        
    Returns:
        Formatted string representation of the finding
    """
    return f"""
Finding ID: {finding.get('Id', 'Unknown')}
Title: {finding.get('Title', 'Unknown')}
Description: {finding.get('Description', 'No description available')}
Severity: {finding.get('Severity', 'Unknown')}
Created At: {finding.get('CreatedAt', 'Unknown')}
Updated At: {finding.get('UpdatedAt', 'Unknown')}
"""


def format_finding_json(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Format a general finding into structured data for JSON output.
    
    Args:
        finding: Finding data dictionary
        
    Returns:
        Dictionary with formatted finding data
    """
    # Format dates
    created_at = finding.get('CreatedAt')
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    
    updated_at = finding.get('UpdatedAt')
    if isinstance(updated_at, datetime):
        updated_at = updated_at.isoformat()
    
    return {
        "id": finding.get('Id', 'Unknown'),
        "title": finding.get('Title', 'Unknown'),
        "description": finding.get('Description', 'No description available'),
        "severity": finding.get('Severity', 'Unknown'),
        "created_at": created_at,
        "updated_at": updated_at
    }


def format_securityhub_finding(finding: Dict[str, Any]) -> str:
    """Format a SecurityHub finding into a readable string.
    
    Args:
        finding: SecurityHub finding data dictionary
        
    Returns:
        Formatted string representation of the finding
    """
    return f"""
Finding ID: {finding.get('Id', 'Unknown')}
Title: {finding.get('Title', 'Unknown')}
Description: {finding.get('Description', 'No description available')}
Severity: {finding.get('Severity', {}).get('Label', 'Unknown')}
Compliance Status: {finding.get('Compliance', {}).get('Status', 'Unknown')}
Created At: {finding.get('CreatedAt', 'Unknown')}
Updated At: {finding.get('UpdatedAt', 'Unknown')}
Resources:
{format_finding_resources(finding.get('Resources', []))}
Remediation:
  Recommendation: {finding.get('Remediation', {}).get('Recommendation', {}).get('Text', 'No recommendation provided')}
  URL: {finding.get('Remediation', {}).get('Recommendation', {}).get('Url', 'No URL provided')}
"""


def format_securityhub_finding_json(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Format a SecurityHub finding into structured data for JSON output.
    
    Args:
        finding: SecurityHub finding data dictionary
        
    Returns:
        Dictionary with formatted SecurityHub finding data
    """
    # Format dates
    created_at = finding.get('CreatedAt')
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    
    updated_at = finding.get('UpdatedAt')
    if isinstance(updated_at, datetime):
        updated_at = updated_at.isoformat()
    
    # Format resources
    resources = []
    for resource in finding.get('Resources', []):
        resources.append({
            "type": resource.get('Type', 'Unknown'),
            "id": resource.get('Id', 'Unknown'),
            "partition": resource.get('Partition', 'Unknown'),
            "region": resource.get('Region', 'Unknown')
        })
    
    return {
        "id": finding.get('Id', 'Unknown'),
        "title": finding.get('Title', 'Unknown'),
        "description": finding.get('Description', 'No description available'),
        "severity": finding.get('Severity', {}).get('Label', 'Unknown'),
        "compliance_status": finding.get('Compliance', {}).get('Status', 'Unknown'),
        "created_at": created_at,
        "updated_at": updated_at,
        "resources": resources,
        "remediation": {
            "recommendation": finding.get('Remediation', {}).get('Recommendation', {}).get('Text', 'No recommendation provided'),
            "url": finding.get('Remediation', {}).get('Recommendation', {}).get('Url', 'No URL provided')
        }
    }


def format_finding_resources(resources: List[Dict[str, Any]]) -> str:
    """Format the resources section of a SecurityHub finding.
    
    Args:
        resources: List of resources from a SecurityHub finding
        
    Returns:
        Formatted string representation of the resources
    """
    if not resources:
        return "  None affected"
    
    formatted_resources = []
    for resource in resources:
        formatted_resources.append(f"""  Type: {resource.get('Type', 'Unknown')}
  ID: {resource.get('Id', 'Unknown')}
  Partition: {resource.get('Partition', 'Unknown')}
  Region: {resource.get('Region', 'Unknown')}""")
    
    return "\n".join(formatted_resources)


def format_finding_resources_json(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format the resources section of a SecurityHub finding for JSON output.
    
    Args:
        resources: List of resources from a SecurityHub finding
        
    Returns:
        List of formatted resource dictionaries
    """
    formatted_resources = []
    for resource in resources:
        formatted_resources.append({
            "type": resource.get('Type', 'Unknown'),
            "id": resource.get('Id', 'Unknown'),
            "partition": resource.get('Partition', 'Unknown'),
            "region": resource.get('Region', 'Unknown')
        })
    
    return formatted_resources


def format_finding_summary(finding: Dict[str, Any]) -> str:
    """Format a brief summary of a SecurityHub finding.
    
    Args:
        finding: SecurityHub finding data dictionary
        
    Returns:
        Formatted string with a brief summary of the finding
    """
    return f"""
Finding ID: {finding.get('Id', 'Unknown')}
Title: {finding.get('Title', 'Unknown')}
Severity: {finding.get('Severity', {}).get('Label', 'Unknown')}
Compliance Status: {finding.get('Compliance', {}).get('Status', 'Unknown')}
Created At: {finding.get('CreatedAt', 'Unknown')}
Resource Type: {finding.get('Resources', [{}])[0].get('Type', 'Unknown') if finding.get('Resources') else 'Unknown'}
"""


def format_finding_summary_json(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Format a brief summary of a SecurityHub finding for JSON output.
    
    Args:
        finding: SecurityHub finding data dictionary
        
    Returns:
        Dictionary with a brief summary of the finding
    """
    # Format dates
    created_at = finding.get('CreatedAt')
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    
    return {
        "id": finding.get('Id', 'Unknown'),
        "title": finding.get('Title', 'Unknown'),
        "severity": finding.get('Severity', {}).get('Label', 'Unknown'),
        "compliance_status": finding.get('Compliance', {}).get('Status', 'Unknown'),
        "created_at": created_at,
        "resource_type": finding.get('Resources', [{}])[0].get('Type', 'Unknown') if finding.get('Resources') else 'Unknown'
    }


def format_insight(insight: Dict[str, Any]) -> str:
    """Format a SecurityHub insight into a readable string.
    
    Args:
        insight: SecurityHub insight data dictionary
        
    Returns:
        Formatted string representation of the insight
    """
    return f"""
Insight ARN: {insight.get('InsightArn', 'Unknown')}
Name: {insight.get('Name', 'Unknown')}
Filters: {json.dumps(insight.get('Filters', {}), indent=2)}
Group By: {insight.get('GroupByAttribute', 'None')}
"""


def format_insight_json(insight: Dict[str, Any]) -> Dict[str, Any]:
    """Format a SecurityHub insight into structured data for JSON output.
    
    Args:
        insight: SecurityHub insight data dictionary
        
    Returns:
        Dictionary with formatted SecurityHub insight data
    """
    return {
        "insight_arn": insight.get('InsightArn', 'Unknown'),
        "name": insight.get('Name', 'Unknown'),
        "filters": insight.get('Filters', {}),
        "group_by": insight.get('GroupByAttribute', None)
    }


def format_standard(standard: Dict[str, Any]) -> str:
    """Format a SecurityHub standard into a readable string.
    
    Args:
        standard: SecurityHub standard data dictionary
        
    Returns:
        Formatted string representation of the standard
    """
    return f"""
Standard ARN: {standard.get('StandardsArn', 'Unknown')}
Name: {standard.get('Name', 'Unknown')}
Description: {standard.get('Description', 'No description available')}
Enabled: {'Yes' if standard.get('EnabledByDefault') else 'No'}
"""


def format_standard_json(standard: Dict[str, Any]) -> Dict[str, Any]:
    """Format a SecurityHub standard into structured data for JSON output.
    
    Args:
        standard: SecurityHub standard data dictionary
        
    Returns:
        Dictionary with formatted SecurityHub standard data
    """
    return {
        "standard_arn": standard.get('StandardsArn', 'Unknown'),
        "name": standard.get('Name', 'Unknown'),
        "description": standard.get('Description', 'No description available'),
        "enabled_by_default": standard.get('EnabledByDefault', False)
    }


def format_control(control: Dict[str, Any]) -> str:
    """Format a SecurityHub control into a readable string.
    
    Args:
        control: SecurityHub control data dictionary
        
    Returns:
        Formatted string representation of the control
    """
    return f"""
Control ID: {control.get('ControlId', 'Unknown')}
Title: {control.get('Title', 'Unknown')}
Description: {control.get('Description', 'No description available')}
Severity: {control.get('SeverityRating', 'Unknown')}
Status: {control.get('ControlStatus', 'Unknown')}
Compliance Status: {control.get('ComplianceStatus', 'Unknown')}
"""


def format_control_json(control: Dict[str, Any]) -> Dict[str, Any]:
    """Format a SecurityHub control into structured data for JSON output.
    
    Args:
        control: SecurityHub control data dictionary
        
    Returns:
        Dictionary with formatted SecurityHub control data
    """
    return {
        "control_id": control.get('ControlId', 'Unknown'),
        "title": control.get('Title', 'Unknown'),
        "description": control.get('Description', 'No description available'),
        "severity": control.get('SeverityRating', 'Unknown'),
        "status": control.get('ControlStatus', 'Unknown'),
        "compliance_status": control.get('ComplianceStatus', 'Unknown')
    } 