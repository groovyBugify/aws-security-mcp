"""Formatters for Route53 resources."""

import json
from typing import Any, Dict, List, Optional, Union


def format_hosted_zone(zone: Dict[str, Any]) -> str:
    """Format a Route53 hosted zone into a readable string.
    
    Args:
        zone: Route53 hosted zone data dictionary
        
    Returns:
        Formatted string representation of the hosted zone
    """
    return f"""
Hosted Zone ID: {zone.get('Id', 'Unknown').replace('/hostedzone/', '')}
Name: {zone.get('Name', 'Unknown')}
Record Count: {zone.get('ResourceRecordSetCount', 'Unknown')}
Private Zone: {'Yes' if zone.get('Config', {}).get('PrivateZone') else 'No'}
"""


def format_record_set(record: Dict[str, Any]) -> str:
    """Format a Route53 record set into a readable string.
    
    Args:
        record: Route53 record set data dictionary
        
    Returns:
        Formatted string representation of the record set
    """
    resource_records = record.get('ResourceRecords', [])
    records_str = "\n  ".join([f"{r.get('Value', 'Unknown')}" for r in resource_records])
    if not records_str:
        if record.get('AliasTarget'):
            records_str = f"ALIAS -> {record.get('AliasTarget', {}).get('DNSName', 'Unknown')}"
        else:
            records_str = "None"
    
    return f"""
Name: {record.get('Name', 'Unknown')}
Type: {record.get('Type', 'Unknown')}
TTL: {record.get('TTL', 'N/A')}
Records:
  {records_str}
"""


def format_health_check(health_check: Dict[str, Any]) -> str:
    """Format a Route53 health check into a readable string.
    
    Args:
        health_check: Route53 health check data dictionary
        
    Returns:
        Formatted string representation of the health check
    """
    config = health_check.get('HealthCheckConfig', {})
    
    return f"""
Health Check ID: {health_check.get('Id', 'Unknown')}
Type: {config.get('Type', 'Unknown')}
Target: {config.get('IPAddress', config.get('FullyQualifiedDomainName', 'Unknown'))}
Port: {config.get('Port', 'Unknown')}
Resource Path: {config.get('ResourcePath', 'N/A')}
Interval: {config.get('RequestInterval', 'Unknown')} seconds
Failure Threshold: {config.get('FailureThreshold', 'Unknown')}
""" 