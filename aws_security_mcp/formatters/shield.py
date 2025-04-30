"""Formatters for AWS Shield resources.

This module provides JSON-based formatting functions for AWS Shield resources
to make them more suitable for API responses and LLM consumption.
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime


def format_shield_subscription_json(subscription: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Shield Advanced subscription into structured data for JSON output.
    
    Args:
        subscription: Shield subscription data dictionary
        
    Returns:
        Dictionary with formatted Shield subscription data
    """
    # Check if there is a subscription
    has_subscription = bool(subscription)
    
    # Format start time if present
    start_time = subscription.get('StartTime')
    if isinstance(start_time, datetime):
        start_time = start_time.isoformat()
    
    # Format end time if present
    end_time = subscription.get('EndTime')
    if isinstance(end_time, datetime):
        end_time = end_time.isoformat()
    
    return {
        "has_subscription": has_subscription,
        "subscription_active": subscription.get('SubscriptionArn') is not None,
        "time_commitment_in_seconds": subscription.get('TimeCommitmentInSeconds'),
        "auto_renew": subscription.get('AutoRenew', False),
        "start_time": start_time,
        "end_time": end_time,
        "limits": subscription.get('Limits', [])
    }


def format_shield_protection_json(protection: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Shield protection into structured data for JSON output.
    
    Args:
        protection: Shield protection data dictionary
        
    Returns:
        Dictionary with formatted Shield protection data
    """
    # Extract resource information from ARN if present
    resource_arn = protection.get('ResourceArn', '')
    resource_info = parse_resource_arn(resource_arn)
    
    return {
        "id": protection.get('Id', 'Unknown'),
        "name": protection.get('Name', 'Unknown'),
        "resource_arn": resource_arn,
        "protection_arn": protection.get('ProtectionArn', ''),
        "resource": resource_info,
        "application_layer_automatic_response": protection.get('ApplicationLayerAutomaticResponseConfiguration', {}).get('Status', 'DISABLED'),
        "health_check_ids": protection.get('HealthCheckIds', [])
    }


def format_shield_protected_resource_json(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Shield protected resource into structured data for JSON output.
    
    Args:
        resource: Shield protected resource data dictionary
        
    Returns:
        Dictionary with formatted Shield protected resource data
    """
    # Extract resource information from ARN
    resource_arn = resource.get('ResourceArn', '')
    resource_info = parse_resource_arn(resource_arn)
    
    return {
        "resource_arn": resource_arn,
        "protection_id": resource.get('ProtectionId'),
        "resource_type": resource_info.get('service'),
        "resource_id": resource_info.get('resource_id'),
        "region": resource_info.get('region'),
        "account_id": resource_info.get('account_id')
    }


def format_shield_attack_json(attack: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Shield attack into structured data for JSON output.
    
    Args:
        attack: Shield attack data dictionary
        
    Returns:
        Dictionary with formatted Shield attack data
    """
    # Format start time
    start_time = attack.get('StartTime')
    if isinstance(start_time, datetime):
        start_time = start_time.isoformat()
    
    # Format end time if present
    end_time = attack.get('EndTime')
    if isinstance(end_time, datetime):
        end_time = end_time.isoformat()
    
    # Extract resource information
    resource_arn = attack.get('ResourceArn', '')
    resource_info = parse_resource_arn(resource_arn)
    
    # Format attack vectors
    attack_vectors = []
    for vector in attack.get('AttackVectors', []):
        attack_vectors.append({
            "vector_type": vector.get('VectorType', 'Unknown'),
            "vector_counters": vector.get('VectorCounters', [])
        })
    
    # Format mitigations
    mitigations = []
    for mitigation in attack.get('Mitigations', []):
        mitigations.append({
            "mitigation_name": mitigation.get('MitigationName', 'Unknown')
        })
    
    return {
        "id": attack.get('Id', 'Unknown'),
        "resource_arn": resource_arn,
        "resource": resource_info,
        "sub_resources": attack.get('SubResources', []),
        "start_time": start_time,
        "end_time": end_time,
        "attack_vectors": attack_vectors,
        "attack_vectors_count": len(attack_vectors),
        "mitigations": mitigations,
        "mitigations_count": len(mitigations)
    }


def format_shield_attack_summary_json(attack: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Shield attack summary into structured data for JSON output.
    
    Args:
        attack: Shield attack summary data dictionary
        
    Returns:
        Dictionary with formatted Shield attack summary data
    """
    # Format start time
    start_time = attack.get('StartTime')
    if isinstance(start_time, datetime):
        start_time = start_time.isoformat()
    
    # Format end time if present
    end_time = attack.get('EndTime')
    if isinstance(end_time, datetime):
        end_time = end_time.isoformat()
    
    # Extract resource information
    resource_arn = attack.get('ResourceArn', '')
    resource_info = parse_resource_arn(resource_arn)
    
    # Determine attack status
    attack_status = 'Stopped' if end_time else 'In Progress'
    
    return {
        "id": attack.get('AttackId', 'Unknown'),
        "resource_arn": resource_arn,
        "resource_type": resource_info.get('service'),
        "resource_id": resource_info.get('resource_id'),
        "start_time": start_time,
        "end_time": end_time,
        "attack_vectors": attack.get('AttackVectors', []),
        "attack_status": attack_status
    }


def format_shield_drt_access_json(drt_access: Dict[str, Any]) -> Dict[str, Any]:
    """Format Shield DRT access information into structured data for JSON output.
    
    Args:
        drt_access: Shield DRT access data dictionary
        
    Returns:
        Dictionary with formatted Shield DRT access data
    """
    has_role_access = bool(drt_access.get('role_arn'))
    has_log_access = bool(drt_access.get('log_bucket_list'))
    
    return {
        "drt_role_arn": drt_access.get('role_arn'),
        "drt_has_role_access": has_role_access,
        "drt_log_buckets": drt_access.get('log_bucket_list', []),
        "drt_has_log_access": has_log_access,
        "drt_access_configured": has_role_access or has_log_access
    }


def format_shield_emergency_contacts_json(contacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format Shield emergency contacts into structured data for JSON output.
    
    Args:
        contacts: List of Shield emergency contact dictionaries
        
    Returns:
        Dictionary with formatted Shield emergency contacts data
    """
    formatted_contacts = []
    for contact in contacts:
        formatted_contacts.append({
            "email_address": contact.get('EmailAddress', 'Unknown'),
            "phone_number": contact.get('PhoneNumber')
        })
    
    return {
        "has_emergency_contacts": len(formatted_contacts) > 0,
        "contacts_count": len(formatted_contacts),
        "contacts": formatted_contacts
    }


def parse_resource_arn(arn: str) -> Dict[str, str]:
    """Parse an AWS ARN to extract resource information.
    
    Args:
        arn: The AWS ARN to parse
        
    Returns:
        Dictionary with extracted resource information
    """
    if not arn:
        return {
            "service": "unknown",
            "region": "unknown",
            "account_id": "unknown",
            "resource_type": "unknown",
            "resource_id": "unknown"
        }
    
    # Split ARN into components
    arn_parts = arn.split(':')
    
    # Extract basic information
    service = arn_parts[2] if len(arn_parts) > 2 else 'unknown'
    region = arn_parts[3] if len(arn_parts) > 3 else 'unknown'
    account_id = arn_parts[4] if len(arn_parts) > 4 else 'unknown'
    
    # Extract resource information
    resource_path = arn_parts[5] if len(arn_parts) > 5 else ''
    resource_parts = resource_path.split('/')
    
    resource_type = resource_parts[0] if resource_parts else 'unknown'
    resource_id = '/'.join(resource_parts[1:]) if len(resource_parts) > 1 else resource_parts[0]
    
    return {
        "service": service,
        "region": region,
        "account_id": account_id,
        "resource_type": resource_type,
        "resource_id": resource_id
    } 