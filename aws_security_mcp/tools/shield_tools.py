"""Tools for working with AWS Shield.

This module provides tools for retrieving and analyzing AWS Shield Advanced resources,
including protected resources, protections, and attack information.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone

from aws_security_mcp.formatters.shield import (
    format_shield_subscription_json,
    format_shield_protection_json,
    format_shield_protected_resource_json,
    format_shield_attack_json,
    format_shield_attack_summary_json,
    format_shield_drt_access_json,
    format_shield_emergency_contacts_json
)
from aws_security_mcp.services.shield import ShieldService
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
async def get_shield_subscription_status() -> Dict[str, Any]:
    """Get the status of AWS Shield Advanced subscription.
    
    Returns:
        JSON object with subscription information
    """
    logger.info("Getting Shield Advanced subscription status")
    
    shield_service = ShieldService()
    
    try:
        subscription = await shield_service.get_subscription_state()
        return format_shield_subscription_json(subscription)
    except Exception as e:
        logger.error(f"Error getting Shield subscription status: {e}")
        return {
            "error": True,
            "message": f"Error retrieving Shield subscription status: {str(e)}",
            "has_subscription": False
        }


@register_tool()
async def list_shield_protected_resources(
    limit: int = 100,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List resources protected by AWS Shield Advanced.
    
    Args:
        limit: Maximum number of protected resources to return
        next_token: Pagination token for fetching the next set of resources
        
    Returns:
        JSON object with protected resource information
    """
    logger.info(f"Listing Shield protected resources with limit: {limit}")
    
    shield_service = ShieldService()
    
    try:
        response = await shield_service.list_protected_resources(max_items=limit, next_token=next_token)
        resources = response['protected_resources']
        
        # Format the results
        formatted_resources = [format_shield_protected_resource_json(resource) for resource in resources]
        
        # Group resources by type for easier analysis
        resource_types = {}
        for resource in formatted_resources:
            resource_type = resource['resource_type']
            if resource_type not in resource_types:
                resource_types[resource_type] = []
            resource_types[resource_type].append(resource)
        
        result = {
            "total_protected_resources": len(formatted_resources),
            "protected_resources": formatted_resources,
            "resource_types": resource_types,
            "resource_type_counts": {k: len(v) for k, v in resource_types.items()},
            "pagination": {
                "has_more": response['has_more'],
                "next_token": response['next_token']
            }
        }
        
        return result
    except Exception as e:
        logger.error(f"Error listing Shield protected resources: {e}")
        return {
            "error": True,
            "message": f"Error listing Shield protected resources: {str(e)}",
            "total_protected_resources": 0,
            "protected_resources": []
        }


@register_tool()
async def list_shield_protections(
    limit: int = 100,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List protections configured in AWS Shield Advanced.
    
    Args:
        limit: Maximum number of protections to return
        next_token: Pagination token for fetching the next set of protections
        
    Returns:
        JSON object with protection information
    """
    logger.info(f"Listing Shield protections with limit: {limit}")
    
    shield_service = ShieldService()
    
    try:
        response = await shield_service.list_protections(max_items=limit, next_token=next_token)
        protections = response['protections']
        
        # Format the results
        formatted_protections = [format_shield_protection_json(protection) for protection in protections]
        
        result = {
            "total_protections": len(formatted_protections),
            "protections": formatted_protections,
            "pagination": {
                "has_more": response['has_more'],
                "next_token": response['next_token']
            }
        }
        
        return result
    except Exception as e:
        logger.error(f"Error listing Shield protections: {e}")
        return {
            "error": True,
            "message": f"Error listing Shield protections: {str(e)}",
            "total_protections": 0,
            "protections": []
        }


@register_tool()
async def get_shield_protection_details(resource_arn: str) -> Dict[str, Any]:
    """Get detailed protection information for a specific resource in AWS Shield Advanced.
    
    Args:
        resource_arn: ARN of the resource to get protection details for
        
    Returns:
        JSON object with detailed protection information
    """
    logger.info(f"Getting Shield protection details for resource: {resource_arn}")
    
    shield_service = ShieldService()
    
    try:
        protection = await shield_service.get_protection_details(resource_arn=resource_arn)
        
        if not protection:
            return {
                "is_protected": False,
                "resource_arn": resource_arn,
                "message": "Resource is not protected by Shield Advanced"
            }
        
        return {
            "is_protected": True,
            **format_shield_protection_json(protection)
        }
    except Exception as e:
        logger.error(f"Error getting Shield protection details: {e}")
        return {
            "error": True,
            "message": f"Error retrieving Shield protection details: {str(e)}",
            "resource_arn": resource_arn
        }


@register_tool()
async def list_shield_attacks(
    days: int = 30,
    limit: int = 100,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List DDoS attacks detected by AWS Shield Advanced.
    
    Args:
        days: Number of days to look back for attacks
        limit: Maximum number of attacks to return
        next_token: Pagination token for fetching the next set of attacks
        
    Returns:
        JSON object with attack information
    """
    logger.info(f"Listing Shield attacks for the last {days} days with limit: {limit}")
    
    shield_service = ShieldService()
    
    try:
        # Calculate start and end times for the attack listing
        end_time = datetime.now(timezone.utc)
        start_time = end_time.replace(hour=0, minute=0, second=0, microsecond=0) - timezone.timedelta(days=days)
        
        time_range = {
            'FromInclusive': start_time,
            'ToExclusive': end_time
        }
        
        response = await shield_service.list_attacks(
            start_time=time_range,
            max_items=limit,
            next_token=next_token
        )
        attacks = response['attacks']
        
        # Format the results
        formatted_attacks = [format_shield_attack_summary_json(attack) for attack in attacks]
        
        # Count attacks by resource type
        attack_counts_by_resource = {}
        for attack in formatted_attacks:
            resource_type = attack['resource_type']
            if resource_type not in attack_counts_by_resource:
                attack_counts_by_resource[resource_type] = 0
            attack_counts_by_resource[resource_type] += 1
        
        # Count ongoing attacks
        ongoing_attacks = [a for a in formatted_attacks if a['attack_status'] == 'In Progress']
        
        result = {
            "total_attacks": len(formatted_attacks),
            "ongoing_attacks": len(ongoing_attacks),
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "days": days
            },
            "attacks": formatted_attacks,
            "attack_counts_by_resource": attack_counts_by_resource,
            "pagination": {
                "has_more": response['has_more'],
                "next_token": response['next_token']
            }
        }
        
        return result
    except Exception as e:
        logger.error(f"Error listing Shield attacks: {e}")
        return {
            "error": True,
            "message": f"Error listing Shield attacks: {str(e)}",
            "total_attacks": 0,
            "attacks": []
        }


@register_tool()
async def get_shield_attack_details(attack_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific DDoS attack detected by AWS Shield Advanced.
    
    Args:
        attack_id: ID of the attack to get details for
        
    Returns:
        JSON object with detailed attack information
    """
    logger.info(f"Getting Shield attack details for attack ID: {attack_id}")
    
    shield_service = ShieldService()
    
    try:
        attack = await shield_service.get_attack_details(attack_id=attack_id)
        return format_shield_attack_json(attack)
    except Exception as e:
        logger.error(f"Error getting Shield attack details: {e}")
        return {
            "error": True,
            "message": f"Error retrieving Shield attack details: {str(e)}",
            "attack_id": attack_id
        }


@register_tool()
async def get_shield_drt_access_status() -> Dict[str, Any]:
    """Get the status of DDoS Response Team (DRT) access in AWS Shield Advanced.
    
    Returns:
        JSON object with DRT access information
    """
    logger.info("Getting Shield DRT access status")
    
    shield_service = ShieldService()
    
    try:
        drt_access = await shield_service.get_drt_access()
        return format_shield_drt_access_json(drt_access)
    except Exception as e:
        logger.error(f"Error getting Shield DRT access status: {e}")
        return {
            "error": True,
            "message": f"Error retrieving Shield DRT access status: {str(e)}",
            "drt_access_configured": False
        }


@register_tool()
async def get_shield_emergency_contacts() -> Dict[str, Any]:
    """Get the emergency contacts configured for AWS Shield Advanced.
    
    Returns:
        JSON object with emergency contact information
    """
    logger.info("Getting Shield emergency contacts")
    
    shield_service = ShieldService()
    
    try:
        contacts = await shield_service.describe_emergency_contact_list()
        return format_shield_emergency_contacts_json(contacts)
    except Exception as e:
        logger.error(f"Error getting Shield emergency contacts: {e}")
        return {
            "error": True,
            "message": f"Error retrieving Shield emergency contacts: {str(e)}",
            "has_emergency_contacts": False,
            "contacts": []
        }


@register_tool()
async def get_shield_summary() -> Dict[str, Any]:
    """Get a comprehensive summary of AWS Shield Advanced status and configuration.
    
    Returns:
        JSON object with Shield Advanced summary information
    """
    logger.info("Getting Shield Advanced summary")
    
    shield_service = ShieldService()
    
    try:
        # Get subscription status
        subscription = await shield_service.get_subscription_state()
        subscription_status = format_shield_subscription_json(subscription)
        
        # Early exit if no subscription
        if not subscription_status.get('has_subscription'):
            return {
                "has_subscription": False,
                "message": "AWS Shield Advanced subscription not found"
            }
        
        # Get protected resources (limit to 100 for summary)
        protected_resources_response = await shield_service.list_protected_resources(max_items=100)
        protected_resources = protected_resources_response['protected_resources']
        formatted_resources = [format_shield_protected_resource_json(resource) for resource in protected_resources]
        
        # Group resources by type
        resource_types = {}
        for resource in formatted_resources:
            resource_type = resource['resource_type']
            if resource_type not in resource_types:
                resource_types[resource_type] = 0
            resource_types[resource_type] += 1
        
        # Get recent attacks (last 7 days)
        end_time = datetime.now(timezone.utc)
        start_time = end_time.replace(hour=0, minute=0, second=0, microsecond=0) - timezone.timedelta(days=7)
        
        time_range = {
            'FromInclusive': start_time,
            'ToExclusive': end_time
        }
        
        attacks_response = await shield_service.list_attacks(start_time=time_range, max_items=100)
        attacks = attacks_response['attacks']
        formatted_attacks = [format_shield_attack_summary_json(attack) for attack in attacks]
        
        # Get ongoing attacks
        ongoing_attacks = [a for a in formatted_attacks if a['attack_status'] == 'In Progress']
        
        # Get DRT access status
        drt_access = await shield_service.get_drt_access()
        drt_status = format_shield_drt_access_json(drt_access)
        
        # Get emergency contacts
        contacts = await shield_service.describe_emergency_contact_list()
        contact_info = format_shield_emergency_contacts_json(contacts)
        
        # Assemble summary
        return {
            "subscription": subscription_status,
            "protected_resources": {
                "total": len(formatted_resources),
                "by_type": resource_types,
                "has_more": protected_resources_response['has_more']
            },
            "recent_attacks": {
                "total": len(formatted_attacks),
                "ongoing": len(ongoing_attacks),
                "time_period_days": 7,
                "has_more": attacks_response['has_more']
            },
            "drt_access": drt_status,
            "emergency_contacts": contact_info
        }
    except Exception as e:
        logger.error(f"Error getting Shield summary: {e}")
        return {
            "error": True,
            "message": f"Error retrieving Shield summary: {str(e)}"
        } 