"""Route53 service client for AWS Security MCP."""

import logging
from typing import Dict, List, Optional, Any

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger(__name__)


def get_route53_client():
    """Get a boto3 Route53 client."""
    return boto3.client('route53')


def list_hosted_zones(max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
    """List Route53 hosted zones with pagination support.
    
    Args:
        max_items: Maximum number of hosted zones to return
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing hosted zones and pagination information
        {
            "zones": [...],         # List of hosted zone dictionaries
            "next_token": "string", # Token for next page or None if no more pages
            "is_truncated": bool    # Whether there are more items
        }
    """
    client = get_route53_client()
    hosted_zones = []
    
    try:
        paginator = client.get_paginator('list_hosted_zones')
        pagination_config = {'MaxItems': str(max_items)}
        
        if next_token:
            pagination_config['Marker'] = next_token
            
        iterator = paginator.paginate(**pagination_config)
        
        # Process pages
        for page in iterator:
            zones = page.get('HostedZones', [])
            hosted_zones.extend(zones)
            
            # Check if we have the next marker
            is_truncated = page.get('IsTruncated', False)
            next_marker = page.get('NextMarker')
            
            # Return with pagination info when we have enough items or reached the end
            if len(hosted_zones) >= max_items or not is_truncated:
                return {
                    "zones": hosted_zones[:max_items],
                    "next_token": next_marker,
                    "is_truncated": is_truncated
                }
        
        # If we get here, we've processed all pages
        return {
            "zones": hosted_zones[:max_items],
            "next_token": None,
            "is_truncated": False
        }
    except ClientError as e:
        logger.error(f"Error listing Route53 hosted zones: {e}")
        return {
            "zones": [],
            "next_token": None,
            "is_truncated": False
        }


def get_hosted_zone(zone_id: str) -> Dict:
    """Get details for a specific Route53 hosted zone.
    
    Args:
        zone_id: The ID of the hosted zone
        
    Returns:
        Hosted zone details dictionary
    """
    client = get_route53_client()
    
    try:
        response = client.get_hosted_zone(Id=zone_id)
        return response
    except ClientError as e:
        logger.error(f"Error getting Route53 hosted zone {zone_id}: {e}")
        return {}


def get_hosted_zone_tags(zone_id: str) -> Dict[str, str]:
    """Get tags for a specific Route53 hosted zone.
    
    Args:
        zone_id: The ID of the hosted zone
        
    Returns:
        Dictionary of tag key-value pairs
    """
    client = get_route53_client()
    tags = {}
    
    try:
        response = client.list_tags_for_resource(
            ResourceType='hostedzone',
            ResourceId=zone_id.replace('/hostedzone/', '')
        )
        tag_list = response.get('ResourceTagSet', {}).get('Tags', [])
        
        for tag in tag_list:
            key = tag.get('Key')
            value = tag.get('Value')
            if key and value:
                tags[key] = value
        
        return tags
    except ClientError as e:
        logger.error(f"Error getting Route53 hosted zone tags {zone_id}: {e}")
        return {}


def list_resource_record_sets(zone_id: str, max_items: int = 100, next_marker: Optional[str] = None) -> Dict[str, Any]:
    """List resource record sets for a specific Route53 hosted zone with pagination support.
    
    Args:
        zone_id: The ID of the hosted zone
        max_items: Maximum number of record sets to return
        next_marker: Marker for pagination (Name and Type of the resource record set that starts the next page)
        
    Returns:
        Dictionary containing resource record sets and pagination information
        {
            "records": [...],        # List of record set dictionaries
            "next_marker": "string", # Token for next page or None if no more pages
            "is_truncated": bool     # Whether there are more items
        }
    """
    client = get_route53_client()
    record_sets = []
    
    try:
        params = {
            'HostedZoneId': zone_id,
            'MaxItems': str(max_items)
        }
        
        if next_marker:
            parts = next_marker.split('|')
            if len(parts) == 2:
                params['StartRecordName'] = parts[0]
                params['StartRecordType'] = parts[1]
        
        response = client.list_resource_record_sets(**params)
        records = response.get('ResourceRecordSets', [])
        record_sets.extend(records)
        
        # Determine if there are more records and create a marker
        next_record_marker = None
        is_truncated = response.get('IsTruncated', False)
        
        if is_truncated:
            next_record_name = response.get('NextRecordName')
            next_record_type = response.get('NextRecordType')
            
            if next_record_name and next_record_type:
                next_record_marker = f"{next_record_name}|{next_record_type}"
        
        return {
            'records': record_sets,
            'next_marker': next_record_marker,
            'is_truncated': is_truncated
        }
    except ClientError as e:
        logger.error(f"Error listing Route53 resource record sets for {zone_id}: {e}")
        return {
            'records': [],
            'next_marker': None,
            'is_truncated': False
        }


def list_health_checks(max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
    """List Route53 health checks with pagination support.
    
    Args:
        max_items: Maximum number of health checks to return
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing health checks and pagination information
        {
            "health_checks": [...],  # List of health check dictionaries
            "next_token": "string",  # Token for next page or None if no more pages
            "is_truncated": bool     # Whether there are more items
        }
    """
    client = get_route53_client()
    health_checks = []
    
    try:
        paginator = client.get_paginator('list_health_checks')
        pagination_config = {'MaxItems': str(max_items)}
        
        if next_token:
            pagination_config['Marker'] = next_token
            
        iterator = paginator.paginate(**pagination_config)
        
        # Process pages
        for page in iterator:
            checks = page.get('HealthChecks', [])
            health_checks.extend(checks)
            
            # Check if we have the next marker
            is_truncated = page.get('IsTruncated', False)
            next_marker = page.get('Marker') if is_truncated else None
            
            # Return with pagination info when we have enough items or reached the end
            if len(health_checks) >= max_items or not is_truncated:
                return {
                    "health_checks": health_checks[:max_items],
                    "next_token": next_marker,
                    "is_truncated": is_truncated
                }
        
        # If we get here, we've processed all pages
        return {
            "health_checks": health_checks[:max_items],
            "next_token": None,
            "is_truncated": False
        }
    except ClientError as e:
        logger.error(f"Error listing Route53 health checks: {e}")
        return {
            "health_checks": [],
            "next_token": None,
            "is_truncated": False
        }


def get_health_check(health_check_id: str) -> Dict:
    """Get details for a specific Route53 health check.
    
    Args:
        health_check_id: The ID of the health check
        
    Returns:
        Health check details dictionary
    """
    client = get_route53_client()
    
    try:
        response = client.get_health_check(HealthCheckId=health_check_id)
        return response.get('HealthCheck', {})
    except ClientError as e:
        logger.error(f"Error getting Route53 health check {health_check_id}: {e}")
        return {}


def list_traffic_policies(max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
    """List Route53 traffic policies with pagination support.
    
    Args:
        max_items: Maximum number of traffic policies to return
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing traffic policies and pagination information
        {
            "policies": [...],       # List of traffic policy dictionaries
            "next_token": "string",  # Token for next page or None if no more pages
            "is_truncated": bool     # Whether there are more items
        }
    """
    client = get_route53_client()
    traffic_policies = []
    
    try:
        params = {
            'MaxItems': str(max_items)
        }
        
        if next_token:
            params['TrafficPolicyIdMarker'] = next_token
            
        response = client.list_traffic_policies(**params)
        policies = response.get('TrafficPolicySummaries', [])
        traffic_policies.extend(policies)
        
        # Determine if there are more policies and create a marker
        is_truncated = response.get('IsTruncated', False)
        next_policy_marker = response.get('TrafficPolicyIdMarker') if is_truncated else None
        
        return {
            'policies': traffic_policies,
            'next_token': next_policy_marker,
            'is_truncated': is_truncated
        }
    except ClientError as e:
        logger.error(f"Error listing Route53 traffic policies: {e}")
        return {
            'policies': [],
            'next_token': None,
            'is_truncated': False
        }


def get_traffic_policy(policy_id: str, version: int) -> Dict:
    """Get details for a specific Route53 traffic policy.
    
    Args:
        policy_id: The ID of the traffic policy
        version: The version of the traffic policy
        
    Returns:
        Traffic policy details dictionary
    """
    client = get_route53_client()
    
    try:
        response = client.get_traffic_policy(Id=policy_id, Version=version)
        return response.get('TrafficPolicy', {})
    except ClientError as e:
        logger.error(f"Error getting Route53 traffic policy {policy_id} version {version}: {e}")
        return {}


def list_traffic_policy_instances(max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
    """List Route53 traffic policy instances with pagination support.
    
    Args:
        max_items: Maximum number of traffic policy instances to return
        next_token: Pagination token from previous request
        
    Returns:
        Dictionary containing traffic policy instances and pagination information
        {
            "instances": [...],      # List of traffic policy instance dictionaries
            "next_token": "string",  # Token for next page or None if no more pages
            "is_truncated": bool     # Whether there are more items
        }
    """
    client = get_route53_client()
    instances = []
    
    try:
        params = {
            'MaxItems': str(max_items)
        }
        
        if next_token:
            params['TrafficPolicyInstanceNameMarker'] = next_token.split('|')[0]
            params['TrafficPolicyInstanceTypeMarker'] = next_token.split('|')[1]
            
        response = client.list_traffic_policy_instances(**params)
        policy_instances = response.get('TrafficPolicyInstances', [])
        instances.extend(policy_instances)
        
        # Determine if there are more instances and create a marker
        is_truncated = response.get('IsTruncated', False)
        next_marker = None
        
        if is_truncated:
            next_name = response.get('TrafficPolicyInstanceNameMarker')
            next_type = response.get('TrafficPolicyInstanceTypeMarker')
            
            if next_name and next_type:
                next_marker = f"{next_name}|{next_type}"
        
        return {
            'instances': instances,
            'next_token': next_marker,
            'is_truncated': is_truncated
        }
    except ClientError as e:
        logger.error(f"Error listing Route53 traffic policy instances: {e}")
        return {
            'instances': [],
            'next_token': None,
            'is_truncated': False
        } 