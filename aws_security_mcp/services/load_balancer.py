"""AWS Elastic Load Balancing service functions.

This module provides direct interaction with AWS ELB services using boto3.
Implements functions for both Classic Load Balancers (ELB) and v2 Load Balancers
(ALB, NLB, GWLB) with proper pagination support.
"""

import logging
from typing import Any, Dict, List, Optional, Union

import boto3
from botocore.exceptions import ClientError

# Import the base service utilities
from aws_security_mcp.services.base import get_client

# Configure logging
logger = logging.getLogger(__name__)


def get_all_classic_load_balancers(
    names: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get Classic Load Balancers (ELB) with optional filtering by name.
    
    Args:
        names: Optional list of load balancer names to filter by
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with load balancers and pagination details
    """
    client = get_client('elb', session_context=session_context)
    params = {}
    
    if names:
        params['LoadBalancerNames'] = names
    
    if next_token:
        params['Marker'] = next_token
    
    # Note: Classic ELB API doesn't use MaxItems, but PageSize
    if max_items:
        params['PageSize'] = max_items
    
    try:
        response = client.describe_load_balancers(**params)
        return {
            "load_balancers": response.get('LoadBalancerDescriptions', []),
            "next_token": response.get('NextMarker')
        }
    except ClientError as e:
        logger.error(f"Error getting Classic Load Balancers: {e}")
        return {
            "load_balancers": [],
            "next_token": None
        }


def get_all_load_balancers_v2(
    load_balancer_type: Optional[str] = None,
    names: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get ELBv2 Load Balancers (ALB, NLB, GWLB) with optional filtering.
    
    Args:
        load_balancer_type: Optional type filter ('application', 'network', or 'gateway')
        names: Optional list of load balancer names to filter by
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with load balancers and pagination details
    """
    client = get_client('elbv2', session_context=session_context)
    params = {}
    
    # Build the filter
    if load_balancer_type or names:
        params['Names'] = names or []
    
    if next_token:
        params['Marker'] = next_token
        
    if max_items:
        params['PageSize'] = max_items
    
    try:
        response = client.describe_load_balancers(**params)
        
        # Filter by type if specified
        load_balancers = response.get('LoadBalancers', [])
        if load_balancer_type:
            load_balancers = [
                lb for lb in load_balancers 
                if lb.get('Type', '').lower() == load_balancer_type.lower()
            ]
        
        return {
            "load_balancers": load_balancers,
            "next_token": response.get('NextMarker')
        }
    except ClientError as e:
        logger.error(f"Error getting ELBv2 Load Balancers: {e}")
        return {
            "load_balancers": [],
            "next_token": None
        }


def get_all_application_load_balancers(
    names: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get Application Load Balancers (ALB) with optional filtering by name.
    
    Args:
        names: Optional list of load balancer names to filter by
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with Application Load Balancers and pagination details
    """
    return get_all_load_balancers_v2(
        load_balancer_type='application',
        names=names,
        next_token=next_token,
        max_items=max_items,
        session_context=session_context
    )


def get_all_network_load_balancers(
    names: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get Network Load Balancers (NLB) with optional filtering by name.
    
    Args:
        names: Optional list of load balancer names to filter by
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with Network Load Balancers and pagination details
    """
    return get_all_load_balancers_v2(
        load_balancer_type='network',
        names=names,
        next_token=next_token,
        max_items=max_items,
        session_context=session_context
    )


def get_all_gateway_load_balancers(
    names: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get Gateway Load Balancers (GWLB) with optional filtering by name.
    
    Args:
        names: Optional list of load balancer names to filter by
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with Gateway Load Balancers and pagination details
    """
    return get_all_load_balancers_v2(
        load_balancer_type='gateway',
        names=names,
        next_token=next_token,
        max_items=max_items,
        session_context=session_context
    )


def describe_instance_health(
    load_balancer_name: str,
    instance_ids: Optional[List[str]] = None,
    session_context: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Describe the health of instances for a Classic Load Balancer.
    
    Args:
        load_balancer_name: Name of the Classic Load Balancer
        instance_ids: Optional list of instance IDs to filter by
        session_context: Optional session key for cross-account access
        
    Returns:
        List of instance health information
    """
    client = get_client('elb', session_context=session_context)
    params = {
        'LoadBalancerName': load_balancer_name
    }
    
    if instance_ids:
        params['Instances'] = [{'InstanceId': instance_id} for instance_id in instance_ids]
    
    try:
        response = client.describe_instance_health(**params)
        return response.get('InstanceStates', [])
    except ClientError as e:
        logger.error(f"Error describing instance health: {e}")
        return []


def get_all_target_groups(
    load_balancer_arn: Optional[str] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get target groups with optional filtering by load balancer ARN.
    
    Args:
        load_balancer_arn: Optional load balancer ARN to filter by
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with target groups and pagination details
    """
    client = get_client('elbv2', session_context=session_context)
    params = {}
        
    if load_balancer_arn:
        params['LoadBalancerArn'] = load_balancer_arn
        
    if next_token:
        params['Marker'] = next_token
    
    if max_items:
        params['PageSize'] = max_items
    
    try:
        response = client.describe_target_groups(**params)
        return {
            "target_groups": response.get('TargetGroups', []),
            "next_token": response.get('NextMarker')
        }
    except ClientError as e:
        logger.error(f"Error getting target groups: {e}")
        return {
            "target_groups": [],
            "next_token": None
        }


def describe_target_health(
    target_group_arn: str,
    targets: Optional[List[Dict[str, str]]] = None,
    session_context: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Describe the health of targets in a target group.
    
    Args:
        target_group_arn: ARN of the target group
        targets: Optional list of targets to describe (format: [{"id": "i-1234", "port": 80}])
        session_context: Optional session key for cross-account access
        
    Returns:
        List of target health descriptions
    """
    client = get_client('elbv2', session_context=session_context)
    params = {
        'TargetGroupArn': target_group_arn
    }
    
    if targets:
        # Convert to expected format
        formatted_targets = []
        for target in targets:
            formatted_target = {}
            if 'id' in target:
                formatted_target['Id'] = target['id']
            if 'port' in target:
                formatted_target['Port'] = int(target['port'])
            formatted_targets.append(formatted_target)
        
        params['Targets'] = formatted_targets
    
    try:
        response = client.describe_target_health(**params)
        return response.get('TargetHealthDescriptions', [])
    except ClientError as e:
        logger.error(f"Error describing target health: {e}")
        return []


def get_all_listeners(
    load_balancer_arn: str,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get listeners for a load balancer.
    
    Args:
        load_balancer_arn: ARN of the load balancer
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with listeners and pagination details
    """
    client = get_client('elbv2', session_context=session_context)
    
    # Validate the load_balancer_arn
    if not load_balancer_arn or not isinstance(load_balancer_arn, str):
        logger.error(f"Invalid load_balancer_arn: {load_balancer_arn}")
        return {
            "listeners": [],
            "next_token": None,
            "error": "Load balancer ARN is required and must be a string"
        }
    
    # Use the paginator for better pagination support
    paginator = client.get_paginator('describe_listeners')
    
    pagination_config = {
        'MaxItems': max_items,
        'PageSize': min(max_items, 100)  # AWS API page size limit
    }
    
    if next_token:
        pagination_config['StartingToken'] = next_token
    
    try:
        page_iterator = paginator.paginate(
            LoadBalancerArn=load_balancer_arn,
            PaginationConfig=pagination_config
        )
        
        # Process the paginated results
        listeners = []
        response_next_token = None
        
        for page in page_iterator:
            listeners.extend(page.get('Listeners', []))
            # If we've reached max_items, we can stop and return the next token
            if len(listeners) >= max_items:
                response_next_token = page_iterator.resume_token
                listeners = listeners[:max_items]
                break
        
        return {
            "listeners": listeners,
            "next_token": response_next_token
        }
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"AWS ClientError in get_all_listeners: {error_code} - {error_message}")
        
        # Provide more specific error information based on error code
        if error_code == 'LoadBalancerNotFound':
            error_info = f"Load balancer not found with ARN: {load_balancer_arn}"
        elif error_code == 'ValidationError':
            error_info = f"Validation error: {error_message}"
        else:
            error_info = error_message
            
        return {
            "listeners": [],
            "next_token": None,
            "error": error_info,
            "error_code": error_code
        }
    except Exception as e:
        logger.error(f"Unexpected error in get_all_listeners: {e}")
        return {
            "listeners": [],
            "next_token": None,
            "error": str(e)
        }


def get_all_rules(
    listener_arn: str,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get rules for a listener.
    
    Args:
        listener_arn: ARN of the listener
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with rules and pagination details
    """
    client = get_client('elbv2', session_context=session_context)
    
    # Use the paginator for better pagination support
    paginator = client.get_paginator('describe_rules')
    
    pagination_config = {
        'MaxItems': max_items,
        'PageSize': min(max_items, 100)  # AWS API page size limit
    }
    
    if next_token:
        pagination_config['StartingToken'] = next_token
    
    try:
        page_iterator = paginator.paginate(
            ListenerArn=listener_arn,
            PaginationConfig=pagination_config
        )
        
        # Process the paginated results
        rules = []
        response_next_token = None
        
        for page in page_iterator:
            rules.extend(page.get('Rules', []))
            # If we've reached max_items, we can stop and return the next token
            if len(rules) >= max_items:
                response_next_token = page_iterator.resume_token
                rules = rules[:max_items]
                break
        
        return {
            "rules": rules,
            "next_token": response_next_token
        }
    except ClientError as e:
        logger.error(f"Error getting rules: {e}")
        return {
            "rules": [],
            "next_token": None
        }


def search_load_balancer(identifier: str, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Search for a load balancer by ARN, name, or DNS name.
    
    Args:
        identifier: ARN, name, or DNS name of the load balancer
        session_context: Optional session key for cross-account access
        
    Returns:
        Load balancer information if found, None otherwise
    """
    # First try to search by ARN in elbv2
    if identifier.startswith('arn:aws:elasticloadbalancing:'):
        # Determine if it's a Classic ELB or ELBv2 based on ARN format
        if ':loadbalancer/app/' in identifier or ':loadbalancer/net/' in identifier or ':loadbalancer/gwy/' in identifier:
            # ELBv2 (ALB, NLB, GWLB)
            client = get_client('elbv2', session_context=session_context)
            try:
                response = client.describe_load_balancers(LoadBalancerArns=[identifier])
                if response.get('LoadBalancers'):
                    return response['LoadBalancers'][0]
            except ClientError as e:
                logger.error(f"Error searching for ELBv2 load balancer by ARN: {e}")
                # Continue to classic ELB search
        
        # Classic ELB
        client = get_client('elb', session_context=session_context)
        # For Classic ELB, we need to extract the name from the ARN
        # Format: arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
        try:
            lb_name = identifier.split('/')[-1]
            response = client.describe_load_balancers(LoadBalancerNames=[lb_name])
            if response.get('LoadBalancerDescriptions'):
                return response['LoadBalancerDescriptions'][0]
        except ClientError as e:
            logger.error(f"Error searching for Classic load balancer by ARN: {e}")
    
    # If not found by ARN or not an ARN, try by name/DNS in elbv2 first
    elbv2_client = get_client('elbv2', session_context=session_context)
    try:
        # Try searching by name in ELBv2
        response = elbv2_client.describe_load_balancers(Names=[identifier])
        if response.get('LoadBalancers'):
            return response['LoadBalancers'][0]
    except ClientError as e:
        # If it's not an error related to not finding the load balancer, log it
        if 'LoadBalancerNotFound' not in str(e):
            logger.error(f"Error searching for ELBv2 load balancer by name: {e}")
    
    # Try to find by DNS name in ELBv2
    try:
        # Get all ELBv2 load balancers and check DNS names
        response = elbv2_client.describe_load_balancers()
        for lb in response.get('LoadBalancers', []):
            if lb.get('DNSName') == identifier:
                return lb
        
        # Check if we need to paginate through results
        next_marker = response.get('NextMarker')
        while next_marker:
            response = elbv2_client.describe_load_balancers(Marker=next_marker)
            for lb in response.get('LoadBalancers', []):
                if lb.get('DNSName') == identifier:
                    return lb
            next_marker = response.get('NextMarker')
    except ClientError as e:
        logger.error(f"Error searching for ELBv2 load balancer by DNS name: {e}")
    
    # Finally, try Classic ELB by name if not found in ELBv2
    elb_client = get_client('elb', session_context=session_context)
    try:
        response = elb_client.describe_load_balancers(LoadBalancerNames=[identifier])
        if response.get('LoadBalancerDescriptions'):
            return response['LoadBalancerDescriptions'][0]
    except ClientError as e:
        # Only log actual errors, not "not found" errors
        if 'LoadBalancerNotFound' not in str(e):
            logger.error(f"Error searching for Classic load balancer by name: {e}")
    
    # Try to find by DNS name in Classic ELB
    try:
        # Get all Classic load balancers and check DNS names
        response = elb_client.describe_load_balancers()
        for lb in response.get('LoadBalancerDescriptions', []):
            if lb.get('DNSName') == identifier:
                return lb
        
        # Check if we need to paginate through results
        next_marker = response.get('NextMarker')
        while next_marker:
            response = elb_client.describe_load_balancers(Marker=next_marker)
            for lb in response.get('LoadBalancerDescriptions', []):
                if lb.get('DNSName') == identifier:
                    return lb
            next_marker = response.get('NextMarker')
    except ClientError as e:
        logger.error(f"Error searching for Classic load balancer by DNS name: {e}")
    
    # ULTIMATE FALLBACK: Paginate through ALL load balancers and match by name
    # This is the most expensive approach but will catch all edge cases
    logger.info(f"All targeted search methods failed for '{identifier}', performing full pagination comparison")
    
    # Try ELBv2 load balancers with full comparison
    try:
        paginator = elbv2_client.get_paginator('describe_load_balancers')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for lb in page.get('LoadBalancers', []):
                # Check for exact name match
                if lb.get('LoadBalancerName') == identifier:
                    logger.info(f"Found ELBv2 load balancer by name pagination: {lb.get('LoadBalancerName')}")
                    return lb
                
                # Check for substring in name (partial match)
                if identifier in lb.get('LoadBalancerName', ''):
                    logger.info(f"Found ELBv2 load balancer by partial name: {lb.get('LoadBalancerName')}")
                    return lb
                
                # Check for DNSName
                if identifier in lb.get('DNSName', ''):
                    logger.info(f"Found ELBv2 load balancer by partial DNS: {lb.get('DNSName')}")
                    return lb
                
                # Check ARN for substring match 
                if identifier in lb.get('LoadBalancerArn', ''):
                    logger.info(f"Found ELBv2 load balancer by partial ARN: {lb.get('LoadBalancerArn')}")
                    return lb
    except ClientError as e:
        logger.error(f"Error in ELBv2 pagination fallback: {e}")
    
    # Try Classic ELB with full comparison
    try:
        paginator = elb_client.get_paginator('describe_load_balancers')
        page_iterator = paginator.paginate()
        
        for page in page_iterator:
            for lb in page.get('LoadBalancerDescriptions', []):
                # Check for exact name match
                if lb.get('LoadBalancerName') == identifier:
                    logger.info(f"Found Classic ELB by name pagination: {lb.get('LoadBalancerName')}")
                    return lb
                
                # Check for substring in name (partial match)
                if identifier in lb.get('LoadBalancerName', ''):
                    logger.info(f"Found Classic ELB by partial name: {lb.get('LoadBalancerName')}")
                    return lb
                
                # Check for DNSName
                if identifier in lb.get('DNSName', ''):
                    logger.info(f"Found Classic ELB by partial DNS: {lb.get('DNSName')}")
                    return lb
    except ClientError as e:
        logger.error(f"Error in Classic ELB pagination fallback: {e}")
    
    # Not found after all searches including full pagination
    logger.error(f"Load balancer not found with identifier after all methods: {identifier}")
    return None


def get_load_balancers(
    load_balancer_type: Optional[str] = None,
    arns: Optional[List[str]] = None,
    names: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get load balancers with flexible filtering options.
    
    This unified function prioritizes ELBv2 before falling back to Classic ELB.
    Always returns ARNs as the primary identifier.
    
    Args:
        load_balancer_type: Optional type filter ('classic', 'application', 'network', 'gateway', or None for all)
        arns: Optional list of load balancer ARNs to filter by (preferred over names)
        names: Optional list of load balancer names to filter by (used if arns not provided)
        next_token: Token for pagination (from previous request)
        max_items: Maximum number of items to return
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with load balancers and pagination details
    """
    # Validate load_balancer_type
    if load_balancer_type and load_balancer_type not in ['classic', 'application', 'network', 'gateway']:
        logger.error(f"Invalid load_balancer_type: {load_balancer_type}")
        return {
            "load_balancers": [],
            "next_token": None,
            "error": f"Invalid load_balancer_type: {load_balancer_type}"
        }
    
    # If ARNs are provided, validate them
    if arns:
        # Validate ARN format
        invalid_arns = [arn for arn in arns if not arn.startswith('arn:aws:elasticloadbalancing:')]
        if invalid_arns:
            logger.error(f"Invalid ARN format for: {invalid_arns}")
            return {
                "load_balancers": [],
                "next_token": None,
                "error": "All ARNs must start with arn:aws:elasticloadbalancing:"
            }
        
        # For now, if ARNs are provided, we'll fetch each one individually
        # This is a simplification - a more optimized approach would be to batch ARNs by type
        load_balancers = []
        for arn in arns:
            lb = search_load_balancer(arn, session_context=session_context)
            if lb:
                # Ensure ARN is always present in the load balancer object
                if "LoadBalancerArn" not in lb and "LoadBalancerName" in lb:
                    # This is a Classic ELB, create an ARN field for consistency
                    sts_client = get_client('sts', session_context=session_context)
                    account_id = sts_client.get_caller_identity()['Account']
                    region = lb.get('AvailabilityZones', [{}])[0].get('ZoneName', '')[:10] if lb.get('AvailabilityZones') else 'us-east-1'
                    lb["LoadBalancerArn"] = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{lb['LoadBalancerName']}"
                
                # Only include essential information for LLM
                simplified_lb = {
                    "LoadBalancerArn": lb.get("LoadBalancerArn"),
                    "LoadBalancerName": lb.get("LoadBalancerName"),
                    "DNSName": lb.get("DNSName"),
                    "Type": lb.get("Type", "classic")
                }
                load_balancers.append(simplified_lb)
        
        return {
            "load_balancers": load_balancers,
            "next_token": None  # No pagination with ARN lookup
        }
    
    # If we get here, we're using names or getting all load balancers
    
    # Classic ELB request
    if load_balancer_type == 'classic':
        result = get_all_classic_load_balancers(
            names=names,
            next_token=next_token,
            max_items=max_items,
            session_context=session_context
        )
        
        # Process result to ensure ARNs are returned
        processed_lbs = []
        for lb in result.get("load_balancers", []):
            if "LoadBalancerName" in lb:
                # Create ARN for Classic ELB
                sts_client = get_client('sts', session_context=session_context)
                account_id = sts_client.get_caller_identity()['Account']
                region = lb.get('AvailabilityZones', [{}])[0].get('ZoneName', '')[:10] if lb.get('AvailabilityZones') else 'us-east-1'
                lb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{lb['LoadBalancerName']}"
                
                # Simplified response with just essential info
                processed_lbs.append({
                    "LoadBalancerArn": lb_arn,
                    "LoadBalancerName": lb.get("LoadBalancerName"),
                    "DNSName": lb.get("DNSName"),
                    "Type": "classic"
                })
        
        return {
            "load_balancers": processed_lbs,
            "next_token": result.get("next_token")
        }
    
    # ELBv2 specific types
    if load_balancer_type in ['application', 'network', 'gateway']:
        if load_balancer_type == 'application':
            result = get_all_application_load_balancers(
                names=names,
                next_token=next_token,
                max_items=max_items,
                session_context=session_context
            )
        elif load_balancer_type == 'network':
            result = get_all_network_load_balancers(
                names=names,
                next_token=next_token,
                max_items=max_items,
                session_context=session_context
            )
        else:  # gateway
            result = get_all_gateway_load_balancers(
                names=names,
                next_token=next_token,
                max_items=max_items,
                session_context=session_context
            )
        
        # Process results to include only essential information
        processed_lbs = []
        for lb in result.get("load_balancers", []):
            processed_lbs.append({
                "LoadBalancerArn": lb.get("LoadBalancerArn"),
                "LoadBalancerName": lb.get("LoadBalancerName"),
                "DNSName": lb.get("DNSName"),
                "Type": lb.get("Type")
            })
        
        return {
            "load_balancers": processed_lbs,
            "next_token": result.get("next_token")
        }
    
    # If we get here, we want all types - prioritize ELBv2 first
    
    # First try ELBv2
    elbv2_result = get_all_load_balancers_v2(
        names=names,
        next_token=next_token,
        max_items=max_items,
        session_context=session_context
    )
    
    # Process ELBv2 results
    processed_elbv2_lbs = []
    for lb in elbv2_result.get("load_balancers", []):
        processed_elbv2_lbs.append({
            "LoadBalancerArn": lb.get("LoadBalancerArn"),
            "LoadBalancerName": lb.get("LoadBalancerName"),
            "DNSName": lb.get("DNSName"),
            "Type": lb.get("Type")
        })
    
    # If we have a full page of results, just return those
    if len(processed_elbv2_lbs) >= max_items:
        return {
            "load_balancers": processed_elbv2_lbs,
            "next_token": elbv2_result.get("next_token")
        }
    
    # Otherwise, also fetch Classic load balancers to fill the page
    remaining_items = max_items - len(processed_elbv2_lbs)
    classic_result = get_all_classic_load_balancers(
        names=names,
        next_token=None,  # We don't pass next_token since we're combining results
        max_items=remaining_items,
        session_context=session_context
    )
    
    # Process Classic ELB results
    processed_classic_lbs = []
    for lb in classic_result.get("load_balancers", []):
        if "LoadBalancerName" in lb:
            # Create ARN for Classic ELB
            sts_client = get_client('sts', session_context=session_context)
            account_id = sts_client.get_caller_identity()['Account']
            region = lb.get('AvailabilityZones', [{}])[0].get('ZoneName', '')[:10] if lb.get('AvailabilityZones') else 'us-east-1'
            lb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{lb['LoadBalancerName']}"
            
            processed_classic_lbs.append({
                "LoadBalancerArn": lb_arn,
                "LoadBalancerName": lb.get("LoadBalancerName"),
                "DNSName": lb.get("DNSName"),
                "Type": "classic"
            })
    
    # Combine the results
    return {
        "load_balancers": processed_elbv2_lbs + processed_classic_lbs,
        "next_token": classic_result.get("next_token"),  # Use the classic next_token if available
        "has_more_elbv2": elbv2_result.get("next_token") is not None
    }


def describe_listeners(
    load_balancer_arn: Optional[str] = None,
    listener_arns: Optional[List[str]] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Describe listeners using either load balancer ARN or listener ARNs.
    
    This function provides direct access to the ELBv2 describe_listeners API.
    Either load_balancer_arn or listener_arns must be provided.
    
    Args:
        load_balancer_arn: ARN of the load balancer (exclusive with listener_arns)
        listener_arns: List of listener ARNs (exclusive with load_balancer_arn)
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary with listeners and any errors
    """
    client = get_client('elbv2', session_context=session_context)
    
    # Parameter validation
    if not load_balancer_arn and not listener_arns:
        error_msg = "Either load_balancer_arn or listener_arns must be provided"
        logger.error(error_msg)
        return {
            "listeners": [],
            "error": error_msg
        }
    
    if load_balancer_arn and listener_arns:
        error_msg = "Cannot provide both load_balancer_arn and listener_arns"
        logger.error(error_msg)
        return {
            "listeners": [],
            "error": error_msg
        }
    
    # Prepare parameters for API call
    params = {}
    if load_balancer_arn:
        params['LoadBalancerArn'] = load_balancer_arn
    if listener_arns:
        params['ListenerArns'] = listener_arns
    
    try:
        response = client.describe_listeners(**params)
        return {
            "listeners": response.get('Listeners', [])
        }
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"AWS ClientError in describe_listeners: {error_code} - {error_message}")
        
        # Provide specific error messages based on error code
        if error_code == 'LoadBalancerNotFound':
            error_info = f"Load balancer not found with ARN: {load_balancer_arn}"
        elif error_code == 'ListenerNotFound':
            error_info = f"One or more listener ARNs not found: {listener_arns}"
        elif error_code == 'ValidationError':
            error_info = f"Validation error: {error_message}"
        else:
            error_info = error_message
        
        return {
            "listeners": [],
            "error": error_info,
            "error_code": error_code
        }
    except Exception as e:
        logger.error(f"Unexpected error in describe_listeners: {e}")
        return {
            "listeners": [],
            "error": str(e)
        } 