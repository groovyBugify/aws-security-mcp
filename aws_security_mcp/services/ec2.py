"""AWS EC2 service client module.

This module provides functions for interacting with AWS EC2 services.
"""

import logging
from typing import Any, Dict, List, Optional, Union, Iterator

import boto3
from botocore.exceptions import ClientError
from botocore.paginate import PageIterator

from aws_security_mcp.services.base import get_client, handle_aws_error, handle_pagination

# Configure logging
logger = logging.getLogger(__name__)

def get_ec2_client(session_context: Optional[str] = None, **kwargs: Any) -> boto3.client:
    """Get AWS EC2 client.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized EC2 client
    """
    return get_client('ec2', session_context=session_context, **kwargs)

def get_paginator(operation_name: str, session_context: Optional[str] = None, **kwargs: Any) -> PageIterator:
    """Get a paginator for the specified EC2 operation.
    
    Args:
        operation_name: Name of the EC2 operation to paginate
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the paginator
        
    Returns:
        PageIterator: A boto3 paginator for the operation
    """
    client = get_ec2_client(session_context=session_context, **kwargs)
    return client.get_paginator(operation_name)

def create_instance_filters(states: Optional[List[str]] = None, 
                           vpc_ids: Optional[List[str]] = None,
                           subnet_ids: Optional[List[str]] = None,
                           additional_filters: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Create properly formatted filters for EC2 instance API calls.
    
    Args:
        states: Optional list of instance states to filter by (e.g., ['running', 'stopped'])
        vpc_ids: Optional list of VPC IDs to filter by
        subnet_ids: Optional list of subnet IDs to filter by
        additional_filters: Optional list of additional filters to include
        
    Returns:
        List[Dict[str, Any]]: Properly formatted filters list for EC2 API calls
    """
    filters = []
    
    # Add instance state filter if provided
    if states:
        filters.append({
            'Name': 'instance-state-name',
            'Values': states
        })
    
    # Add VPC filter if provided
    if vpc_ids:
        filters.append({
            'Name': 'vpc-id',
            'Values': vpc_ids
        })
    
    # Add subnet filter if provided
    if subnet_ids:
        filters.append({
            'Name': 'subnet-id',
            'Values': subnet_ids
        })
    
    # Add any additional filters
    if additional_filters:
        filters.extend(additional_filters)
    
    return filters

def describe_instances(
    filters: Optional[List[Dict[str, Any]]] = None,
    instance_ids: Optional[List[str]] = None,
    max_results: Optional[int] = None,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe EC2 instances with filtering options.
    
    Args:
        filters: List of filters to apply
        instance_ids: List of instance IDs to describe
        max_results: Maximum number of instances to return per page (None for all, API limits: 5-1000)
        next_token: Token for pagination
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_instances API call
        
    Returns:
        Dict[str, Any]: Response containing instances grouped by reservation
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if filters:
        params['Filters'] = filters
    
    if instance_ids:
        params['InstanceIds'] = instance_ids
    
    
    if next_token:
        params['NextToken'] = next_token
    
    try:
        return client.describe_instances(**params)
    except ClientError as e:
        logger.error(f"Error describing EC2 instances: {e}")
        raise

def get_all_instances(
    filters: Optional[List[Dict[str, Any]]] = None,
    instance_ids: Optional[List[str]] = None,
    max_items: Optional[int] = None, 
    states: Optional[List[str]] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get all EC2 instances with pagination handling using boto3 paginators.
    
    Args:
        filters: List of filters to apply
        instance_ids: List of instance IDs to describe
        max_items: Maximum number of instances to return (None for all)
        states: Optional list of instance states to filter by (e.g., ['running', 'stopped'])
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_instances API call
        
    Returns:
        List[Dict[str, Any]]: List of EC2 instances
    """
    # Create filters including state filters if provided
    if states:
        if filters is None:
            filters = []
        filters = create_instance_filters(states=states, additional_filters=filters)
    
    # Set up parameters
    params = {}
    if filters:
        params['Filters'] = filters
    if instance_ids:
        params['InstanceIds'] = instance_ids
    
    # Add additional parameters
    params.update(kwargs)
    
    # Get paginator
    paginator = get_paginator('describe_instances', session_context=session_context)
    
    # Configure pagination
    page_config = {}
    
    # Get all instances
    all_instances = []
    
    try:
        page_iterator = paginator.paginate(**params, PaginationConfig=page_config)
        
        for page in page_iterator:
            # Process instances
            reservations = page.get('Reservations', [])
            
            for reservation in reservations:
                all_instances.extend(reservation.get('Instances', []))
                
    except ClientError as e:
        logger.error(f"Error getting EC2 instances: {e}")
        raise
    
    return all_instances

def filter_instances_by_text(instances: List[Dict[str, Any]], search_term: str) -> List[Dict[str, Any]]:
    """Filter instances based on text search.
    
    Args:
        instances: List of instances to filter
        search_term: Text to search for in instance attributes
        
    Returns:
        List[Dict[str, Any]]: Filtered list of instances
    """
    search_term = search_term.lower()
    
    # Check if we're specifically searching for state
    state_search = None
    if search_term in ['running', 'stopped', 'stopping', 'pending', 'terminated', 'shutting-down']:
        state_search = search_term
    elif search_term.startswith('state:'):
        state_search = search_term.split(':', 1)[1].strip()
    
    # If we're only searching for state, use a direct filter
    if state_search and search_term == state_search or search_term == f"state:{state_search}":
        return [
            instance for instance in instances 
            if instance.get('State', {}).get('Name', '').lower() == state_search
        ]
    
    filtered_instances = []
    
    for instance in instances:
        # Get relevant fields to search in
        instance_id = instance.get('InstanceId', '').lower()
        instance_type = instance.get('InstanceType', '').lower()
        private_ip = instance.get('PrivateIpAddress', '').lower()
        public_ip = instance.get('PublicIpAddress', '').lower()
        vpc_id = instance.get('VpcId', '').lower()
        subnet_id = instance.get('SubnetId', '').lower()
        image_id = instance.get('ImageId', '').lower()
        state = instance.get('State', {}).get('Name', '').lower()
        
        # Check for name tag
        name_tag = ""
        for tag in instance.get('Tags', []):
            if tag.get('Key') == 'Name':
                name_tag = tag.get('Value', '').lower()
                break
        
        # If state search is active, filter out non-matching instances
        if state_search and state != state_search:
            continue
        
        # Check if any field matches the search term
        if (search_term in instance_id or
            search_term in instance_type or
            search_term in private_ip or
            search_term in public_ip or
            search_term in vpc_id or
            search_term in subnet_id or
            search_term in image_id or
            search_term in name_tag or
            search_term in state):
            filtered_instances.append(instance)
    
    return filtered_instances

def describe_security_groups(
    group_ids: Optional[List[str]] = None,
    group_names: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    next_token: Optional[str] = None,
    max_results: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe EC2 security groups.
    
    Args:
        group_ids: List of security group IDs to describe
        group_names: List of security group names to describe
        filters: List of filters to apply
        next_token: Token for pagination
        max_results: Maximum number of results to return per page (None for all)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_security_groups API call
        
    Returns:
        Dict containing security groups and pagination information
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if group_ids:
        params['GroupIds'] = group_ids
    
    if group_names:
        params['GroupNames'] = group_names
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    try:
        response = client.describe_security_groups(**params)
        
        security_groups = response.get('SecurityGroups', [])
        next_token_value = response.get('NextToken')
        
        return {
            'SecurityGroups': security_groups,
            'NextToken': next_token_value
        }
    except ClientError as e:
        logger.error(f"Error describing security groups: {e}")
        raise

def get_all_security_groups(
    filters: Optional[List[Dict[str, Any]]] = None,
    group_ids: Optional[List[str]] = None,
    group_names: Optional[List[str]] = None,
    max_items: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get all security groups with pagination handling using boto3 paginators.
    
    Args:
        filters: List of filters to apply
        group_ids: List of security group IDs to describe
        group_names: List of security group names to describe
        max_items: Maximum number of security groups to return (None for all)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_security_groups API call
        
    Returns:
        List[Dict[str, Any]]: List of security groups
    """
    # Set up parameters
    params = {}
    if filters:
        params['Filters'] = filters
    if group_ids:
        params['GroupIds'] = group_ids
    if group_names:
        params['GroupNames'] = group_names
    
    # Add additional parameters
    params.update(kwargs)
    
    # Get paginator
    paginator = get_paginator('describe_security_groups', session_context=session_context)
    
    # Configure pagination
    page_config = {}
    
    # Get all security groups
    all_security_groups = []
    
    try:
        page_iterator = paginator.paginate(**params, PaginationConfig=page_config)
        
        for page in page_iterator:
            all_security_groups.extend(page.get('SecurityGroups', []))
                
    except ClientError as e:
        logger.error(f"Error getting security groups: {e}")
        raise
    
    return all_security_groups

def filter_security_groups_by_text(
    search_term: str,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Filter security groups by matching text in name, description, or tags.
    
    Args:
        search_term: Text to search for in security group name, description or tags
                    Special syntax:
                    - port:XX - Find security groups with specific port open
                    - protocol:XX - Find security groups allowing specific protocol
                    - public:true - Find security groups open to the internet
                    - cidr:X.X.X.X/X - Find security groups allowing specific CIDR range
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the get_all_security_groups function
        
    Returns:
        List[Dict[str, Any]]: List of matching security groups
    """
    # Get all security groups without any limit
    security_groups = get_all_security_groups(session_context=session_context, **kwargs)
    
    # If empty search term, return all
    if not search_term:
        return security_groups
    
    # Handle special search syntax
    if search_term.startswith("port:"):
        try:
            # Extract port number and convert to int
            port_str = search_term.split(':', 1)[1]
            port = int(port_str)
            
            # Filter security groups with this port open
            matching_groups = []
            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    rule_protocol = rule.get('IpProtocol', '')
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    
                    # Check if port is in range
                    port_match = False
                    if rule_protocol == '-1':  # All traffic
                        port_match = True
                    elif from_port is not None and to_port is not None:
                        if from_port <= port <= to_port:
                            port_match = True
                    
                    if port_match:
                        matching_groups.append(sg)
                        break  # No need to check other rules
                        
            return matching_groups
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid port number in search: {search_term}")
            # Fall back to text search
            pass
    
    elif search_term.startswith("protocol:"):
        protocol = search_term.split(':', 1)[1].lower()
        matching_groups = []
        
        for sg in security_groups:
            for rule in sg.get('IpPermissions', []):
                rule_protocol = rule.get('IpProtocol', '').lower()
                
                # Handle protocol matching
                if rule_protocol == '-1' or rule_protocol == protocol:
                    matching_groups.append(sg)
                    break
                elif protocol == 'tcp' and rule_protocol == '6':
                    matching_groups.append(sg)
                    break
                elif protocol == 'udp' and rule_protocol == '17':
                    matching_groups.append(sg)
                    break
                    
        return matching_groups
    
    elif search_term.startswith("public:true"):
        matching_groups = []
        
        for sg in security_groups:
            for rule in sg.get('IpPermissions', []):
                is_public = False
                
                # Check for public CIDR ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if cidr in ('0.0.0.0/0', '::/0'):
                        is_public = True
                        break
                
                # Check IPv6 ranges too
                if not is_public:
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        cidr = ipv6_range.get('CidrIpv6', '')
                        if cidr == '::/0':
                            is_public = True
                            break
                
                if is_public:
                    matching_groups.append(sg)
                    break
                    
        return matching_groups
    
    elif search_term.startswith("cidr:"):
        cidr = search_term.split(':', 1)[1]
        matching_groups = []
        
        for sg in security_groups:
            for rule in sg.get('IpPermissions', []):
                cidr_match = False
                
                # Check IPv4 CIDR ranges
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp', '') == cidr:
                        cidr_match = True
                        break
                
                # Check IPv6 ranges
                if not cidr_match:
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        if ipv6_range.get('CidrIpv6', '') == cidr:
                            cidr_match = True
                            break
                
                if cidr_match:
                    matching_groups.append(sg)
                    break
                    
        return matching_groups
        
    # Standard text search for everything else
    # Normalize search term
    search_term_lower = search_term.lower()
    
    # Filter security groups by search term
    matching_groups = []
    for sg in security_groups:
        # Check if search term is in name or description
        if search_term_lower in sg.get('GroupName', '').lower() or search_term_lower in sg.get('Description', '').lower():
            matching_groups.append(sg)
            continue
            
        # Check if search term is in tags
        tags = sg.get('Tags', [])
        for tag in tags:
            if (search_term_lower in tag.get('Key', '').lower() or 
                search_term_lower in tag.get('Value', '').lower()):
                matching_groups.append(sg)
                break
    
    return matching_groups

def describe_vpcs(
    vpc_ids: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    next_token: Optional[str] = None,
    max_results: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe VPCs with filtering options.
    
    Args:
        vpc_ids: List of VPC IDs to describe
        filters: List of filters to apply
        next_token: Token for pagination
        max_results: Maximum number of results to return (None for all)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_vpcs API call
        
    Returns:
        Dict[str, Any]: Response containing VPCs
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if vpc_ids:
        params['VpcIds'] = vpc_ids
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    try:
        return client.describe_vpcs(**params)
    except ClientError as e:
        logger.error(f"Error describing VPCs: {e}")
        raise

def get_all_vpcs(
    filters: Optional[List[Dict[str, Any]]] = None,
    vpc_ids: Optional[List[str]] = None,
    max_items: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get all VPCs with pagination handling using boto3 paginators.
    
    Args:
        filters: List of filters to apply
        vpc_ids: List of VPC IDs to describe
        max_items: Maximum number of VPCs to return (None for all)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_vpcs API call
        
    Returns:
        List[Dict[str, Any]]: List of VPCs
    """
    # Set up parameters
    params = {}
    if filters:
        params['Filters'] = filters
    if vpc_ids:
        params['VpcIds'] = vpc_ids
    
    # Add additional parameters
    params.update(kwargs)
    
    # Get paginator
    paginator = get_paginator('describe_vpcs', session_context=session_context)
    
    # Configure pagination
    page_config = {}
    
    # Get all VPCs
    all_vpcs = []
    
    try:
        page_iterator = paginator.paginate(**params, PaginationConfig=page_config)
        
        for page in page_iterator:
            all_vpcs.extend(page.get('Vpcs', []))
                
    except ClientError as e:
        logger.error(f"Error getting VPCs: {e}")
        raise
    
    return all_vpcs

def filter_vpcs_by_text(vpcs: List[Dict[str, Any]], search_term: str) -> List[Dict[str, Any]]:
    """Filter a list of VPCs by search term.
    
    Args:
        vpcs: List of VPC dictionaries
        search_term: Term to search for in VPC fields
        
    Returns:
        List[Dict[str, Any]]: Filtered list of VPCs
    """
    if not search_term:
        return vpcs
    
    search_term_lower = search_term.lower()
    filtered_vpcs = []
    
    for vpc in vpcs:
        # Get relevant fields to search in
        vpc_id = vpc.get('VpcId', '').lower()
        cidr_block = vpc.get('CidrBlock', '').lower()
        
        # Check name tag and other tags
        tag_match = False
        for tag in vpc.get('Tags', []):
            tag_value = tag.get('Value', '').lower()
            if search_term_lower in tag_value:
                tag_match = True
                break
        
        # Check if any field matches the search term
        if (search_term_lower in vpc_id or
            search_term_lower in cidr_block or
            tag_match):
            filtered_vpcs.append(vpc)
    
    return filtered_vpcs

def describe_route_tables(
    filters: Optional[List[Dict[str, Any]]] = None,
    route_table_ids: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_results: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe route tables with filtering options.
    
    Args:
        filters: List of filters to apply
        route_table_ids: List of route table IDs to describe
        next_token: Token for pagination
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_route_tables API call
        
    Returns:
        Dict[str, Any]: Response containing route tables
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if filters:
        params['Filters'] = filters
    
    if route_table_ids:
        params['RouteTableIds'] = route_table_ids
    
    if next_token:
        params['NextToken'] = next_token
        
    try:
        return client.describe_route_tables(**params)
    except ClientError as e:
        logger.error(f"Error describing route tables: {e}")
        raise

def get_all_route_tables(
    filters: Optional[List[Dict[str, Any]]] = None,
    route_table_ids: Optional[List[str]] = None,
    max_items: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get all route tables with pagination handling using boto3 paginators.
    
    Args:
        filters: List of filters to apply
        route_table_ids: List of route table IDs to describe
        max_items: Maximum number of route tables to return (None for all)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_route_tables API call
        
    Returns:
        List[Dict[str, Any]]: List of route tables
    """
    # Set up parameters
    params = {}
    if filters:
        params['Filters'] = filters
    if route_table_ids:
        params['RouteTableIds'] = route_table_ids
    
    # Add additional parameters
    params.update(kwargs)
    
    # Get paginator
    paginator = get_paginator('describe_route_tables', session_context=session_context)
    
    # Configure pagination
    page_config = {}
    
    # Get all route tables
    all_route_tables = []
    
    try:
        page_iterator = paginator.paginate(**params, PaginationConfig=page_config)
        
        for page in page_iterator:
            all_route_tables.extend(page.get('RouteTables', []))
                
    except ClientError as e:
        logger.error(f"Error getting route tables: {e}")
        raise
    
    return all_route_tables

def describe_images(
    image_ids: Optional[List[str]] = None,
    owners: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe AMIs with filtering options.
    
    Args:
        image_ids: List of AMI IDs to describe
        owners: List of AMI owners (e.g., 'self', 'amazon')
        filters: List of filters to apply
        next_token: Token for pagination
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_images API call
        
    Returns:
        Dict[str, Any]: Response containing AMIs
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if image_ids:
        params['ImageIds'] = image_ids
    
    if owners:
        params['Owners'] = owners
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    try:
        return client.describe_images(**params)
    except ClientError as e:
        logger.error(f"Error describing AMIs: {e}")
        raise

def describe_volumes(
    volume_ids: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe EBS volumes with filtering options.
    
    Args:
        volume_ids: List of volume IDs to describe
        filters: List of filters to apply
        next_token: Token for pagination
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_volumes API call
        
    Returns:
        Dict[str, Any]: Response containing volumes
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if volume_ids:
        params['VolumeIds'] = volume_ids
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    try:
        return client.describe_volumes(**params)
    except ClientError as e:
        logger.error(f"Error describing EBS volumes: {e}")
        raise

def describe_internet_gateways(
    internet_gateway_ids: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe internet gateways with filtering options.
    
    Args:
        internet_gateway_ids: List of internet gateway IDs to describe
        filters: List of filters to apply
        next_token: Token for pagination
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_internet_gateways API call
        
    Returns:
        Dict[str, Any]: Response containing internet gateways
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if internet_gateway_ids:
        params['InternetGatewayIds'] = internet_gateway_ids
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    try:
        return client.describe_internet_gateways(**params)
    except ClientError as e:
        logger.error(f"Error describing internet gateways: {e}")
        raise

def describe_subnets(
    subnet_ids: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    next_token: Optional[str] = None,
    max_results: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe subnets with filtering options.
    
    Args:
        subnet_ids: List of subnet IDs to describe
        filters: List of filters to apply
        next_token: Token for pagination
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_subnets API call
        
    Returns:
        Dict[str, Any]: Response containing subnets
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if subnet_ids:
        params['SubnetIds'] = subnet_ids
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    try:
        return client.describe_subnets(**params)
    except ClientError as e:
        logger.error(f"Error describing subnets: {e}")
        raise

def get_all_subnets(
    filters: Optional[List[Dict[str, Any]]] = None,
    subnet_ids: Optional[List[str]] = None,
    max_items: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get all subnets with pagination handling using boto3 paginators.
    
    Args:
        filters: List of filters to apply
        subnet_ids: List of subnet IDs to describe
        max_items: Maximum number of subnets to return (None for all)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_subnets API call
        
    Returns:
        List[Dict[str, Any]]: List of subnets
    """
    # Set up parameters
    params = {}
    if filters:
        params['Filters'] = filters
    if subnet_ids:
        params['SubnetIds'] = subnet_ids
    
    # Add additional parameters
    params.update(kwargs)
    
    # Get paginator
    paginator = get_paginator('describe_subnets', session_context=session_context)
    
    # Configure pagination
    page_config = {}
    
    # Get all subnets
    all_subnets = []
    
    try:
        page_iterator = paginator.paginate(**params, PaginationConfig=page_config)
        
        for page in page_iterator:
            all_subnets.extend(page.get('Subnets', []))
                
    except ClientError as e:
        logger.error(f"Error getting subnets: {e}")
        raise
    
    return all_subnets

def filter_subnets_by_text(subnets: List[Dict[str, Any]], search_term: str) -> List[Dict[str, Any]]:
    """Filter a list of subnets by search term.
    
    Args:
        subnets: List of subnet dictionaries
        search_term: Term to search for in subnet fields
        
    Returns:
        List[Dict[str, Any]]: Filtered list of subnets
    """
    if not search_term:
        return subnets
    
    search_term_lower = search_term.lower()
    filtered_subnets = []
    
    for subnet in subnets:
        # Get relevant fields to search in
        subnet_id = subnet.get('SubnetId', '').lower()
        vpc_id = subnet.get('VpcId', '').lower()
        cidr_block = subnet.get('CidrBlock', '').lower()
        availability_zone = subnet.get('AvailabilityZone', '').lower()
        
        # Check name tag and other tags
        tag_match = False
        for tag in subnet.get('Tags', []):
            tag_key = tag.get('Key', '').lower()
            tag_value = tag.get('Value', '').lower()
            if search_term_lower in tag_key or search_term_lower in tag_value:
                tag_match = True
                break
        
        # Check if any field matches the search term
        if (search_term_lower in subnet_id or
            search_term_lower in vpc_id or
            search_term_lower in cidr_block or
            search_term_lower in availability_zone or
            tag_match):
            filtered_subnets.append(subnet)
    
    return filtered_subnets

def describe_network_acls(
    network_acl_ids: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    next_token: Optional[str] = None,
    max_results: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """Describe network ACLs with filtering options.
    
    Args:
        network_acl_ids: List of network ACL IDs to describe
        filters: List of filters to apply
        next_token: Token for pagination
        max_results: Maximum number of results to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_network_acls API call
        
    Returns:
        Dict[str, Any]: Response containing network ACLs
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if network_acl_ids:
        params['NetworkAclIds'] = network_acl_ids
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    try:
        return client.describe_network_acls(**params)
    except ClientError as e:
        logger.error(f"Error describing network ACLs: {e}")
        raise

def describe_addresses(
    allocation_ids: Optional[List[str]] = None,
    public_ips: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Describe Elastic IP addresses.
    
    Args:
        allocation_ids: List of allocation IDs to describe
        public_ips: List of public IP addresses to describe
        filters: List of filters to apply
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_addresses API call
        
    Returns:
        List of Elastic IP address data
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if allocation_ids:
        params['AllocationIds'] = allocation_ids
    
    if public_ips:
        params['PublicIps'] = public_ips
    
    if filters:
        params['Filters'] = filters
    
    try:
        response = client.describe_addresses(**params)
        return response.get('Addresses', [])
    except ClientError as e:
        logger.error(f"Error describing Elastic IP addresses: {e}")
        raise

def describe_network_interfaces(
    network_interface_ids: Optional[List[str]] = None,
    filters: Optional[List[Dict[str, Any]]] = None,
    next_token: Optional[str] = None,
    max_results: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Describe EC2 network interfaces.
    
    Args:
        network_interface_ids: List of network interface IDs to describe
        filters: List of filters to apply
        next_token: Token for pagination
        max_results: Maximum number of results to return per page (None for all)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_network_interfaces API call
        
    Returns:
        List of network interface data
    """
    client = get_ec2_client(session_context=session_context)
    
    params = {
        **kwargs
    }
    
    if network_interface_ids:
        params['NetworkInterfaceIds'] = network_interface_ids
    
    if filters:
        params['Filters'] = filters
    
    if next_token:
        params['NextToken'] = next_token
    
    if max_results:
        params['MaxResults'] = max_results
    
    try:
        response = client.describe_network_interfaces(**params)
        return response.get('NetworkInterfaces', [])
    except ClientError as e:
        logger.error(f"Error describing network interfaces: {e}")
        raise

def get_all_network_interfaces(
    filters: Optional[List[Dict[str, Any]]] = None,
    network_interface_ids: Optional[List[str]] = None,
    max_items: Optional[int] = None,
    session_context: Optional[str] = None,
    **kwargs: Any
) -> List[Dict[str, Any]]:
    """Get all network interfaces with pagination handling using boto3 paginators.
    
    Args:
        filters: List of filters to apply
        network_interface_ids: List of network interface IDs to describe
        max_items: Maximum number of network interfaces to return (None for all)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the describe_network_interfaces API call
        
    Returns:
        List[Dict[str, Any]]: List of network interfaces
    """
    # Set up parameters
    params = {}
    if filters:
        params['Filters'] = filters
    if network_interface_ids:
        params['NetworkInterfaceIds'] = network_interface_ids
    
    # Add additional parameters
    params.update(kwargs)
    
    # Get paginator
    paginator = get_paginator('describe_network_interfaces', session_context=session_context)
    
    # Configure pagination
    page_config = {}
    if max_items:
        page_config['MaxItems'] = max_items
    
    # Get all network interfaces
    all_interfaces = []
    
    try:
        page_iterator = paginator.paginate(**params, PaginationConfig=page_config)
        
        for page in page_iterator:
            all_interfaces.extend(page.get('NetworkInterfaces', []))
                
    except ClientError as e:
        logger.error(f"Error getting network interfaces: {e}")
        raise
    
    return all_interfaces 