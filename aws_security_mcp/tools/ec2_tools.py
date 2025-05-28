"""EC2 tools for AWS Security MCP.

This module provides tools for working with EC2 resources, including:
- Listing and searching EC2 instances
- Listing and filtering security groups, including by inbound rules and ports
- Identifying resources with public internet access
- Analyzing VPCs and networking components
- Finding security vulnerabilities like open ports
"""

import logging
from typing import Any, Dict, List, Optional, Union
import json
from datetime import datetime
import boto3

from aws_security_mcp.services import ec2
from aws_security_mcp.services.base import get_client
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)

# Define custom JSON encoder for datetime objects
class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


@register_tool()
async def list_ec2_instances(limit: Optional[int] = None, search_term: str = "", state: str = "running", next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List EC2 instances with details.
    
    Args:
        limit: Maximum number of instances to return (None for all)
        search_term: Optional search term to filter instances by name, ID, or type
        state: Instance state to filter by (default is "running"). Set to empty string to show all states.
        next_token: Pagination token from a previous request (optional)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with EC2 instance information
    """
    logger.info(f"Listing EC2 instances (limit={limit}, search_term='{search_term}', state='{state}', next_token={next_token}, session_context={session_context})")
    
    try:
        ec2_client = get_client("ec2", session_context=session_context)
        
        # Prepare parameters for the API call
        kwargs = {}
        
        # Add filters based on state if provided
        if state:
            filters = [{
                'Name': 'instance-state-name',
                'Values': [state]
            }]
            kwargs['Filters'] = filters
        
        # Add pagination token if provided
        if next_token:
            kwargs['NextToken'] = next_token
            
        # Add max results if limit is specified
        if limit:
            kwargs['MaxResults'] = min(limit, 1000)  # AWS API max is 1000
        
        # Get instances
        response = ec2_client.describe_instances(**kwargs)
        
        # Extract instances from reservations
        instances = []
        for reservation in response.get('Reservations', []):
            instances.extend(reservation.get('Instances', []))
            
        # Filter instances based on search term if provided
        filtered_instances = []
        for instance in instances:
            if search_term:
                # Convert all values to lowercase for case-insensitive search
                instance_id = instance.get('InstanceId', '').lower()
                instance_type = instance.get('InstanceType', '').lower()
                private_ip = instance.get('PrivateIpAddress', '').lower() if instance.get('PrivateIpAddress') else ''
                public_ip = instance.get('PublicIpAddress', '').lower() if instance.get('PublicIpAddress') else ''
                vpc_id = instance.get('VpcId', '').lower() if instance.get('VpcId') else ''
                subnet_id = instance.get('SubnetId', '').lower() if instance.get('SubnetId') else ''
                
                # Get name tag if available
                instance_name = next((tag['Value'].lower() for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), '')
                
                search_lower = search_term.lower()
                
                # Skip if search term not found in any field
                if (search_lower not in instance_id and
                    search_lower not in instance_type and
                    search_lower not in private_ip and
                    search_lower not in public_ip and
                    search_lower not in vpc_id and
                    search_lower not in subnet_id and
                    search_lower not in instance_name):
                    continue
                
            # Extract security groups
            security_groups = []
            for sg in instance.get('SecurityGroups', []):
                security_groups.append({
                    'id': sg.get('GroupId', ''),
                    'name': sg.get('GroupName', '')
                })
            
            # Get instance name from tags
            name = next((tag.get('Value', '') for tag in instance.get('Tags', []) if tag.get('Key') == 'Name'), '')
            
            # Format instance details
            formatted_instance = {
                'id': instance.get('InstanceId', ''),
                'name': name,
                'type': instance.get('InstanceType', ''),
                'state': instance.get('State', {}).get('Name', ''),
                'private_ip': instance.get('PrivateIpAddress', ''),
                'public_ip': instance.get('PublicIpAddress', ''),
                'vpc_id': instance.get('VpcId', ''),
                'subnet_id': instance.get('SubnetId', ''),
                'image_id': instance.get('ImageId', ''),
                'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else '',
                'key_name': instance.get('KeyName', ''),
                'security_groups': security_groups,
                'iam_instance_profile': instance.get('IamInstanceProfile', {}).get('Arn', '') if instance.get('IamInstanceProfile') else '',
                'ebs_volumes': [
                    {
                        'device': mapping.get('DeviceName', ''),
                        'volume_id': mapping.get('Ebs', {}).get('VolumeId', '') if mapping.get('Ebs') else ''
                    } for mapping in instance.get('BlockDeviceMappings', [])
                ]
            }
            
            filtered_instances.append(formatted_instance)
            
            # Check if we've reached the limit
            if limit and len(filtered_instances) >= limit:
                break
        
        # Extract next token for pagination
        next_token = response.get('NextToken')
        
        # Format the final result
        result = {
            'instances': filtered_instances,
            'count': len(filtered_instances),
            'has_more': bool(next_token),
            'next_token': next_token
        }
        
        return json.dumps(result, cls=CustomJSONEncoder)
        
    except Exception as e:
        error_message = f"Error listing EC2 instances: {str(e)}"
        logger.error(error_message, exc_info=True)
        return json.dumps({
            "error": error_message,
            "instances": [],
            "count": 0,
            "has_more": False
        })


@register_tool()
async def count_ec2_instances(state: str = "", has_public_access: Optional[bool] = None, port: Optional[int] = None, session_context: Optional[str] = None) -> str:
    """Count EC2 instances, optionally filtering by state and security group rules.
    
    Args:
        state: Optional instance state to filter by (e.g., running, stopped, terminated)
        has_public_access: If set, only count instances with (True) or without (False) public internet access
        port: Optional specific port to check for access (e.g., 22 for SSH)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with instance count information
    """
    logger.info(f"Counting EC2 instances (state='{state}', has_public_access={has_public_access}, port={port}, session_context={session_context})")
    
    try:
        # Handle state filtering - convert single string state to list if provided
        states = [state] if state else None
        
        # Get all instances with state filtering - pass session_context to ec2 service calls
        all_instances = ec2.get_all_instances(max_items=None, states=states, session_context=session_context)
        
        # If we're not filtering by public access, return the count now
        if has_public_access is None and port is None:
            count_by_state = {}
            for instance in all_instances:
                current_state = instance.get('State', {}).get('Name', 'unknown')
                count_by_state[current_state] = count_by_state.get(current_state, 0) + 1
            
            total_count = len(all_instances)
            
            if state:
                return json.dumps({"summary": f"Found {total_count} EC2 instance(s) in state '{state}'"})
            else:
                result = f"Total EC2 instances: {total_count}\n\nBreakdown by state:\n"
                for s, count in sorted(count_by_state.items()):
                    result += f"- {s}: {count}\n"
                return json.dumps({"summary": result})
        
        # We need to check for public access, so get security groups
        all_security_groups = ec2.get_all_security_groups(max_items=None, session_context=session_context)
        
        # Create lookup dictionary for security groups
        sg_dict = {sg.get('GroupId'): sg for sg in all_security_groups}
        
        # Track instances with public access
        public_instances = []
        non_public_instances = []
        
        # Check each instance
        for instance in all_instances:
            # Get security groups attached to the instance
            instance_sgs = instance.get('SecurityGroups', [])
            instance_public = False
            
            for instance_sg in instance_sgs:
                sg_id = instance_sg.get('GroupId')
                
                # Get the full security group details
                sg = sg_dict.get(sg_id)
                if not sg:
                    continue
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    rule_protocol = rule.get('IpProtocol', '')
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    
                    # Check if port matches if specified
                    port_match = False
                    if port is not None:
                        if rule_protocol == '-1':  # All traffic
                            port_match = True
                        elif from_port is not None and to_port is not None:
                            if from_port <= port <= to_port:
                                port_match = True
                    else:
                        port_match = True  # No specific port to check
                    
                    # Skip if port doesn't match
                    if not port_match:
                        continue
                    
                    # Check for public CIDR ranges
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr in ('0.0.0.0/0', '::/0'):
                            instance_public = True
                            break
                    
                    if instance_public:
                        break
                
                if instance_public:
                    public_instances.append(instance)
            else:
                non_public_instances.append(instance)
        
        # Count results based on public access filter
        if has_public_access is True:
            instances_to_count = public_instances
        elif has_public_access is False:
            instances_to_count = non_public_instances
        else:
            # Port filter only, regardless of public access
            instances_to_count = public_instances + non_public_instances
        
        # Formulate result message
        if port is not None:
            msg = f"Found {len(instances_to_count)} EC2 instance(s)"
            if has_public_access is True:
                msg += " with public access"
            elif has_public_access is False:
                msg += " without public access"
            msg += f" on port {port}"
            if state:
                msg += f" in state '{state}'"
            return json.dumps({"summary": msg})
        else:
            msg = f"Found {len(instances_to_count)} EC2 instance(s)"
            if has_public_access is True:
                msg += " with public internet access"
            elif has_public_access is False:
                msg += " without public internet access"
            if state:
                msg += f" in state '{state}'"
            return json.dumps({"summary": msg})
    except Exception as e:
        logger.error(f"Error counting EC2 instances: {e}")
        return json.dumps({"error": {"message": f"Error counting EC2 instances: {str(e)}", "type": type(e).__name__}})


@register_tool()
async def list_security_groups(limit: Optional[int] = None, search_term: str = "", next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List EC2 security groups with details.
    
    Args:
        limit: Maximum number of security groups to return (None for all)
        search_term: Optional search term to filter security groups. Supports special syntax:
            - Standard text search by name, ID, description, or VPC ID
            - port:XX - Find security groups with specific port open (e.g., port:22 for SSH)
            - protocol:XX - Find security groups allowing specific protocol (e.g., protocol:http)
            - public:true - Find security groups open to the internet (0.0.0.0/0)
            - cidr:X.X.X.X/X - Find security groups allowing specific CIDR range
        next_token: Pagination token from a previous request (optional)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with security group information
    """
    logger.info(f"Listing security groups (limit={limit}, search_term='{search_term}', next_token={next_token}, session_context={session_context})")
    
    try:
        if next_token:
            # If next_token is provided, we're requesting a specific page
            response = ec2.describe_security_groups(
                next_token=next_token,
                session_context=session_context
            )
            
            security_groups = response.get('SecurityGroups', [])
            
            # Apply text search filter if provided
            if search_term:
                security_groups = ec2.filter_security_groups_by_text(
                    search_term=search_term,
                    session_context=session_context
                )
                
            next_token_value = response.get('NextToken')
        else:
            # No next_token provided, get with optional filtering
            if search_term:
                # Special search syntax handling is done in filter_security_groups_by_text
                security_groups = ec2.filter_security_groups_by_text(
                    search_term=search_term,
                    session_context=session_context
                )
                next_token_value = None
            else:
                # Get all security groups if no search term
                response = ec2.describe_security_groups(session_context=session_context)
                security_groups = response.get('SecurityGroups', [])
                next_token_value = response.get('NextToken')
        
        # Format response
        formatted_groups = []
        
        for sg in security_groups:
            # Extract basic info
            group_id = sg.get('GroupId', '')
            group_name = sg.get('GroupName', '')
            vpc_id = sg.get('VpcId', '')
            description = sg.get('Description', '')
            
            # Format inbound rules
            inbound_rules = []
            for rule in sg.get('IpPermissions', []):
                protocol = rule.get('IpProtocol', '')
                from_port = rule.get('FromPort', '')
                to_port = rule.get('ToPort', '')
                
                # Format protocol display
                if protocol == '-1':
                    protocol_display = 'All'
                    port_range = 'All'
                elif protocol == 'tcp':
                    protocol_display = 'TCP'
                    if from_port == to_port:
                        port_range = str(from_port)
                    else:
                        port_range = f"{from_port}-{to_port}"
                elif protocol == 'udp':
                    protocol_display = 'UDP'
                    if from_port == to_port:
                        port_range = str(from_port)
                    else:
                        port_range = f"{from_port}-{to_port}"
                elif protocol == 'icmp':
                    protocol_display = 'ICMP'
                    port_range = 'N/A'
                else:
                    protocol_display = protocol
                    if from_port or to_port:
                        if from_port == to_port:
                            port_range = str(from_port)
                        else:
                            port_range = f"{from_port}-{to_port}"
                    else:
                        port_range = 'All'
                
                # Add sources
                sources = []
                
                # IP ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    description = ip_range.get('Description', '')
                    
                    source_entry = {
                        'type': 'IPv4 CIDR',
                        'value': cidr,
                        'description': description
                    }
                    
                    # Flag if open to the internet
                    if cidr == '0.0.0.0/0':
                        source_entry['is_public'] = True
                        
                    sources.append(source_entry)
                
                # IPv6 ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    description = ipv6_range.get('Description', '')
                    
                    source_entry = {
                        'type': 'IPv6 CIDR',
                        'value': cidr,
                        'description': description
                    }
                    
                    # Flag if open to the internet
                    if cidr == '::/0':
                        source_entry['is_public'] = True
                        
                    sources.append(source_entry)
                    
                # Security group sources
                for sg_source in rule.get('UserIdGroupPairs', []):
                    source_entry = {
                        'type': 'Security Group',
                        'value': sg_source.get('GroupId', ''),
                        'description': sg_source.get('Description', '')
                    }
                    sources.append(source_entry)
                    
                # Prefix list sources
                for prefix_source in rule.get('PrefixListIds', []):
                    source_entry = {
                        'type': 'Prefix List',
                        'value': prefix_source.get('PrefixListId', ''),
                        'description': prefix_source.get('Description', '')
                    }
                    sources.append(source_entry)
                
                # Add rule to inbound_rules
                rule_entry = {
                    'protocol': protocol_display,
                    'port_range': port_range,
                    'sources': sources
                }
                inbound_rules.append(rule_entry)
            
            # Format outbound rules
            outbound_rules = []
            for rule in sg.get('IpPermissionsEgress', []):
                protocol = rule.get('IpProtocol', '')
                from_port = rule.get('FromPort', '')
                to_port = rule.get('ToPort', '')
                
                # Format protocol display
                if protocol == '-1':
                    protocol_display = 'All'
                    port_range = 'All'
                elif protocol == 'tcp':
                    protocol_display = 'TCP'
                    if from_port == to_port:
                        port_range = str(from_port)
                    else:
                        port_range = f"{from_port}-{to_port}"
                elif protocol == 'udp':
                    protocol_display = 'UDP'
                    if from_port == to_port:
                        port_range = str(from_port)
                    else:
                        port_range = f"{from_port}-{to_port}"
                elif protocol == 'icmp':
                    protocol_display = 'ICMP'
                    port_range = 'N/A'
                else:
                    protocol_display = protocol
                    if from_port or to_port:
                        if from_port == to_port:
                            port_range = str(from_port)
                        else:
                            port_range = f"{from_port}-{to_port}"
                    else:
                        port_range = 'All'
                
                # Add destinations
                destinations = []
                
                # IP ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    description = ip_range.get('Description', '')
                    
                    dest_entry = {
                        'type': 'IPv4 CIDR',
                        'value': cidr,
                        'description': description
                    }
                    
                    # Flag if open to the internet
                    if cidr == '0.0.0.0/0':
                        dest_entry['is_public'] = True
                        
                    destinations.append(dest_entry)
                
                # IPv6 ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    description = ipv6_range.get('Description', '')
                    
                    dest_entry = {
                        'type': 'IPv6 CIDR',
                        'value': cidr,
                        'description': description
                    }
                    
                    # Flag if open to the internet
                    if cidr == '::/0':
                        dest_entry['is_public'] = True
                        
                    destinations.append(dest_entry)
                    
                # Security group destinations
                for sg_dest in rule.get('UserIdGroupPairs', []):
                    dest_entry = {
                        'type': 'Security Group',
                        'value': sg_dest.get('GroupId', ''),
                        'description': sg_dest.get('Description', '')
                    }
                    destinations.append(dest_entry)
                    
                # Prefix list destinations
                for prefix_dest in rule.get('PrefixListIds', []):
                    dest_entry = {
                        'type': 'Prefix List',
                        'value': prefix_dest.get('PrefixListId', ''),
                        'description': prefix_dest.get('Description', '')
                    }
                    destinations.append(dest_entry)
                
                # Add rule to outbound_rules
                rule_entry = {
                    'protocol': protocol_display,
                    'port_range': port_range,
                    'destinations': destinations
                }
                outbound_rules.append(rule_entry)
            
            # Add security group to formatted_groups
            sg_entry = {
                'id': group_id,
                'name': group_name,
                'vpc_id': vpc_id,
                'description': description,
                'inbound_rules': inbound_rules,
                'outbound_rules': outbound_rules
            }
            formatted_groups.append(sg_entry)
        
        # Create summary and response
        result = {
            'security_groups': formatted_groups,
            'count': len(formatted_groups),
            'total_count': len(formatted_groups),  # For legacy compatibility
            'has_more': next_token_value is not None,
            'next_token': next_token_value
        }
        
        return json.dumps(result)
        
    except Exception as e:
        logger.error(f"Error listing security groups: {e}", exc_info=True)
        return json.dumps({
            'error': str(e),
            'security_groups': [],
            'count': 0,
            'total_count': 0,
            'has_more': False
        })


@register_tool()
async def list_vpcs(limit: Optional[int] = None, search_term: str = "", next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List VPCs with details.
    
    Args:
        limit: Maximum number of VPCs to return (None for all)
        search_term: Optional search term to filter VPCs by ID or CIDR
        next_token: Optional pagination token for fetching next page of results
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with VPC information
    """
    logger.info(f"Listing VPCs (limit={limit}, search_term='{search_term}', next_token={next_token}, session_context={session_context})")
    
    try:
        ec2_client = get_client("ec2", session_context=session_context)
        
        # Prepare parameters for the API call
        kwargs = {}
        
        # Add pagination token if provided
        if next_token:
            kwargs['NextToken'] = next_token
            
        # Add max results if limit is specified
        if limit:
            kwargs['MaxResults'] = min(limit, 1000)  # AWS API max is 1000
        
        # Get VPCs
        response = ec2_client.describe_vpcs(**kwargs)
        vpcs = response.get('Vpcs', [])
        
        # Filter VPCs based on search term if provided
        filtered_vpcs = []
        for vpc in vpcs:
            if search_term:
                # Convert all values to lowercase for case-insensitive search
                vpc_id = vpc.get('VpcId', '').lower()
                cidr_block = vpc.get('CidrBlock', '').lower()
                vpc_name = next((tag['Value'].lower() for tag in vpc.get('Tags', []) if tag['Key'].lower() == 'name'), '')
                search_lower = search_term.lower()
                
                # Skip if search term not found in any field
                if (search_lower not in vpc_id and
                    search_lower not in cidr_block and
                    search_lower not in vpc_name):
                    continue
            
            # Format VPC data
            formatted_vpc = {
                'id': vpc.get('VpcId'),
                'cidr_block': vpc.get('CidrBlock'),
                'state': vpc.get('State'),
                'is_default': vpc.get('IsDefault', False),
                'tags': {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])} if 'Tags' in vpc else {},
                'cidr_block_association_set': vpc.get('CidrBlockAssociationSet', []),
                'ipv6_cidr_block_association_set': vpc.get('Ipv6CidrBlockAssociationSet', []),
                'instance_tenancy': vpc.get('InstanceTenancy')
            }
            
            # Add name from tags if available
            formatted_vpc['name'] = next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), '')
            
            filtered_vpcs.append(formatted_vpc)
            
            # Check if we've reached the limit
            if limit and len(filtered_vpcs) >= limit:
                break
        
        # Extract next token for pagination
        next_token = response.get('NextToken')
        
        # Format the final result
        result = {
            'vpcs': filtered_vpcs,
            'count': len(filtered_vpcs),
            'has_more': bool(next_token),
            'next_token': next_token
        }
        
        return json.dumps(result, cls=CustomJSONEncoder)
    
    except Exception as e:
        error_message = f"Error listing VPCs: {str(e)}"
        logger.error(error_message, exc_info=True)
        return json.dumps({
            "error": error_message,
            "vpcs": [],
            "count": 0,
            "has_more": False
        })


@register_tool()
async def list_route_tables(limit: Optional[int] = None, search_term: str = "", next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List route tables with details.
    
    Args:
        limit: Maximum number of route tables to return (None for all)
        search_term: Optional search term to filter route tables by ID or VPC ID
        next_token: Optional pagination token for fetching next page of results
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with route table information
    """
    logger.info(f"Listing route tables (limit={limit}, search_term='{search_term}', next_token={next_token}, session_context={session_context})")
    
    try:
        ec2_client = get_client("ec2", session_context=session_context)
        
        # Prepare parameters for the API call
        kwargs = {}
        
        # Set up filters based on search term
        filters = None
        if search_term and (search_term.startswith("vpc:") or search_term.startswith("vpc-")):
            # Check if search is for a specific VPC
            if search_term.startswith("vpc:"):
                vpc_id = search_term.split(':', 1)[1]
            else:
                vpc_id = search_term
                
            filters = [{
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }]
            kwargs['Filters'] = filters
            search_term = ""  # Clear search term since we're using a filter
        
        # Add pagination token if provided
        if next_token:
            kwargs['NextToken'] = next_token
            
        # Add max results if limit is specified
        if limit:
            kwargs['MaxResults'] = min(limit, 1000)  # AWS API max is 1000
        
        # Get route tables
        response = ec2_client.describe_route_tables(**kwargs)
        route_tables = response.get('RouteTables', [])
        
        # Filter route tables based on search term if provided
        filtered_route_tables = []
        for rt in route_tables:
            if search_term:
                # Convert all values to lowercase for case-insensitive search
                rt_id = rt.get('RouteTableId', '').lower()
                vpc_id = rt.get('VpcId', '').lower()
                rt_name = next((tag['Value'].lower() for tag in rt.get('Tags', []) if tag['Key'].lower() == 'name'), '')
                search_lower = search_term.lower()
                
                # Skip if search term not found in any field
                if (search_lower not in rt_id and
                    search_lower not in vpc_id and
                    search_lower not in rt_name):
                    continue
            
            # Format route table data
            formatted_rt = {
                'id': rt.get('RouteTableId'),
                'vpc_id': rt.get('VpcId'),
                'routes': [
                    {
                        'destination_cidr_block': route.get('DestinationCidrBlock', ''),
                        'destination_ipv6_cidr_block': route.get('DestinationIpv6CidrBlock', ''),
                        'destination_prefix_list_id': route.get('DestinationPrefixListId', ''),
                        'gateway_id': route.get('GatewayId', ''),
                        'instance_id': route.get('InstanceId', ''),
                        'nat_gateway_id': route.get('NatGatewayId', ''),
                        'network_interface_id': route.get('NetworkInterfaceId', ''),
                        'vpc_peering_connection_id': route.get('VpcPeeringConnectionId', ''),
                        'state': route.get('State', '')
                    } for route in rt.get('Routes', [])
                ],
                'associations': [
                    {
                        'id': assoc.get('RouteTableAssociationId', ''),
                        'subnet_id': assoc.get('SubnetId', ''),
                        'gateway_id': assoc.get('GatewayId', ''),
                        'main': assoc.get('Main', False)
                    } for assoc in rt.get('Associations', [])
                ],
                'propagating_vgws': [vgw.get('GatewayId', '') for vgw in rt.get('PropagatingVgws', [])],
                'tags': {tag['Key']: tag['Value'] for tag in rt.get('Tags', [])} if 'Tags' in rt else {}
            }
            
            # Add name from tags if available
            formatted_rt['name'] = next((tag['Value'] for tag in rt.get('Tags', []) if tag['Key'] == 'Name'), '')
            
            # Check if this is the main route table
            formatted_rt['is_main'] = any(assoc.get('Main', False) for assoc in rt.get('Associations', []))
            
            # Determine if this route table has internet access
            formatted_rt['has_internet_access'] = any(
                route.get('GatewayId', '').startswith('igw-') for route in rt.get('Routes', [])
            )
            
            filtered_route_tables.append(formatted_rt)
            
            # Check if we've reached the limit
            if limit and len(filtered_route_tables) >= limit:
                break
        
        # Extract next token for pagination
        next_token = response.get('NextToken')
        
        # Format the final result
        result = {
            'route_tables': filtered_route_tables,
            'count': len(filtered_route_tables),
            'has_more': bool(next_token),
            'next_token': next_token
        }
        
        return json.dumps(result, cls=CustomJSONEncoder)
    
    except Exception as e:
        error_message = f"Error listing route tables: {str(e)}"
        logger.error(error_message, exc_info=True)
        return json.dumps({
            "error": error_message,
            "route_tables": [],
            "count": 0,
            "has_more": False
        })


@register_tool()
async def list_subnets(vpc_id: Optional[str] = None, include_details: bool = True, 
                      limit: Optional[int] = None, search_term: str = "", 
                      next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List all subnets in a VPC or across all VPCs.
    
    Args:
        vpc_id: Optional VPC ID to list subnets for. If None, lists subnets across all VPCs.
        include_details: Whether to include detailed subnet information (route tables, ACLs)
        limit: Maximum number of subnets to return (None for all)
        search_term: Optional text to filter subnets by ID, VPC ID, CIDR, or tags
        next_token: Optional pagination token for fetching next page of results
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with subnet information
    """
    logger.info(f"Listing subnets (vpc_id={vpc_id}, include_details={include_details}, limit={limit}, search_term='{search_term}', next_token={next_token}, session_context={session_context})")
    
    try:
        # Set up filters if VPC ID is provided
        filters = None
        if vpc_id:
            filters = [{
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }]
        
        if next_token:
            # If next_token is provided, we're requesting a specific page
            response = ec2.describe_subnets(
                filters=filters,
                next_token=next_token,
                session_context=session_context
            )
            
            subnets = response.get('Subnets', [])
            
            # Apply text search filter if provided
            if search_term:
                subnets = ec2.filter_subnets_by_text(subnets, search_term)
                
            next_token_value = response.get('NextToken')
        else:
            # No next_token provided, get with optional filtering
            if search_term:
                # Get all subnets and filter by text
                subnets = ec2.get_all_subnets(filters=filters, session_context=session_context)
                if search_term:
                    subnets = ec2.filter_subnets_by_text(subnets, search_term)
                next_token_value = None
            else:
                # Get all subnets if no search term
                response = ec2.describe_subnets(filters=filters, session_context=session_context)
                subnets = response.get('Subnets', [])
                next_token_value = response.get('NextToken')
        
        # Format response
        formatted_subnets = []
        
        for subnet in subnets:
            # Extract basic info
            subnet_id = subnet.get('SubnetId', '')
            subnet_vpc_id = subnet.get('VpcId', '')
            cidr_block = subnet.get('CidrBlock', '')
            availability_zone = subnet.get('AvailabilityZone', '')
            state = subnet.get('State', '')
            available_ip_count = subnet.get('AvailableIpAddressCount', 0)
            
            # Get public IP assignment setting
            map_public_ip = subnet.get('MapPublicIpOnLaunch', False)
            
            # Get name tag if available
            name = ''
            for tag in subnet.get('Tags', []):
                if tag.get('Key') == 'Name':
                    name = tag.get('Value', '')
                    break
            
            # Format tags
            tags = {}
            for tag in subnet.get('Tags', []):
                tags[tag.get('Key', '')] = tag.get('Value', '')
            
            # Create basic subnet details
            subnet_details = {
                'id': subnet_id,
                'name': name,
                'vpc_id': subnet_vpc_id,
                'cidr_block': cidr_block,
                'availability_zone': availability_zone,
                'state': state,
                'available_ip_count': available_ip_count,
                'map_public_ip_on_launch': map_public_ip,
                'tags': tags
            }
            
            # Add detailed information if requested
            if include_details:
                # Get route table associations for this subnet
                route_table_filters = [{
                    'Name': 'association.subnet-id',
                    'Values': [subnet_id]
                }]
                
                route_tables = ec2.get_all_route_tables(filters=route_table_filters, session_context=session_context)
                
                # Format route tables
                associated_route_tables = []
                for rt in route_tables:
                    rt_id = rt.get('RouteTableId', '')
                    
                    # Get association information
                    association = None
                    for assoc in rt.get('Associations', []):
                        if assoc.get('SubnetId') == subnet_id:
                            association = {
                                'id': assoc.get('RouteTableAssociationId', ''),
                                'main': assoc.get('Main', False)
                            }
                            break
                    
                    # Get name tag if available
                    rt_name = ''
                    for tag in rt.get('Tags', []):
                        if tag.get('Key') == 'Name':
                            rt_name = tag.get('Value', '')
                            break
                    
                    associated_route_tables.append({
                        'id': rt_id,
                        'name': rt_name,
                        'association': association
                    })
                
                subnet_details['route_tables'] = associated_route_tables
                
                # Get network ACLs for this subnet
                acl_filters = [{
                    'Name': 'association.subnet-id',
                    'Values': [subnet_id]
                }]
                
                acl_response = ec2.describe_network_acls(filters=acl_filters, session_context=session_context)
                acls = acl_response.get('NetworkAcls', [])
                
                # Format network ACLs
                associated_acls = []
                for acl in acls:
                    acl_id = acl.get('NetworkAclId', '')
                    is_default = acl.get('IsDefault', False)
                    
                    # Format entries
                    entries = []
                    for entry in acl.get('Entries', []):
                        entry_data = {
                            'rule_number': entry.get('RuleNumber', 0),
                            'protocol': entry.get('Protocol', ''),
                            'rule_action': entry.get('RuleAction', ''),
                            'egress': entry.get('Egress', False),
                            'cidr_block': entry.get('CidrBlock', '')
                        }
                        
                        # Add port range information if available
                        if 'PortRange' in entry:
                            entry_data['port_range'] = {
                                'from': entry.get('PortRange', {}).get('From', 0),
                                'to': entry.get('PortRange', {}).get('To', 0)
                            }
                            
                        entries.append(entry_data)
                    
                    # Get association information
                    association = None
                    for assoc in acl.get('Associations', []):
                        if assoc.get('SubnetId') == subnet_id:
                            association = {
                                'id': assoc.get('NetworkAclAssociationId', '')
                            }
                            break
                    
                    associated_acls.append({
                        'id': acl_id,
                        'is_default': is_default,
                        'association': association,
                        'entries': entries
                    })
                
                subnet_details['network_acls'] = associated_acls
            
            formatted_subnets.append(subnet_details)
        
        # Create summary and response
        result = {
            'subnets': formatted_subnets,
            'count': len(formatted_subnets),
            'total_count': len(formatted_subnets),  # For legacy compatibility
            'has_more': next_token_value is not None,
            'next_token': next_token_value
        }
        
        return json.dumps(result)
        
    except Exception as e:
        logger.error(f"Error listing subnets: {e}", exc_info=True)
        return json.dumps({
            'error': str(e),
            'subnets': [],
            'count': 0,
            'total_count': 0,
            'has_more': False
        })


@register_tool()
async def list_ec2_resources(resource_type: str = "all", limit: Optional[int] = None, 
                           search_term: str = "", state: str = "running", 
                           next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List EC2 resources of the specified type.
    
    Args:
        resource_type: Type of EC2 resource to list (instances, security_groups, vpcs, route_tables, subnets, or all)
        limit: Maximum number of resources to return (None for all)
        search_term: Optional search term to filter resources
        state: Instance state to filter by (default is "running"). Only applies to instances.
        next_token: Optional pagination token for fetching next page of results
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with EC2 resource information
    """
    logger.info(f"Listing EC2 resources (type={resource_type}, limit={limit}, search_term='{search_term}', state='{state}', next_token={next_token}, session_context={session_context})")
    
    try:
        # Normalize resource type
        resource_type = resource_type.lower()
        
        # Validate resource type
        valid_types = ["all", "instances", "security_groups", "vpcs", "route_tables", "subnets"]
        if resource_type not in valid_types:
            return json.dumps({
                "error": f"Invalid resource type: {resource_type}. Valid types are: {', '.join(valid_types)}"
            })
        
        if resource_type == "instances" or resource_type == "all":
            instances_result = await list_ec2_instances(limit=limit, search_term=search_term, state=state, next_token=next_token if resource_type == "instances" else None, session_context=session_context)
            instances_data = json.loads(instances_result)
        else:
            instances_data = {"instances": [], "count": 0, "has_more": False}
        
        if resource_type == "security_groups" or resource_type == "all":
            sg_result = await list_security_groups(limit=limit, search_term=search_term, next_token=next_token if resource_type == "security_groups" else None, session_context=session_context)
            sg_data = json.loads(sg_result)
        else:
            sg_data = {"security_groups": [], "count": 0, "has_more": False}
        
        if resource_type == "vpcs" or resource_type == "all":
            vpc_result = await list_vpcs(limit=limit, search_term=search_term, next_token=next_token if resource_type == "vpcs" else None, session_context=session_context)
            vpc_data = json.loads(vpc_result)
        else:
            vpc_data = {"vpcs": [], "count": 0, "has_more": False}
        
        if resource_type == "route_tables" or resource_type == "all":
            rt_result = await list_route_tables(limit=limit, search_term=search_term, next_token=next_token if resource_type == "route_tables" else None, session_context=session_context)
            rt_data = json.loads(rt_result)
        else:
            rt_data = {"route_tables": [], "count": 0, "has_more": False}
        
        if resource_type == "subnets" or resource_type == "all":
            subnet_result = await list_subnets(limit=limit, search_term=search_term, next_token=next_token if resource_type == "subnets" else None, session_context=session_context)
            subnet_data = json.loads(subnet_result)
        else:
            subnet_data = {"subnets": [], "count": 0, "has_more": False}
        
        # Build comprehensive result
        result = {
            "resource_type": resource_type,
            "instances": instances_data.get("instances", []) if resource_type in ["instances", "all"] else [],
            "security_groups": sg_data.get("security_groups", []) if resource_type in ["security_groups", "all"] else [],
            "vpcs": vpc_data.get("vpcs", []) if resource_type in ["vpcs", "all"] else [],
            "route_tables": rt_data.get("route_tables", []) if resource_type in ["route_tables", "all"] else [],
            "subnets": subnet_data.get("subnets", []) if resource_type in ["subnets", "all"] else [],
            "counts": {
                "instances": instances_data.get("count", 0) if resource_type in ["instances", "all"] else 0,
                "security_groups": sg_data.get("count", 0) if resource_type in ["security_groups", "all"] else 0,
                "vpcs": vpc_data.get("count", 0) if resource_type in ["vpcs", "all"] else 0,
                "route_tables": rt_data.get("count", 0) if resource_type in ["route_tables", "all"] else 0,
                "subnets": subnet_data.get("count", 0) if resource_type in ["subnets", "all"] else 0
            },
            "has_more": (
                (resource_type == "instances" and instances_data.get("has_more", False)) or
                (resource_type == "security_groups" and sg_data.get("has_more", False)) or
                (resource_type == "vpcs" and vpc_data.get("has_more", False)) or
                (resource_type == "route_tables" and rt_data.get("has_more", False)) or
                (resource_type == "subnets" and subnet_data.get("has_more", False))
            ),
            "next_token": (
                instances_data.get("next_token") if resource_type == "instances" and instances_data.get("has_more", False) else
                sg_data.get("next_token") if resource_type == "security_groups" and sg_data.get("has_more", False) else
                vpc_data.get("next_token") if resource_type == "vpcs" and vpc_data.get("has_more", False) else
                rt_data.get("next_token") if resource_type == "route_tables" and rt_data.get("has_more", False) else
                subnet_data.get("next_token") if resource_type == "subnets" and subnet_data.get("has_more", False) else
                None
            )
        }
        
        return json.dumps(result)
        
    except Exception as e:
        logger.error(f"Error listing EC2 resources: {e}", exc_info=True)
        return json.dumps({
            "error": str(e),
            "resource_type": resource_type,
            "instances": [],
            "security_groups": [],
            "vpcs": [],
            "route_tables": [],
            "subnets": [],
            "counts": {
                "instances": 0,
                "security_groups": 0,
                "vpcs": 0,
                "route_tables": 0,
                "subnets": 0
            },
            "has_more": False
        })


@register_tool()
async def find_public_security_groups(port: Optional[int] = None, session_context: Optional[str] = None) -> str:
    """Find security groups with public internet access (0.0.0.0/0).
    
    Args:
        port: Optional specific port to check for public access (e.g., 22 for SSH)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with security groups that allow public access
    """
    logger.info(f"Finding security groups with public internet access (port={port}, session_context={session_context})")
    
    try:
        # Get all security groups using pagination
        security_groups = []
        ec2_client = ec2.get_ec2_client(session_context=session_context)
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        # Iterate through all pages
        for page in paginator.paginate():
            security_groups.extend(page.get('SecurityGroups', []))
        
        # Filter security groups with public access
        public_sgs = []
        
        for sg in security_groups:
            is_public = False
            is_port_match = False
            
            # Check each inbound rule
            for rule in sg.get('IpPermissions', []):
                rule_protocol = rule.get('IpProtocol', '')
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                # Check if port matches if specified
                if port is not None:
                    if rule_protocol == '-1':  # All traffic
                        is_port_match = True
                    elif from_port is not None and to_port is not None:
                        if from_port <= port <= to_port:
                            is_port_match = True
                    else:
                        is_port_match = False
                else:
                    is_port_match = True  # No specific port to check
                
                # Check for public CIDR ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if cidr in ('0.0.0.0/0', '::/0'):
                        is_public = True
                        break
                
                # If we found a public rule matching our criteria, no need to check further
                if is_public and is_port_match:
                    public_sgs.append(sg)
                    break
        
        if not public_sgs:
            if port is not None:
                return json.dumps({"summary": f"No security groups found with public internet access on port {port}", "security_groups": []})
            else:
                return json.dumps({"summary": "No security groups found with public internet access", "security_groups": []})
        
        # Format the results with JSON objects instead of strings
        formatted_sgs = []
        for sg in public_sgs:
            # Create a structured JSON object for each security group
            formatted_sg = {
                "id": sg.get('GroupId'),
                "name": sg.get('GroupName'),
                "description": sg.get('Description'),
                "vpc_id": sg.get('VpcId'),
                "inbound_rules_count": len(sg.get('IpPermissions', [])),
                "outbound_rules_count": len(sg.get('IpPermissionsEgress', [])),
                "tags": {tag.get('Key'): tag.get('Value') for tag in sg.get('Tags', [])},
                "inbound_rules": []
            }
            
            # Format inbound rules
            for rule in sg.get('IpPermissions', []):
                protocol = rule.get('IpProtocol', '-1')
                
                # Handle protocol display
                if protocol == '-1':
                    protocol_display = 'All Traffic'
                elif protocol == '6':
                    protocol_display = 'TCP'
                elif protocol == '17':
                    protocol_display = 'UDP'
                elif protocol == '1':
                    protocol_display = 'ICMP'
                else:
                    protocol_display = protocol.upper()
                
                # Handle port range display
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                if protocol == '-1':
                    port_range = 'All'
                elif from_port is None or to_port is None:
                    port_range = 'N/A'
                elif from_port == to_port:
                    port_range = str(from_port)
                else:
                    port_range = f"{from_port}-{to_port}"
                
                # Process IP ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    description = ip_range.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "source": cidr,
                        "description": description,
                        "type": "IPv4"
                    }
                    
                    formatted_sg["inbound_rules"].append(formatted_rule)
                
                # Process IPv6 ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    description = ipv6_range.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "source": cidr,
                        "description": description,
                        "type": "IPv6"
                    }
                    
                    formatted_sg["inbound_rules"].append(formatted_rule)
            
            formatted_sgs.append(formatted_sg)
        
        summary = f"Found {len(public_sgs)} security group(s) with public internet access"
        if port is not None:
            summary += f" on port {port}"
        
        return json.dumps({"summary": summary, "security_groups": formatted_sgs})
    except Exception as e:
        logger.error(f"Error finding public security groups: {e}")
        return json.dumps({"error": {"message": f"Error finding public security groups: {str(e)}", "type": type(e).__name__}})


@register_tool()
async def find_instances_with_public_access(port: Optional[int] = None, state: str = "running", session_context: Optional[str] = None) -> str:
    """Find EC2 instances that have public internet access through their security groups.
    
    Args:
        port: Optional specific port to check for public access (e.g., 22 for SSH)
        state: Instance state to filter by (default is "running")
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with publicly accessible instances
    """
    logger.info(f"Finding EC2 instances with public access (port={port}, state='{state}', session_context={session_context})")
    
    try:
        # Get all instances in the specified state - pass session_context to ec2 service calls
        states = [state] if state else None
        instances = ec2.get_all_instances(max_items=None, states=states, session_context=session_context)
        
        # Get all security groups - pass session_context to ec2 service calls
        security_groups = ec2.get_all_security_groups(max_items=None, session_context=session_context)
        
        # Create lookup dictionary for security groups
        sg_dict = {sg.get('GroupId'): sg for sg in security_groups}
        
        # Track publicly accessible instances and their exposed ports
        public_instances = []
        
        # Process each instance
        for instance in instances:
            instance_id = instance.get('InstanceId')
            
            # Extract instance security groups
            instance_sgs = instance.get('SecurityGroups', [])
            
            # Check each security group for public access rules
            public_ports = []
            public_sg_ids = []
            
            for instance_sg in instance_sgs:
                sg_id = instance_sg.get('GroupId')
                
                # Get the full security group details
                sg = sg_dict.get(sg_id)
                if not sg:
                    continue
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    # Check if this matches our target port if specified
                    if port is not None:
                        # Skip rules that don't match our port
                        # Handle protocol -1 (all traffic)
                        if rule.get('IpProtocol') != '-1':
                            from_port = rule.get('FromPort')
                            to_port = rule.get('ToPort')
                            
                            # Skip if port is not in range
                            if from_port is not None and to_port is not None:
                                if port < from_port or port > to_port:
                                    continue
                    
                    # Check for public CIDR ranges
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            # This rule allows public access
                            if rule.get('IpProtocol') == '-1':
                                # All ports
                                public_ports.append('ALL')
                            elif rule.get('FromPort') == rule.get('ToPort'):
                                # Single port
                                public_ports.append(str(rule.get('FromPort')))
                            else:
                                # Port range
                                public_ports.append(f"{rule.get('FromPort')}-{rule.get('ToPort')}")
                            
                            # Track the security group ID
                            if sg_id not in public_sg_ids:
                                public_sg_ids.append(sg_id)
                    
                    # Check IPv6 ranges too
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        cidr = ipv6_range.get('CidrIpv6', '')
                        if cidr == '::/0':
                            # This rule allows public IPv6 access
                            if rule.get('IpProtocol') == '-1':
                                # All ports
                                public_ports.append('ALL (IPv6)')
                            elif rule.get('FromPort') == rule.get('ToPort'):
                                # Single port
                                public_ports.append(f"{rule.get('FromPort')} (IPv6)")
                            else:
                                # Port range
                                public_ports.append(f"{rule.get('FromPort')}-{rule.get('ToPort')} (IPv6)")
                            
                            # Track the security group ID
                            if sg_id not in public_sg_ids:
                                public_sg_ids.append(sg_id)
            
            # If we found public access ports for this instance, add it to our list
            if public_ports:
                # Extract name tag
                name = None
                for tag in instance.get('Tags', []):
                    if tag.get('Key') == 'Name':
                        name = tag.get('Value')
                        break
                
                # Get IAM Instance Profile information
                iam_profile_info = None
                if instance.get('IamInstanceProfile'):
                    iam_profile = instance.get('IamInstanceProfile', {})
                    iam_profile_info = {
                        "id": iam_profile.get('Id'),
                        "arn": iam_profile.get('Arn')
                    }
                
                # Format the instance details
                instance_details = {
                    "id": instance_id,
                    "name": name,
                    "type": instance.get('InstanceType'),
                    "state": instance.get('State', {}).get('Name'),
                    "private_ip": instance.get('PrivateIpAddress'),
                    "public_ip": instance.get('PublicIpAddress'),
                    "vpc_id": instance.get('VpcId'),
                    "subnet_id": instance.get('SubnetId'),
                    "public_ports": public_ports,
                    "public_security_groups": public_sg_ids,
                    "iam_instance_profile": iam_profile_info
                }
                
                public_instances.append(instance_details)
        
        # Build the summary message
        if port is not None:
            summary = f"Found {len(public_instances)} {state} instances with public access on port {port}"
        else:
            summary = f"Found {len(public_instances)} {state} instances with public internet access"
        
        # Build the final response
        result = {
            "summary": summary,
            "count": len(public_instances),
            "instances": public_instances
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error finding instances with public access: {e}")
        return json.dumps({"error": f"Error finding instances with public access: {str(e)}"})


@register_tool()
async def find_resource_by_ip(ip_address: str, session_context: Optional[str] = None) -> str:
    """Find AWS resources associated with a specific IP address.
    
    Args:
        ip_address: IP address to search for (public or private)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with information about resources using the IP address
    """
    logger.info(f"Searching for resources with IP address: {ip_address}")
    
    try:
        # Get EC2 client - pass session_context to get cross-account access
        client = ec2.get_ec2_client(session_context=session_context)
        
        # Try to find ENIs with this IP
        private_ip_filters = [
            {'Name': 'private-ip-address', 'Values': [ip_address]}
        ]
        
        # First check for private IPs
        private_response = client.describe_network_interfaces(Filters=private_ip_filters)
        interfaces = private_response.get('NetworkInterfaces', [])
        
        # If not found as private IP, check for public IPs
        if not interfaces:
            logger.info(f"IP {ip_address} not found as private IP, checking public IPs")
            public_ip_filters = [
                {'Name': 'association.public-ip', 'Values': [ip_address]}
            ]
            public_response = client.describe_network_interfaces(Filters=public_ip_filters)
            interfaces = public_response.get('NetworkInterfaces', [])
        
        if not interfaces:
            return json.dumps({"summary": f"No resources found with IP address {ip_address}"})
        
        # Process the results
        results = []
        for eni in interfaces:
            eni_id = eni.get('NetworkInterfaceId', 'Unknown')
            subnet_id = eni.get('SubnetId', 'Unknown')
            vpc_id = eni.get('VpcId', 'Unknown')
            private_ip = eni.get('PrivateIpAddress', 'Unknown')
            
            # Get public IP if available
            public_ip = None
            association = eni.get('Association', {})
            if association:
                public_ip = association.get('PublicIp')
            
            # Determine the resource type and ID
            resource_type = "Unknown"
            resource_id = "Unknown"
            
            attachment = eni.get('Attachment', {})
            if attachment:
                instance_id = attachment.get('InstanceId')
                if instance_id:
                    resource_type = "EC2 Instance"
                    resource_id = instance_id
                    
                    # Get instance details
                    try:
                        instance_response = client.describe_instances(InstanceIds=[instance_id])
                        reservations = instance_response.get('Reservations', [])
                        if reservations and reservations[0].get('Instances'):
                            instance = reservations[0]['Instances'][0]
                            instance_name = None
                            for tag in instance.get('Tags', []):
                                if tag.get('Key') == 'Name':
                                    instance_name = tag.get('Value')
                                    break
                            
                            if instance_name:
                                resource_id = f"{instance_id} ({instance_name})"
                    except Exception as e:
                        logger.warning(f"Error getting instance details: {e}")
            
            # Check for other resource types
            owner_id = eni.get('RequesterId')
            description = eni.get('Description', '')
            
            if description and owner_id:
                # Check for ELB
                if 'ELB' in description or 'elasticloadbalancing' in owner_id:
                    resource_type = "Elastic Load Balancer"
                    resource_id = description
                # Check for RDS
                elif 'RDS' in description or 'rds.amazonaws.com' in owner_id:
                    resource_type = "RDS Database"
                    resource_id = description
                # Check for Lambda
                elif 'lambda' in description.lower() or 'lambda' in owner_id.lower():
                    resource_type = "Lambda Function"
                    resource_id = description
                # Check for NAT Gateway
                elif 'NAT' in description or 'nat-' in description:
                    resource_type = "NAT Gateway"
                    resource_id = description
                # Check for ECS tasks
                elif 'ecs-tasks' in owner_id:
                    resource_type = "ECS Task"
                    resource_id = description
            
            # Format the result
            result = {
                "ip_address": ip_address,
                "private_ip": private_ip if private_ip != ip_address and private_ip != "Unknown" else None,
                "public_ip": public_ip if public_ip and public_ip != ip_address else None,
                "network_interface": eni_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "vpc": vpc_id,
                "subnet": subnet_id,
                "status": eni.get('Status', 'Unknown'),
                "description": description if description else None,
                "security_groups": [
                    {
                        "id": sg.get('GroupId', 'Unknown'),
                        "name": sg.get('GroupName', 'Unknown')
                    }
                    for sg in eni.get('Groups', [])
                ]
            }
            
            results.append(result)
        
        summary = f"Found {len(interfaces)} resource(s) with IP address {ip_address}"
        return json.dumps({"summary": summary, "resources": results})
    except Exception as e:
        logger.error(f"Error finding resources by IP: {e}")
        return json.dumps({"error": {"message": f"Error searching for IP address {ip_address}: {str(e)}", "type": type(e).__name__}})


@register_tool()
async def find_instances_by_port(port: int, state: str = "running", session_context: Optional[str] = None) -> str:
    """Find EC2 instances with security groups allowing access on a specific port.
    
    Args:
        port: The port number to check for
        state: Instance state to filter by (default is "running")
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with instances that have the specified port open
    """
    logger.info(f"Finding EC2 instances with port {port} open (state='{state}', session_context={session_context})")
    
    try:
        # Get all instances in the specified state - pass session_context to ec2 service calls
        states = [state] if state else None
        instances = ec2.get_all_instances(max_items=None, states=states, session_context=session_context)
        
        # Get all security groups - pass session_context to ec2 service calls
        security_groups = ec2.get_all_security_groups(max_items=None, session_context=session_context)
        
        # Identify security groups that allow the specified port
        port_open_sg_ids = []
        
        for sg in security_groups:
            sg_id = sg.get('GroupId')
            
            # Check inbound rules
            for rule in sg.get('IpPermissions', []):
                # All traffic (-1) allows any port
                if rule.get('IpProtocol') == '-1':
                    port_open_sg_ids.append(sg_id)
                    break
                
                # For TCP/UDP protocols, check port range
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                # Check if port is in range (if both ports are defined)
                if from_port is not None and to_port is not None:
                    if from_port <= port <= to_port:
                        port_open_sg_ids.append(sg_id)
                        break
        
        # Create lookup dictionary for security groups
        sg_dict = {sg.get('GroupId'): sg for sg in security_groups}
        
        # Find instances with the open port
        port_open_instances = []
        
        for instance in instances:
            instance_id = instance.get('InstanceId')
            
            # Extract instance security groups
            instance_sgs = instance.get('SecurityGroups', [])
            
            # Check if any of the instance's security groups allow the port
            instance_open_sg_ids = []
            
            for instance_sg in instance_sgs:
                sg_id = instance_sg.get('GroupId')
                
                if sg_id in port_open_sg_ids:
                    instance_open_sg_ids.append(sg_id)
            
            # If we found security groups allowing this port, add the instance to our list
            if instance_open_sg_ids:
                # Extract name tag
                name = None
                for tag in instance.get('Tags', []):
                    if tag.get('Key') == 'Name':
                        name = tag.get('Value')
                        break
                
                # Get IAM Instance Profile information
                iam_profile_info = None
                if instance.get('IamInstanceProfile'):
                    iam_profile = instance.get('IamInstanceProfile', {})
                    iam_profile_info = {
                        "id": iam_profile.get('Id'),
                        "arn": iam_profile.get('Arn')
                    }
                
                # Format the instance details
                instance_details = {
                    "id": instance_id,
                    "name": name,
                    "type": instance.get('InstanceType'),
                    "state": instance.get('State', {}).get('Name'),
                    "private_ip": instance.get('PrivateIpAddress'),
                    "public_ip": instance.get('PublicIpAddress'),
                    "vpc_id": instance.get('VpcId'),
                    "subnet_id": instance.get('SubnetId'),
                    "security_groups_with_port_open": instance_open_sg_ids,
                    "iam_instance_profile": iam_profile_info
                }
                
                # Get security group details
                sg_details = []
                for sg_id in instance_open_sg_ids:
                    sg = sg_dict.get(sg_id)
                    if sg:
                        sg_detail = {
                            "id": sg_id,
                            "name": sg.get('GroupName'),
                            "description": sg.get('Description'),
                            "rules": []
                        }
                        
                        # Add rules that include the port
                        for rule in sg.get('IpPermissions', []):
                            # Check if rule includes the port
                            if rule.get('IpProtocol') == '-1' or (rule.get('FromPort', float('inf')) <= port <= rule.get('ToPort', float('-inf'))):
                                sg_detail["rules"].append({
                                    "protocol": rule.get('IpProtocol'),
                                    "port_range": f"{rule.get('FromPort')}-{rule.get('ToPort')}" if rule.get('FromPort') != rule.get('ToPort') else str(rule.get('FromPort')),
                                    "sources": [cidr.get('CidrIp') for cidr in rule.get('IpRanges', [])]
                                })
                        
                        sg_details.append(sg_detail)
                
                instance_details["security_group_details"] = sg_details
                port_open_instances.append(instance_details)
        
        # Build the summary message
        summary = f"Found {len(port_open_instances)} {state} instances with port {port} open"
        
        # Build the final response
        result = {
            "summary": summary,
            "count": len(port_open_instances),
            "instances": port_open_instances
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error finding instances by port: {e}")
        return json.dumps({"error": f"Error finding instances by port: {str(e)}"})


@register_tool()
async def find_security_groups_by_port(port: int, session_context: Optional[str] = None) -> str:
    """Find security groups with a specific port open.
    
    Args:
        port: Port number to check for (e.g., 22 for SSH, 3389 for RDP)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with security groups that have the specified port open
    """
    logger.info(f"Finding security groups with port {port} open (session_context={session_context})")
    
    try:
        # Get all security groups using pagination
        security_groups = []
        ec2_client = ec2.get_ec2_client(session_context=session_context)
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        # Iterate through all pages
        for page in paginator.paginate():
            security_groups.extend(page.get('SecurityGroups', []))
        
        # Filter security groups with the specified port open
        matching_sgs = []
        
        for sg in security_groups:
            is_port_match = False
            
            # Check each inbound rule
            for rule in sg.get('IpPermissions', []):
                rule_protocol = rule.get('IpProtocol', '')
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                # Check if port matches
                if rule_protocol == '-1':  # All traffic
                    is_port_match = True
                elif from_port is not None and to_port is not None:
                    if from_port <= port <= to_port:
                        is_port_match = True
                
                # If we found a rule matching our criteria, no need to check further
                if is_port_match:
                    matching_sgs.append(sg)
                    break
        
        if not matching_sgs:
            return json.dumps({"summary": f"No security groups found with port {port} open", "security_groups": []})
        
        # Format the results with JSON objects instead of strings
        formatted_sgs = []
        for sg in matching_sgs:
            # Create a structured JSON object for each security group
            formatted_sg = {
                "id": sg.get('GroupId'),
                "name": sg.get('GroupName'),
                "description": sg.get('Description'),
                "vpc_id": sg.get('VpcId'),
                "inbound_rules_count": len(sg.get('IpPermissions', [])),
                "outbound_rules_count": len(sg.get('IpPermissionsEgress', [])),
                "tags": {tag.get('Key'): tag.get('Value') for tag in sg.get('Tags', [])},
                "inbound_rules": []
            }
            
            # Format inbound rules
            for rule in sg.get('IpPermissions', []):
                protocol = rule.get('IpProtocol', '-1')
                
                # Handle protocol display
                if protocol == '-1':
                    protocol_display = 'All Traffic'
                elif protocol == '6':
                    protocol_display = 'TCP'
                elif protocol == '17':
                    protocol_display = 'UDP'
                elif protocol == '1':
                    protocol_display = 'ICMP'
                else:
                    protocol_display = protocol.upper()
                
                # Handle port range display
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                if protocol == '-1':
                    port_range = 'All'
                elif from_port is None or to_port is None:
                    port_range = 'N/A'
                elif from_port == to_port:
                    port_range = str(from_port)
                else:
                    port_range = f"{from_port}-{to_port}"
                
                # Process IP ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    description = ip_range.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "source": cidr,
                        "description": description,
                        "type": "IPv4"
                    }
                    
                    formatted_sg["inbound_rules"].append(formatted_rule)
                
                # Process IPv6 ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    description = ipv6_range.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "source": cidr,
                        "description": description,
                        "type": "IPv6"
                    }
                    
                    formatted_sg["inbound_rules"].append(formatted_rule)
            
            formatted_sgs.append(formatted_sg)
        
        summary = f"Found {len(matching_sgs)} security group(s) with port {port} open"
        
        return json.dumps({"summary": summary, "security_groups": formatted_sgs})
    except Exception as e:
        logger.error(f"Error finding security groups by port: {e}")
        return json.dumps({"error": {"message": f"Error finding security groups by port: {str(e)}", "type": type(e).__name__}})


@register_tool()
async def batch_describe_security_groups(security_group_ids: List[str], session_context: Optional[str] = None) -> str:
    """Batch describe multiple security groups by ID.
    
    Args:
        security_group_ids: List of security group IDs to describe
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with detailed information about multiple security groups
    """
    logger.info(f"Batch describing {len(security_group_ids)} security groups (session_context={session_context})")
    
    if not security_group_ids:
        return json.dumps({"error": "No security group IDs provided"})
    
    try:
        # EC2 API can accept multiple security group IDs in a single call
        # But we'll batch in smaller chunks to be safe
        batch_size = 100
        all_security_groups = []
        not_found_sgs = []
        
        client = ec2.get_ec2_client(session_context=session_context)
        
        # Process in batches
        for i in range(0, len(security_group_ids), batch_size):
            batch = security_group_ids[i:i+batch_size]
            
            try:
                response = client.describe_security_groups(GroupIds=batch)
                
                # Extract security groups
                security_groups = response.get('SecurityGroups', [])
                all_security_groups.extend(security_groups)
                
                # Check if any security groups were not found
                found_ids = set()
                for sg in security_groups:
                    found_ids.add(sg.get('GroupId'))
                    
                for sg_id in batch:
                    if sg_id not in found_ids:
                        not_found_sgs.append(sg_id)
                
            except Exception as batch_error:
                logger.warning(f"Error describing batch {i//batch_size}: {batch_error}")
                # If the error is due to non-existent security groups, extract those IDs
                error_message = str(batch_error)
                if "InvalidGroup.NotFound" in error_message or "InvalidGroupId.Malformed" in error_message:
                    # Try to extract the security group IDs from the error message
                    import re
                    missing_ids = re.findall(r'sg-[a-zA-Z0-9]+', error_message)
                    if missing_ids:
                        not_found_sgs.extend(missing_ids)
                    else:
                        # If we can't extract IDs, mark all as not found
                        not_found_sgs.extend(batch)
                else:
                    # For other errors, mark all in this batch as failed
                    not_found_sgs.extend(batch)
        
        # Format the results
        formatted_sgs = []
        for sg in all_security_groups:
            formatted_sg = {
                "id": sg.get('GroupId'),
                "name": sg.get('GroupName'),
                "description": sg.get('Description'),
                "vpc_id": sg.get('VpcId'),
                "tags": {tag.get('Key'): tag.get('Value') for tag in sg.get('Tags', [])},
                "inbound_rules": [],
                "outbound_rules": []
            }
            
            # Format inbound rules
            for rule in sg.get('IpPermissions', []):
                protocol = rule.get('IpProtocol', '-1')
                
                # Handle protocol display
                if protocol == '-1':
                    protocol_display = 'All Traffic'
                elif protocol == '6':
                    protocol_display = 'TCP'
                elif protocol == '17':
                    protocol_display = 'UDP'
                elif protocol == '1':
                    protocol_display = 'ICMP'
                else:
                    protocol_display = protocol.upper()
                
                # Handle port range display
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                if protocol == '-1':
                    port_range = 'All'
                elif from_port is None or to_port is None:
                    port_range = 'N/A'
                elif from_port == to_port:
                    port_range = str(from_port)
                else:
                    port_range = f"{from_port}-{to_port}"
                
                # Process IP ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    description = ip_range.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "source": cidr,
                        "description": description,
                        "type": "IPv4"
                    }
                    
                    formatted_sg["inbound_rules"].append(formatted_rule)
                
                # Process IPv6 ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    description = ipv6_range.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "source": cidr,
                        "description": description,
                        "type": "IPv6"
                    }
                    
                    formatted_sg["inbound_rules"].append(formatted_rule)
                
                # Process security group references
                for group_pair in rule.get('UserIdGroupPairs', []):
                    group_id = group_pair.get('GroupId', '')
                    description = group_pair.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "source": f"sg-{group_id}" if not group_id.startswith('sg-') else group_id,
                        "description": description,
                        "type": "Security Group"
                    }
                    
                    formatted_sg["inbound_rules"].append(formatted_rule)
            
            # Format outbound rules (similar logic as inbound rules)
            for rule in sg.get('IpPermissionsEgress', []):
                protocol = rule.get('IpProtocol', '-1')
                
                # Handle protocol display
                if protocol == '-1':
                    protocol_display = 'All Traffic'
                elif protocol == '6':
                    protocol_display = 'TCP'
                elif protocol == '17':
                    protocol_display = 'UDP'
                elif protocol == '1':
                    protocol_display = 'ICMP'
                else:
                    protocol_display = protocol.upper()
                
                # Handle port range display
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                if protocol == '-1':
                    port_range = 'All'
                elif from_port is None or to_port is None:
                    port_range = 'N/A'
                elif from_port == to_port:
                    port_range = str(from_port)
                else:
                    port_range = f"{from_port}-{to_port}"
                
                # Process IP ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    description = ip_range.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "destination": cidr,
                        "description": description,
                        "type": "IPv4"
                    }
                    
                    formatted_sg["outbound_rules"].append(formatted_rule)
                
                # Process IPv6 ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    description = ipv6_range.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "destination": cidr,
                        "description": description,
                        "type": "IPv6"
                    }
                    
                    formatted_sg["outbound_rules"].append(formatted_rule)
                
                # Process security group references
                for group_pair in rule.get('UserIdGroupPairs', []):
                    group_id = group_pair.get('GroupId', '')
                    description = group_pair.get('Description', '')
                    
                    formatted_rule = {
                        "protocol": protocol_display,
                        "port_range": port_range,
                        "destination": f"sg-{group_id}" if not group_id.startswith('sg-') else group_id,
                        "description": description,
                        "type": "Security Group"
                    }
                    
                    formatted_sg["outbound_rules"].append(formatted_rule)
            
            formatted_sgs.append(formatted_sg)
            
        # Build the final response
        result = {
            "summary": f"Found {len(formatted_sgs)} of {len(security_group_ids)} requested security groups",
            "security_groups": formatted_sgs,
            "count": len(formatted_sgs),
            "not_found": not_found_sgs,
            "not_found_count": len(not_found_sgs)
        }
        
        return json.dumps(result, default=lambda o: o.isoformat() if hasattr(o, 'isoformat') else str(o))
        
    except Exception as e:
        logger.error(f"Error batch describing security groups: {e}")
        return json.dumps({"error": {"message": f"Error batch describing security groups: {str(e)}", "type": type(e).__name__}})


@register_tool()
async def batch_describe_instances(instance_ids: List[str], session_context: Optional[str] = None) -> str:
    """Batch describe multiple EC2 instances by ID.
    
    Args:
        instance_ids: List of EC2 instance IDs to describe
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON formatted string with detailed information about multiple EC2 instances
    """
    logger.info(f"Batch describing {len(instance_ids)} EC2 instances (session_context={session_context})")
    
    if not instance_ids:
        return json.dumps({"error": "No instance IDs provided"})
    
    try:
        all_instances = []
        not_found_instances = []
        
        # Get EC2 client - pass session_context to get cross-account access
        client = ec2.get_ec2_client(session_context=session_context)
        
        # The EC2 API has a limit of 1000 IDs per call, so we need to batch
        # This isn't limiting the results, just working within API constraints
        max_ids_per_request = 1000  # AWS API limit
        
        # Process all instance IDs in necessary batches
        for i in range(0, len(instance_ids), max_ids_per_request):
            batch = instance_ids[i:i+max_ids_per_request]
            
            try:
                response = client.describe_instances(InstanceIds=batch)
                
                # Extract instances from reservations
                found_instances = []
                for reservation in response.get('Reservations', []):
                    found_instances.extend(reservation.get('Instances', []))
                
                # Add to our cumulative list
                all_instances.extend(found_instances)
                
                # Check if any instance IDs were not found
                found_ids = set(instance.get('InstanceId') for instance in found_instances)
                for instance_id in batch:
                    if instance_id not in found_ids:
                        not_found_instances.append(instance_id)
                
            except Exception as batch_error:
                logger.warning(f"Error describing batch {i//max_ids_per_request}: {batch_error}")
                # If the error is due to non-existent instances, extract those IDs
                error_message = str(batch_error)
                if "InvalidInstanceID.NotFound" in error_message:
                    # Try to extract the instance IDs from the error message
                    import re
                    missing_ids = re.findall(r'i-[a-zA-Z0-9]+', error_message)
                    if missing_ids:
                        not_found_instances.extend(missing_ids)
                    else:
                        # If we can't extract IDs, mark all as not found
                        not_found_instances.extend(batch)
                else:
                    # For other errors, mark all in this batch as failed
                    not_found_instances.extend(batch)
        
        # Format the results - no limiting of results here
        formatted_instances = []
        for instance in all_instances:
            # Extract name tag if available
            name = None
            for tag in instance.get('Tags', []):
                if tag.get('Key') == 'Name':
                    name = tag.get('Value')
                    break
            
            # Basic instance details
            formatted_instance = {
                "id": instance.get('InstanceId'),
                "name": name,
                "type": instance.get('InstanceType'),
                "state": instance.get('State', {}).get('Name'),
                "private_ip": instance.get('PrivateIpAddress'),
                "public_ip": instance.get('PublicIpAddress'),
                "vpc_id": instance.get('VpcId'),
                "subnet_id": instance.get('SubnetId'),
                "image_id": instance.get('ImageId'),
                "availability_zone": instance.get('Placement', {}).get('AvailabilityZone'),
                "launch_time": instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                "key_name": instance.get('KeyName'),
                "monitoring": instance.get('Monitoring', {}).get('State'),
                "platform": instance.get('Platform'),
                "architecture": instance.get('Architecture'),
                "root_device_type": instance.get('RootDeviceType'),
                "root_device_name": instance.get('RootDeviceName'),
                "virtualization_type": instance.get('VirtualizationType'),
                "tags": {tag.get('Key'): tag.get('Value') for tag in instance.get('Tags', [])}
            }
            
            # Security groups - include ALL security groups
            formatted_instance["security_groups"] = [
                {
                    "id": sg.get('GroupId'),
                    "name": sg.get('GroupName')
                } for sg in instance.get('SecurityGroups', [])
            ]
            
            # IAM Instance Profile information if available
            if instance.get('IamInstanceProfile'):
                iam_profile = instance.get('IamInstanceProfile', {})
                formatted_instance["iam_instance_profile"] = {
                    "id": iam_profile.get('Id'),
                    "arn": iam_profile.get('Arn')
                }
            else:
                formatted_instance["iam_instance_profile"] = None
            
            # EBS volume information - include ALL volumes
            formatted_instance["ebs_volumes"] = []
            for block_device in instance.get('BlockDeviceMappings', []):
                if 'Ebs' in block_device:
                    volume_info = {
                        "device_name": block_device.get('DeviceName'),
                        "volume_id": block_device.get('Ebs', {}).get('VolumeId'),
                        "status": block_device.get('Ebs', {}).get('Status'),
                        "delete_on_termination": block_device.get('Ebs', {}).get('DeleteOnTermination', False),
                        "volume_type": block_device.get('Ebs', {}).get('VolumeType'),
                        "size_gb": block_device.get('Ebs', {}).get('Size'),
                        "encrypted": block_device.get('Ebs', {}).get('Encrypted', False),
                        "kms_key_id": block_device.get('Ebs', {}).get('KmsKeyId')
                    }
                    formatted_instance["ebs_volumes"].append(volume_info)
            
            # Network interfaces - include ALL interfaces
            formatted_instance["network_interfaces"] = []
            for eni in instance.get('NetworkInterfaces', []):
                eni_info = {
                    "id": eni.get('NetworkInterfaceId'),
                    "description": eni.get('Description'),
                    "subnet_id": eni.get('SubnetId'),
                    "vpc_id": eni.get('VpcId'),
                    "private_ip": eni.get('PrivateIpAddress'),
                    "private_dns_name": eni.get('PrivateDnsName'),
                    "status": eni.get('Status'),
                    "mac_address": eni.get('MacAddress'),
                    "security_groups": [
                        {
                            "id": sg.get('GroupId'),
                            "name": sg.get('GroupName')
                        } for sg in eni.get('Groups', [])
                    ],
                    "source_dest_check": eni.get('SourceDestCheck')
                }
                
                # Add all private IPs
                eni_info["private_ips"] = [
                    {
                        "ip": ip.get('PrivateIpAddress'),
                        "is_primary": ip.get('Primary', False)
                    } for ip in eni.get('PrivateIpAddresses', [])
                ]
                
                # Add public IP if available
                if eni.get('Association', {}).get('PublicIp'):
                    eni_info["public_ip"] = eni.get('Association', {}).get('PublicIp')
                    eni_info["public_dns_name"] = eni.get('Association', {}).get('PublicDnsName')
                
                formatted_instance["network_interfaces"].append(eni_info)
            
            # Product codes
            formatted_instance["product_codes"] = [
                {
                    "id": pc.get('ProductCodeId'),
                    "type": pc.get('ProductCodeType')
                } for pc in instance.get('ProductCodes', [])
            ]
            
            # CPU options
            if instance.get('CpuOptions'):
                formatted_instance["cpu_options"] = {
                    "cores": instance.get('CpuOptions', {}).get('CoreCount'),
                    "threads_per_core": instance.get('CpuOptions', {}).get('ThreadsPerCore')
                }
            
            # Instance lifecycle (spot, scheduled)
            if instance.get('InstanceLifecycle'):
                formatted_instance["lifecycle"] = instance.get('InstanceLifecycle')
                if instance.get('SpotInstanceRequestId'):
                    formatted_instance["spot_instance_request_id"] = instance.get('SpotInstanceRequestId')
            
            # State transition reason
            if instance.get('StateTransitionReason'):
                formatted_instance["state_transition_reason"] = instance.get('StateTransitionReason')
            
            # Hypervisor information
            if instance.get('Hypervisor'):
                formatted_instance["hypervisor"] = instance.get('Hypervisor')
            
            # ENA support
            if 'EnaSupport' in instance:
                formatted_instance["ena_support"] = instance.get('EnaSupport')
            
            # Public DNS name
            if instance.get('PublicDnsName'):
                formatted_instance["public_dns_name"] = instance.get('PublicDnsName')
            
            # Private DNS name
            if instance.get('PrivateDnsName'):
                formatted_instance["private_dns_name"] = instance.get('PrivateDnsName')
            
            formatted_instances.append(formatted_instance)
        
        # Build the final response - all data included, no limits
        result = {
            "summary": f"Found {len(formatted_instances)} of {len(instance_ids)} requested EC2 instances",
            "instances": formatted_instances,
            "count": len(formatted_instances),
            "not_found": not_found_instances,
            "not_found_count": len(not_found_instances)
        }
        
        return json.dumps(result, default=lambda o: o.isoformat() if hasattr(o, 'isoformat') else str(o))
        
    except Exception as e:
        logger.error(f"Error batch describing EC2 instances: {e}")
        return json.dumps({"error": {"message": f"Error batch describing EC2 instances: {str(e)}", "type": type(e).__name__}})