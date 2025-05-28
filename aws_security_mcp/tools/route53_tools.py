"""Route53 tools for AWS Security MCP."""

import logging
import json
from typing import Optional, List, Dict, Any
import re

from aws_security_mcp.services import route53
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)

# Import EC2 services for IP lookup functionality
try:
    from aws_security_mcp.services import ec2
except ImportError:
    logger.warning("EC2 services module not available for IP lookups")


@register_tool("list_hosted_zones")
async def list_hosted_zones(limit: int = 100, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List Route53 hosted zones in the AWS account.
    
    Args:
        limit: Maximum number of hosted zones to return (default: 100)
        next_token: Token for pagination (from previous request)
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON string with Route53 hosted zones information
    """
    logger.info(f"Listing Route53 hosted zones (limit={limit}, next_token={next_token})")
    
    try:
        response = route53.list_hosted_zones(max_items=limit, next_token=next_token, session_context=session_context)
        zones = response.get("zones", [])
        next_token = response.get("next_token")
        is_truncated = response.get("is_truncated", False)
        
        formatted_zones = []
        for zone in zones:
            # Extract basic information
            zone_id = zone.get('Id', 'Unknown').replace('/hostedzone/', '')
            name = zone.get('Name', 'Unknown')
            record_count = zone.get('ResourceRecordSetCount', 0)
            private_zone = zone.get('Config', {}).get('PrivateZone', False)
            
            # Format as JSON object
            zone_data = {
                "zone_id": zone_id,
                "name": name,
                "record_count": record_count,
                "private_zone": private_zone
            }
            
            # Add comment if available
            comment = zone.get('Config', {}).get('Comment')
            if comment:
                zone_data["comment"] = comment
            
            formatted_zones.append(zone_data)
        
        result = {
            "summary": f"Found {len(zones)} Route53 hosted zone(s)",
            "count": len(zones),
            "zones": formatted_zones,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_token
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing Route53 hosted zones: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing Route53 hosted zones: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool("get_hosted_zone_details")
async def get_hosted_zone_details(zone_id: str, session_context: Optional[str] = None) -> str:
    """Get detailed information about a specific Route53 hosted zone.
    
    Args:
        zone_id: ID of the Route53 hosted zone (can include or exclude '/hostedzone/' prefix)
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON string with hosted zone details
    """
    logger.info(f"Getting details for Route53 hosted zone: {zone_id}")
    
    # Ensure zone_id has the proper format
    if not zone_id.startswith('/hostedzone/'):
        zone_id = f'/hostedzone/{zone_id}'
    
    try:
        zone = route53.get_hosted_zone(zone_id, session_context=session_context)
        
        if not zone:
            clean_id = zone_id.replace('/hostedzone/', '')
            return json.dumps({
                "error": {
                    "message": f"Route53 hosted zone '{clean_id}' not found",
                    "type": "ResourceNotFound"
                }
            })
        
        # Extract basic information
        clean_id = zone_id.replace('/hostedzone/', '')
        name = zone.get('HostedZone', {}).get('Name', 'Unknown')
        record_count = zone.get('HostedZone', {}).get('ResourceRecordSetCount', 0)
        private_zone = zone.get('HostedZone', {}).get('Config', {}).get('PrivateZone', False)
        
        # Add comment if available
        comment = zone.get('HostedZone', {}).get('Config', {}).get('Comment')
        
        # Format as JSON object
        result = {
            "zone_id": clean_id,
            "name": name,
            "record_count": record_count,
            "private_zone": private_zone
        }
        
        if comment:
            result["comment"] = comment
        
        # Add name servers
        name_servers = zone.get('DelegationSet', {}).get('NameServers', [])
        if name_servers:
            result["name_servers"] = name_servers
        
        # VPC Information for private zones
        vpcs = zone.get('VPCs', [])
        if vpcs:
            result["vpcs"] = []
            for vpc in vpcs:
                vpc_id = vpc.get('VPCId', 'Unknown')
                vpc_region = vpc.get('VPCRegion', 'Unknown')
                result["vpcs"].append({
                    "vpc_id": vpc_id,
                    "region": vpc_region
                })
        
        # Get tags
        tags = route53.get_hosted_zone_tags(zone_id, session_context=session_context)
        if tags:
            result["tags"] = tags
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error getting Route53 hosted zone details: {e}")
        clean_id = zone_id.replace('/hostedzone/', '')
        return json.dumps({
            "error": {
                "message": f"Error getting details for Route53 hosted zone '{clean_id}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool("list_resource_record_sets")
async def list_resource_record_sets(zone_id: str, limit: int = 100, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List resource record sets in a specific Route53 hosted zone.
    
    Args:
        zone_id: ID of the Route53 hosted zone (can include or exclude '/hostedzone/' prefix)
        limit: Maximum number of record sets to return per page (default: 100)
        next_token: Pagination token from a previous request (optional)
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON string with resource record sets and pagination information
    """
    logger.info(f"Listing resource record sets for Route53 hosted zone: {zone_id} (limit={limit}, next_token={next_token})")
    
    # Ensure zone_id has the proper format
    if not zone_id.startswith('/hostedzone/'):
        zone_id = f'/hostedzone/{zone_id}'
    
    try:
        response = route53.list_resource_record_sets(zone_id, max_items=limit, next_marker=next_token, session_context=session_context)
        records = response.get('records', [])
        next_marker = response.get('next_marker')
        is_truncated = response.get('is_truncated', False)
        
        if not records:
            clean_id = zone_id.replace('/hostedzone/', '')
            return json.dumps({
                "summary": f"No resource record sets found for Route53 hosted zone '{clean_id}'",
                "zone_id": clean_id,
                "count": 0,
                "records": []
            })
        
        formatted_records = []
        for record in records:
            # Extract basic information
            name = record.get('Name', 'Unknown')
            type_str = record.get('Type', 'Unknown')
            ttl = record.get('TTL', None)
            
            # Format as JSON object
            record_data = {
                "name": name,
                "type": type_str
            }
            
            if ttl is not None:
                record_data["ttl"] = ttl
            
            # Resource Records
            resource_records = record.get('ResourceRecords', [])
            if resource_records:
                record_data["values"] = [rr.get('Value', 'Unknown') for rr in resource_records]
            
            # Alias Target
            alias_target = record.get('AliasTarget', {})
            if alias_target:
                record_data["alias_target"] = {
                    "dns_name": alias_target.get('DNSName', 'Unknown'),
                    "hosted_zone_id": alias_target.get('HostedZoneId', 'Unknown'),
                    "evaluate_target_health": alias_target.get('EvaluateTargetHealth', False)
                }
            
            # Geo Location
            geo_location = record.get('GeoLocation', {})
            if geo_location:
                record_data["geo_location"] = {}
                if geo_location.get('ContinentCode'):
                    record_data["geo_location"]["continent_code"] = geo_location.get('ContinentCode')
                if geo_location.get('CountryCode'):
                    record_data["geo_location"]["country_code"] = geo_location.get('CountryCode')
                if geo_location.get('SubdivisionCode'):
                    record_data["geo_location"]["subdivision_code"] = geo_location.get('SubdivisionCode')
            
            # Health Check
            health_check_id = record.get('HealthCheckId')
            if health_check_id:
                record_data["health_check_id"] = health_check_id
            
            formatted_records.append(record_data)
        
        clean_id = zone_id.replace('/hostedzone/', '')
        result = {
            "summary": f"Found {len(records)} resource record set(s) for Route53 hosted zone '{clean_id}'",
            "zone_id": clean_id,
            "count": len(records),
            "records": formatted_records,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_marker
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing Route53 resource record sets: {e}")
        clean_id = zone_id.replace('/hostedzone/', '')
        return json.dumps({
            "error": {
                "message": f"Error listing resource record sets for Route53 hosted zone '{clean_id}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool("list_health_checks")
async def list_health_checks(limit: int = 100, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List Route53 health checks in the AWS account.
    
    Args:
        limit: Maximum number of health checks to return (default: 100)
        next_token: Token for pagination (from previous request)
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON string with Route53 health checks
    """
    logger.info(f"Listing Route53 health checks (limit={limit}, next_token={next_token})")
    
    try:
        health_checks_response = route53.list_health_checks(max_items=limit, next_token=next_token, session_context=session_context)
        health_checks = health_checks_response.get('health_checks', [])
        next_marker = health_checks_response.get('next_token')
        is_truncated = health_checks_response.get('is_truncated', False)
        
        if not health_checks:
            return json.dumps({
                "summary": "No Route53 health checks found",
                "count": 0,
                "health_checks": []
            })
        
        formatted_checks = []
        for health_check in health_checks:
            # Extract basic information
            health_check_id = health_check.get('Id', 'Unknown')
            caller_reference = health_check.get('CallerReference', 'Unknown')
            
            # Get health check config
            config = health_check.get('HealthCheckConfig', {})
            check_type = config.get('Type', 'Unknown')
            
            # Format as JSON object
            check_data = {
                "id": health_check_id,
                "type": check_type,
                "caller_reference": caller_reference,
                "request_interval": config.get('RequestInterval'),
                "failure_threshold": config.get('FailureThreshold')
            }
            
            # Add specific config based on type
            if check_type in ['HTTP', 'HTTPS', 'HTTP_STR_MATCH', 'HTTPS_STR_MATCH']:
                check_data["protocol"] = check_type.split('_')[0]
                check_data["host"] = config.get('FullyQualifiedDomainName')
                check_data["path"] = config.get('ResourcePath', '/')
                
                if 'STR_MATCH' in check_type:
                    check_data["search_string"] = config.get('SearchString')
            
            elif check_type == 'TCP':
                check_data["host"] = config.get('FullyQualifiedDomainName')
                check_data["port"] = config.get('Port')
            
            elif check_type == 'CALCULATED':
                check_data["child_health_checks"] = config.get('ChildHealthChecks', [])
            
            elif check_type == 'CLOUDWATCH_METRIC':
                check_data["cloudwatch"] = {
                    "alarm_name": config.get('AlarmName'),
                    "region": config.get('AlarmRegion')
                }
            
            # Add health check status
            status = health_check.get('HealthCheckStatus')
            if status:
                check_data["status"] = status
            
            formatted_checks.append(check_data)
        
        result = {
            "summary": f"Found {len(health_checks)} Route53 health check(s)",
            "count": len(health_checks),
            "health_checks": formatted_checks,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_marker
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing Route53 health checks: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing Route53 health checks: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool("list_traffic_policies")
async def list_traffic_policies(limit: int = 100, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List Route53 traffic policies in the AWS account.
    
    Args:
        limit: Maximum number of traffic policies to return (default: 100)
        next_token: Token for pagination (from previous request)
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON string with Route53 traffic policies
    """
    logger.info(f"Listing Route53 traffic policies (limit={limit}, next_token={next_token})")
    
    try:
        policies_response = route53.list_traffic_policies(max_items=limit, next_token=next_token, session_context=session_context)
        policies = policies_response.get('policies', [])
        next_marker = policies_response.get('next_token')
        is_truncated = policies_response.get('is_truncated', False)
        
        if not policies:
            return json.dumps({
                "summary": "No Route53 traffic policies found",
                "count": 0,
                "policies": []
            })
        
        formatted_policies = []
        for policy in policies:
            # Extract basic information
            policy_id = policy.get('Id', 'Unknown')
            policy_name = policy.get('Name', 'Unknown')
            version = policy.get('LatestVersion', 'Unknown')
            
            # Format as JSON object
            policy_data = {
                "id": policy_id,
                "name": policy_name,
                "latest_version": version
            }
            
            # Add comment if available
            comment = policy.get('Comment')
            if comment:
                policy_data["comment"] = comment
            
            formatted_policies.append(policy_data)
        
        result = {
            "summary": f"Found {len(policies)} Route53 traffic policy(s)",
            "count": len(policies),
            "policies": formatted_policies,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_marker
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing Route53 traffic policies: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing Route53 traffic policies: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool("check_subdomain_takeover_vulnerability")
async def check_subdomain_takeover_vulnerability(domain_name: str, session_context: Optional[str] = None) -> str:
    """Check if a specific domain or subdomain is vulnerable to subdomain takeover attacks.
    
    This function performs a DNS-based analysis for subdomain takeover vulnerabilities:
    1. Identifies all DNS records for the domain
    2. For CNAME records, checks if they point to services that could be vulnerable
    3. Analyzes DNS configurations for signs of abandoned or unclaimed resources
    
    Args:
        domain_name: The domain or subdomain name to check (e.g., xyz.dreamplug.in)
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON string with vulnerability assessment results
    """
    import socket
    import dns.resolver
    from urllib.parse import urlparse
    
    logger.info(f"Checking subdomain takeover vulnerability for: {domain_name}")
    
    # Define service patterns that are commonly vulnerable to takeover
    vulnerable_service_patterns = [
        # AWS Services
        's3.amazonaws.com',
        'cloudfront.net',
        'elasticbeanstalk.com',
        'amazonaws.com',
        'elb.amazonaws.com',  # Explicit check for ELB DNS names
        # GitHub & Git Services
        'github.io',
        'bitbucket.io',
        # PaaS providers
        'herokuapp.com',
        'azurewebsites.net',
        'netlify.app',
        'surge.sh',
        # CMS & Tools
        'shopify.com',
        'statuspage.io',
        'tumblr.com',
        'wpengine.com',
        'zendesk.com'
    ]
    
    # Function to check DNS resolution
    def check_dns_resolution(domain):
        try:
            socket.gethostbyname(domain)
            return {'status': 'ok', 'details': 'Domain resolves to an IP address', 'ip': socket.gethostbyname(domain)}
        except socket.gaierror:
            # Try with DNS resolver as a backup method
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ips = [rdata.address for rdata in answers]
                return {'status': 'ok', 'details': 'Domain resolves to an IP address', 'ip': ips[0] if ips else None}
            except Exception:
                return {'status': 'error', 'details': 'Domain does not resolve to an IP address'}
    
    # Function to analyze CNAME record for takeover patterns
    def analyze_cname_takeover_risk(cname_target):
        # Check if the CNAME points to a known potentially vulnerable service
        for pattern in vulnerable_service_patterns:
            if pattern in cname_target.lower():
                # Now check if the target domain resolves
                target_resolution = check_dns_resolution(cname_target.rstrip('.'))
                if target_resolution['status'] == 'error':
                    return {
                        'vulnerable': True,
                        'service': pattern,
                        'details': f"CNAME points to {pattern} but target does not resolve - potential subdomain takeover"
                    }
                
                # Special handling for ELB names
                if 'elb.amazonaws.com' in cname_target.lower():
                    # Import the load balancer tools module
                    from aws_security_mcp.services import load_balancer
                    
                    # Extract the load balancer name from the DNS
                    import re
                    
                    # Handle dualstack prefix if present
                    clean_target = cname_target.lower()
                    if clean_target.startswith('dualstack.'):
                        clean_target = clean_target[10:]  # Remove 'dualstack.' prefix
                    
                    elb_regex = r'^([^\.]+)\.([^\.]+)\.elb\.amazonaws\.com'
                    match = re.match(elb_regex, clean_target)
                    
                    if match:
                        lb_name = match.group(1)
                        logger.info(f"Checking if ELB exists: {lb_name}")
                        
                        try:
                            # Check if the load balancer exists
                            response = load_balancer.describe_load_balancers_v2(names=[lb_name])
                            lbs = response.get('LoadBalancers', [])
                            
                            if not lbs:
                                # Try classic load balancers
                                try:
                                    classic_response = load_balancer.describe_classic_load_balancers(
                                        load_balancer_names=[lb_name]
                                    )
                                    classic_lbs = classic_response.get('LoadBalancerDescriptions', [])
                                    
                                    if not classic_lbs:
                                        # Load balancer doesn't exist in either type
                                        return {
                                            'vulnerable': True,
                                            'service': 'AWS ELB',
                                            'details': f"CNAME points to ELB {lb_name} which doesn't exist - potential subdomain takeover"
                                        }
                                except Exception as classic_error:
                                    if 'LoadBalancerNotFound' in str(classic_error):
                                        return {
                                            'vulnerable': True,
                                            'service': 'AWS ELB',
                                            'details': f"CNAME points to ELB {lb_name} which doesn't exist - potential subdomain takeover"
                                        }
                        except Exception as lb_error:
                            logger.warning(f"Error checking load balancer {lb_name}: {lb_error}")
                            if 'LoadBalancerNotFound' in str(lb_error):
                                return {
                                    'vulnerable': True,
                                    'service': 'AWS ELB',
                                    'details': f"CNAME points to ELB {lb_name} which doesn't exist - potential subdomain takeover"
                                }
        
        # General check for any CNAME that doesn't resolve
        target_resolution = check_dns_resolution(cname_target.rstrip('.'))
        if target_resolution['status'] == 'error':
            return {
                'vulnerable': True,
                'service': 'Unknown',
                'details': f"CNAME target does not resolve - potential subdomain takeover"
            }
            
        return {
            'vulnerable': False,
            'service': None,
            'details': "CNAME target resolves correctly"
        }
    
    try:
        # Normalize domain name format by ensuring it ends with a period (Route53 standard)
        if not domain_name.endswith('.'):
            normalized_domain = f"{domain_name}."
        else:
            normalized_domain = domain_name
            
        # Strip trailing dot for DNS resolution
        resolution_domain = domain_name.rstrip('.')
        
        # Find the hosted zone that might contain this record
        zones_response = route53.list_hosted_zones()
        zones = zones_response.get('zones', [])
        target_zone = None
        zone_id = None
        
        # Find the most specific matching hosted zone
        matching_zones = []
        for zone in zones:
            zone_name = zone.get('Name', '')
            if normalized_domain.endswith(zone_name):
                matching_zones.append((zone_name, zone))
        
        # Sort by domain name length to find the most specific match
        if matching_zones:
            matching_zones.sort(key=lambda x: len(x[0]), reverse=True)
            target_zone = matching_zones[0][1]
            zone_id = target_zone.get('Id', '')
        
        if not zone_id:
            return json.dumps({
                "error": {
                    "message": f"No Route53 hosted zone found for domain {domain_name}",
                    "type": "ResourceNotFound"
                }
            })
        
        # Get record sets for this domain
        response = route53.list_resource_record_sets(zone_id)
        records = response.get('records', [])
        
        # Find records matching our domain name
        matching_records = []
        for record in records:
            record_name = record.get('Name', '')
            if record_name == normalized_domain:
                matching_records.append(record)
        
        if not matching_records:
            return json.dumps({
                "summary": f"No DNS records found for {domain_name} in Route53",
                "domain": domain_name,
                "vulnerable": False,
                "records_found": False
            })
        
        # Check DNS resolution for the domain
        dns_result = check_dns_resolution(resolution_domain)
        
        # Variable to track vulnerability status
        vulnerable_records = []
        record_analysis = []
        
        # Process each record for vulnerability indicators
        for record in matching_records:
            record_type = record.get('Type', '')
            record_data = {
                "type": record_type,
                "vulnerable": False
            }
            
            # Process record based on type
            if record_type == 'CNAME':
                resource_records = record.get('ResourceRecords', [])
                
                for resource in resource_records:
                    target = resource.get('Value', '')
                    clean_target = target.rstrip('.')
                    record_data["target"] = target
                    
                    # Check if target domain is vulnerable to takeover
                    service_check = analyze_cname_takeover_risk(clean_target)
                    
                    if service_check.get('vulnerable', False):
                        vulnerable_records.append({
                            'type': 'CNAME',
                            'target': target,
                            'service': service_check.get('service', 'Unknown'),
                            'details': service_check.get('details')
                        })
                        record_data["vulnerable"] = True
                        record_data["vulnerability_details"] = service_check.get('details')
                        record_data["service"] = service_check.get('service', 'Unknown')
            
            elif record_type == 'A':
                resource_records = record.get('ResourceRecords', [])
                ip_addresses = []
                
                for resource in resource_records:
                    ip_address = resource.get('Value', '')
                    ip_addresses.append(ip_address)
                    
                    # Check if this points to an abandoned Elastic IP
                    try:
                        addresses = ec2.describe_addresses(public_ips=[ip_address])
                        
                        if addresses:
                            # IP exists in this account
                            is_associated = False
                            for addr in addresses:
                                if 'AssociationId' in addr:
                                    is_associated = True
                                    break
                            
                            if not is_associated:
                                vulnerable_records.append({
                                    'type': 'A',
                                    'ip': ip_address,
                                    'service': 'AWS Elastic IP',
                                    'details': 'IP exists in AWS account but is not associated with any resource'
                                })
                                record_data["vulnerable"] = True
                                record_data["vulnerability_details"] = "IP exists in AWS account but is not associated with any resource"
                                record_data["service"] = "AWS Elastic IP"
                    except Exception as e:
                        logger.warning(f"Error checking IP {ip_address}: {e}")
                
                record_data["ip_addresses"] = ip_addresses
            
            elif record_type == 'NS':
                resource_records = record.get('ResourceRecords', [])
                nameservers = [r.get('Value', '') for r in resource_records]
                record_data["nameservers"] = nameservers
            
            record_analysis.append(record_data)
        
        # Prepare result object
        result = {
            "domain": domain_name,
            "dns_resolution": dns_result.get('details'),
            "records_found": True,
            "records_count": len(matching_records),
            "records": record_analysis,
            "vulnerable": len(vulnerable_records) > 0,
            "vulnerability_count": len(vulnerable_records),
            "vulnerabilities": vulnerable_records
        }
        
        if dns_result.get('status') == 'ok' and dns_result.get('ip'):
            result["ip_address"] = dns_result.get('ip')
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error checking subdomain takeover vulnerability: {e}")
        return json.dumps({
            "error": {
                "message": f"Error checking subdomain takeover vulnerability for {domain_name}: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool("find_ip_address_details")
async def find_ip_address_details(ip_address: str, session_context: Optional[str] = None) -> str:
    """Find details about an IP address, including associated EC2 resources and DNS records pointing to it.
    
    This function:
    1. Identifies EC2 instances with this IP (public or private)
    2. Finds network interfaces using this IP
    3. Searches Route53 records pointing to this IP
    
    Args:
        ip_address: The IP address to lookup (e.g., 43.205.186.36)
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON string with IP address details and associated resources
    """
    logger.info(f"Looking up details for IP address: {ip_address}")
    
    result = {
        "ip_address": ip_address,
        "ec2_instances": [],
        "network_interfaces": [],
        "route53_records": [],
        "summary": ""
    }
    
    try:
        # Check for EC2 instances with this IP
        instances = []
        try:
            # Look for instances with this public IP
            instances.extend(ec2.describe_instances(filters=[
                {"Name": "public-ip", "Values": [ip_address]}
            ], session_context=session_context))
            
            # Also check for instances with this private IP
            instances.extend(ec2.describe_instances(filters=[
                {"Name": "private-ip-address", "Values": [ip_address]}
            ], session_context=session_context))
            
            # Deduplicate instances
            seen_ids = set()
            unique_instances = []
            for instance in instances:
                instance_id = instance.get('InstanceId')
                if instance_id and instance_id not in seen_ids:
                    seen_ids.add(instance_id)
                    
                    # Extract relevant instance details
                    instance_details = {
                        "instance_id": instance_id,
                        "state": instance.get('State', {}).get('Name', 'unknown'),
                        "instance_type": instance.get('InstanceType'),
                        "private_ip": instance.get('PrivateIpAddress'),
                        "public_ip": instance.get('PublicIpAddress'),
                        "vpc_id": instance.get('VpcId'),
                        "subnet_id": instance.get('SubnetId'),
                        "launch_time": str(instance.get('LaunchTime')) if instance.get('LaunchTime') else None,
                    }
                    
                    # Add tags if available
                    if 'Tags' in instance:
                        instance_details["tags"] = {tag['Key']: tag['Value'] for tag in instance['Tags']}
                    
                    unique_instances.append(instance_details)
            
            result["ec2_instances"] = unique_instances
            
        except Exception as e:
            logger.error(f"Error finding EC2 instances for IP {ip_address}: {e}")
            result["ec2_instances_error"] = str(e)
        
        # Check for network interfaces with this IP
        network_interfaces = []
        try:
            # Look for network interfaces with this IP
            interfaces = ec2.describe_network_interfaces(filters=[
                {"Name": "addresses.private-ip-address", "Values": [ip_address]}
            ], session_context=session_context)
            
            # Also check for interfaces with public IP
            public_interfaces = ec2.describe_network_interfaces(filters=[
                {"Name": "association.public-ip", "Values": [ip_address]}
            ], session_context=session_context)
            
            interfaces.extend(public_interfaces)
            
            # Deduplicate interfaces
            seen_ids = set()
            for interface in interfaces:
                eni_id = interface.get('NetworkInterfaceId')
                if eni_id and eni_id not in seen_ids:
                    seen_ids.add(eni_id)
                    
                    # Extract relevant interface details
                    interface_details = {
                        "network_interface_id": eni_id,
                        "status": interface.get('Status'),
                        "description": interface.get('Description'),
                        "vpc_id": interface.get('VpcId'),
                        "subnet_id": interface.get('SubnetId'),
                        "private_ip": interface.get('PrivateIpAddress'),
                        "private_ips": [ip.get('PrivateIpAddress') for ip in interface.get('PrivateIpAddresses', [])],
                    }
                    
                    # Add public IP if available
                    association = interface.get('Association', {})
                    if association and 'PublicIp' in association:
                        interface_details["public_ip"] = association.get('PublicIp')
                    
                    # Add attachment info if available
                    attachment = interface.get('Attachment', {})
                    if attachment:
                        interface_details["attachment"] = {
                            "instance_id": attachment.get('InstanceId'),
                            "device_index": attachment.get('DeviceIndex'),
                            "status": attachment.get('Status'),
                            "delete_on_termination": attachment.get('DeleteOnTermination')
                        }
                    
                    network_interfaces.append(interface_details)
            
            result["network_interfaces"] = network_interfaces
            
        except Exception as e:
            logger.error(f"Error finding network interfaces for IP {ip_address}: {e}")
            result["network_interfaces_error"] = str(e)
        
        # Find Route53 records pointing to this IP
        try:
            # Get all hosted zones
            hosted_zones_response = route53.list_hosted_zones(max_items=100, session_context=session_context)
            zones = hosted_zones_response.get('zones', [])
            
            matching_records = []
            
            # Look through each zone for A records with this IP
            for zone in zones:
                zone_id = zone.get('Id')
                zone_name = zone.get('Name', '')
                
                if not zone_id:
                    continue
                
                # Get records for this zone
                records_response = route53.list_resource_record_sets(zone_id, max_items=300, session_context=session_context)
                records = records_response.get('records', [])
                
                # Find A records matching this IP
                for record in records:
                    record_type = record.get('Type')
                    
                    if record_type == 'A':
                        resource_records = record.get('ResourceRecords', [])
                        
                        for rr in resource_records:
                            if rr.get('Value') == ip_address:
                                record_details = {
                                    "name": record.get('Name'),
                                    "type": record_type,
                                    "ttl": record.get('TTL'),
                                    "zone_id": zone_id.replace('/hostedzone/', ''),
                                    "zone_name": zone_name
                                }
                                matching_records.append(record_details)
            
            result["route53_records"] = matching_records
            
        except Exception as e:
            logger.error(f"Error finding Route53 records for IP {ip_address}: {e}")
            result["route53_records_error"] = str(e)
        
        # Create summary
        ec2_count = len(result["ec2_instances"])
        eni_count = len(result["network_interfaces"])
        record_count = len(result["route53_records"])
        
        summary_parts = []
        if ec2_count > 0:
            summary_parts.append(f"Found {ec2_count} EC2 instance(s)")
        if eni_count > 0:
            summary_parts.append(f"Found {eni_count} network interface(s)")
        if record_count > 0:
            summary_parts.append(f"Found {record_count} Route53 record(s)")
            
        if summary_parts:
            result["summary"] = f"IP {ip_address}: " + ", ".join(summary_parts)
        else:
            result["summary"] = f"IP {ip_address}: No associated AWS resources found"
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error looking up details for IP {ip_address}: {e}")
        return json.dumps({
            "error": {
                "message": f"Error looking up details for IP {ip_address}: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool("analyze_domain_security")
async def analyze_domain_security(domain_name: str, session_context: Optional[str] = None) -> str:
    """Analyze the security posture of a domain, including its DNS configuration and associated resources.
    
    This function:
    1. Checks the domain's DNS records
    2. For A records, analyzes the security of the associated IP addresses
    3. For CNAME records, checks for subdomain takeover vulnerabilities
    4. Provides security recommendations based on the findings
    
    Args:
        domain_name: The domain name to analyze
        session_context: Optional session key for cross-account access
        
    Returns:
        JSON string with security analysis results
    """
    logger.info(f"Analyzing security posture for domain: {domain_name}")
    
    result = {
        "domain": domain_name,
        "dns_records": [],
        "ec2_resources": [],
        "vulnerabilities": [],
        "security_recommendations": [],
        "summary": ""
    }
    
    try:
        # Normalize domain name format by ensuring it ends with a period (Route53 standard)
        if not domain_name.endswith('.'):
            normalized_domain = f"{domain_name}."
        else:
            normalized_domain = domain_name
        
        # Find the hosted zone that might contain this record
        hosted_zones_response = route53.list_hosted_zones(max_items=100)
        zones = hosted_zones_response.get('zones', [])
        
        # Find the most specific matching hosted zone
        matching_zones = []
        for zone in zones:
            zone_name = zone.get('Name', '')
            if normalized_domain.endswith(zone_name):
                matching_zones.append((zone_name, zone))
        
        if not matching_zones:
            return json.dumps({
                "summary": f"No Route53 hosted zones found for domain {domain_name}",
                "domain": domain_name,
                "dns_records": [],
                "vulnerabilities": []
            })
        
        # Sort by domain name length to find the most specific match
        matching_zones.sort(key=lambda x: len(x[0]), reverse=True)
        target_zone = matching_zones[0][1]
        zone_id = target_zone.get('Id', '')
        
        # Get record sets for this domain
        response = route53.list_resource_record_sets(zone_id)
        records = response.get('records', [])
        
        # Find records matching our domain name or subdomains
        matching_records = []
        for record in records:
            record_name = record.get('Name', '')
            if record_name == normalized_domain or record_name.endswith(f".{normalized_domain}"):
                matching_records.append(record)
        
        if not matching_records:
            return json.dumps({
                "summary": f"No DNS records found for {domain_name} in Route53",
                "domain": domain_name,
                "dns_records": [],
                "vulnerabilities": []
            })
        
        # Process each record for security analysis
        a_records_ips = []
        record_details = []
        vulnerabilities = []
        
        for record in matching_records:
            record_name = record.get('Name', '')
            record_type = record.get('Type', '')
            
            record_info = {
                "name": record_name,
                "type": record_type,
                "ttl": record.get('TTL')
            }
            
            # Process record based on type
            if record_type == 'A':
                resource_records = record.get('ResourceRecords', [])
                ip_addresses = [r.get('Value', '') for r in resource_records]
                record_info["values"] = ip_addresses
                a_records_ips.extend(ip_addresses)
                
            elif record_type == 'CNAME':
                resource_records = record.get('ResourceRecords', [])
                targets = [r.get('Value', '') for r in resource_records]
                record_info["values"] = targets
                
                # Check for subdomain takeover vulnerabilities
                for target in targets:
                    # Clean up target for analysis
                    clean_target = target.lower()
                    if clean_target.startswith('dualstack.'):
                        clean_target = clean_target[10:]  # Remove 'dualstack.' prefix
                    
                    # This is a simplified check - in production, we'd call the full function
                    for pattern in ['s3.amazonaws.com', 'cloudfront.net', 'elasticbeanstalk.com',
                                  'github.io', 'herokuapp.com', 'azurewebsites.net', 'elb.amazonaws.com']:
                        if pattern in clean_target:
                            service_name = pattern
                            
                            # For ELB names, extract the actual load balancer name for better reporting
                            if pattern == 'elb.amazonaws.com':
                                elb_regex = r'^([^\.]+)\.([^\.]+)\.elb\.amazonaws\.com'
                                match = re.match(elb_regex, clean_target)
                                if match:
                                    service_name = f"AWS ELB ({match.group(1)})"
                            
                            # This is a potential risk - flag it for further investigation
                            vulnerabilities.append({
                                "type": "potential_subdomain_takeover",
                                "record_name": record_name,
                                "record_type": "CNAME",
                                "target": target,
                                "service": service_name,
                                "details": f"CNAME points to {pattern} which could be vulnerable to subdomain takeover if unclaimed"
                            })
            
            elif record_type == 'MX':
                resource_records = record.get('ResourceRecords', [])
                values = [r.get('Value', '') for r in resource_records]
                record_info["values"] = values
                
                # Check for common mail security issues
                has_spf = False
                has_dmarc = False
                
                # Find corresponding SPF and DMARC records
                for spf_check in matching_records:
                    if spf_check.get('Type') == 'TXT':
                        txt_name = spf_check.get('Name', '')
                        if txt_name == record_name:
                            for txt_record in spf_check.get('ResourceRecords', []):
                                txt_value = txt_record.get('Value', '')
                                if 'v=spf1' in txt_value:
                                    has_spf = True
                
                for dmarc_check in matching_records:
                    if dmarc_check.get('Type') == 'TXT':
                        dmarc_name = dmarc_check.get('Name', '')
                        if dmarc_name.startswith('_dmarc.'):
                            for txt_record in dmarc_check.get('ResourceRecords', []):
                                txt_value = txt_record.get('Value', '')
                                if 'v=DMARC1' in txt_value:
                                    has_dmarc = True
                
                if not has_spf:
                    vulnerabilities.append({
                        "type": "missing_spf",
                        "record_name": record_name,
                        "details": "Domain has MX records but no SPF record was found"
                    })
                
                if not has_dmarc:
                    vulnerabilities.append({
                        "type": "missing_dmarc",
                        "record_name": record_name,
                        "details": "Domain has MX records but no DMARC record was found"
                    })
            
            record_details.append(record_info)
        
        result["dns_records"] = record_details
        result["vulnerabilities"] = vulnerabilities
        
        # Analyze EC2 instances associated with A record IPs
        ec2_instances = []
        for ip in a_records_ips:
            try:
                # Check for EC2 instances with this IP
                instances = ec2.describe_instances(filters=[
                    {"Name": "public-ip", "Values": [ip]}
                ], session_context=session_context)
                
                for instance in instances:
                    instance_id = instance.get('InstanceId')
                    
                    # Extract security groups
                    security_groups = []
                    for sg in instance.get('SecurityGroups', []):
                        sg_id = sg.get('GroupId')
                        sg_details = ec2.describe_security_groups(group_ids=[sg_id])
                        
                        if sg_details:
                            sg_info = sg_details[0]
                            open_ports = []
                            
                            # Check for open ports
                            for permission in sg_info.get('IpPermissions', []):
                                from_port = permission.get('FromPort')
                                to_port = permission.get('ToPort')
                                protocol = permission.get('IpProtocol')
                                
                                for ip_range in permission.get('IpRanges', []):
                                    cidr = ip_range.get('CidrIp', '')
                                    if cidr == '0.0.0.0/0':
                                        if from_port == to_port:
                                            open_ports.append(f"{from_port}/{protocol}")
                                        else:
                                            open_ports.append(f"{from_port}-{to_port}/{protocol}")
                            
                            security_groups.append({
                                "group_id": sg_id,
                                "group_name": sg_info.get('GroupName'),
                                "description": sg_info.get('Description'),
                                "open_to_internet": len(open_ports) > 0,
                                "open_ports": open_ports
                            })
                    
                    instance_details = {
                        "instance_id": instance_id,
                        "state": instance.get('State', {}).get('Name'),
                        "instance_type": instance.get('InstanceType'),
                        "image_id": instance.get('ImageId'),
                        "ip_address": ip,
                        "security_groups": security_groups
                    }
                    
                    # Check if instance is in a public subnet
                    subnet_id = instance.get('SubnetId')
                    if subnet_id:
                        subnet = ec2.describe_subnets(subnet_ids=[subnet_id])
                        if subnet:
                            subnet_info = subnet[0]
                            instance_details["public_subnet"] = subnet_info.get('MapPublicIpOnLaunch', False)
                    
                    ec2_instances.append(instance_details)
                    
                    # Add security recommendations based on findings
                    if any(sg.get('open_to_internet', False) for sg in security_groups):
                        result["security_recommendations"].append({
                            "severity": "HIGH",
                            "resource_id": instance_id,
                            "resource_type": "EC2",
                            "finding": "Instance has security groups with ports open to the internet (0.0.0.0/0)",
                            "recommendation": "Restrict security group rules to specific IP ranges instead of 0.0.0.0/0"
                        })
            
            except Exception as e:
                logger.error(f"Error analyzing EC2 instance for IP {ip}: {e}")
        
        result["ec2_resources"] = ec2_instances
        
        # Create summary
        record_count = len(record_details)
        vulnerability_count = len(vulnerabilities)
        ec2_count = len(ec2_instances)
        
        result["summary"] = f"Domain {domain_name}: Found {record_count} DNS records, {vulnerability_count} potential vulnerabilities, and {ec2_count} associated EC2 instances"
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error analyzing security for domain {domain_name}: {e}")
        return json.dumps({
            "error": {
                "message": f"Error analyzing security for domain {domain_name}: {str(e)}",
                "type": type(e).__name__
            },
            "domain": domain_name
        }) 