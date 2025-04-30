"""Formatters for Load Balancer resources."""

import json
from typing import Any, Dict, List, Optional, Union


def format_load_balancer(lb: Dict[str, Any]) -> str:
    """Format a load balancer into a readable string.
    
    Args:
        lb: Load balancer data dictionary
        
    Returns:
        Formatted string representation of the load balancer
    """
    # Determine load balancer type
    lb_type = lb.get('Type', 'Unknown').lower()
    
    # Common fields
    formatted = f"""
Load Balancer: {lb.get('LoadBalancerName', 'Unknown')}
DNS Name: {lb.get('DNSName', 'Unknown')}
Type: {lb_type.title()}
Scheme: {lb.get('Scheme', 'Unknown')}
"""
    
    # Add VPC info if available
    if 'VpcId' in lb:
        formatted += f"VPC: {lb.get('VpcId', 'Unknown')}\n"
    
    # Add state if available
    if isinstance(lb.get('State'), dict):
        formatted += f"State: {lb.get('State', {}).get('Code', 'Unknown')}\n"
    else:
        formatted += f"State: {lb.get('State', 'Unknown')}\n"

    # Format AZs based on load balancer type
    if lb_type == 'classic':
        # Classic load balancer AZ format
        if 'AvailabilityZones' in lb and isinstance(lb['AvailabilityZones'], list):
            formatted += f"AZs: {', '.join(lb.get('AvailabilityZones', []))}\n"
    else:
        # ELBv2 AZ format (more complex object)
        if 'AvailabilityZones' in lb and isinstance(lb['AvailabilityZones'], list):
            az_names = [az.get('ZoneName', 'Unknown') for az in lb.get('AvailabilityZones', [])]
            formatted += f"AZs: {', '.join(az_names)}\n"
    
    # Add security groups
    formatted += f"Security Groups: {', '.join(lb.get('SecurityGroups', []))}\n"
    
    # Add creation time
    if 'CreatedTime' in lb:
        formatted += f"Created: {lb.get('CreatedTime', 'Unknown')}\n"
    
    # Add type-specific details
    if lb_type == 'application':
        formatted += f"IP Address Type: {lb.get('IpAddressType', 'Unknown')}\n"
        if 'LoadBalancerAttributes' in lb:
            attrs = lb.get('LoadBalancerAttributes', [])
            for attr in attrs:
                if attr.get('Key') == 'idle_timeout.timeout_seconds':
                    formatted += f"Idle Timeout: {attr.get('Value', 'Unknown')} seconds\n"
                if attr.get('Key') == 'routing.http2.enabled':
                    formatted += f"HTTP/2 Enabled: {attr.get('Value', 'Unknown')}\n"
    
    elif lb_type == 'network':
        formatted += f"IP Address Type: {lb.get('IpAddressType', 'Unknown')}\n"
    
    elif lb_type == 'classic':
        if 'ListenerDescriptions' in lb:
            listeners = lb.get('ListenerDescriptions', [])
            if listeners:
                formatted += "\nListeners:\n"
                for listener in listeners:
                    l_conf = listener.get('Listener', {})
                    formatted += f"  {l_conf.get('Protocol', 'Unknown')}:{l_conf.get('LoadBalancerPort', 'Unknown')} -> {l_conf.get('InstanceProtocol', 'Unknown')}:{l_conf.get('InstancePort', 'Unknown')}\n"
    
    # Add ARN if available (ELBv2 only)
    if 'LoadBalancerArn' in lb:
        formatted += f"\nARN: {lb.get('LoadBalancerArn', 'Unknown')}\n"
    
    return formatted


def format_target_group(tg: Dict[str, Any]) -> str:
    """Format a target group into a readable string.
    
    Args:
        tg: Target group data dictionary
        
    Returns:
        Formatted string representation of the target group
    """
    formatted = f"""
Target Group: {tg.get('TargetGroupName', 'Unknown')}
ARN: {tg.get('TargetGroupArn', 'Unknown')}
Protocol: {tg.get('Protocol', 'Unknown')}
Port: {tg.get('Port', 'Unknown')}
Target Type: {tg.get('TargetType', 'Unknown')}
VPC: {tg.get('VpcId', 'Unknown')}
Health Check: 
  Protocol: {tg.get('HealthCheckProtocol', 'Unknown')}
  Port: {tg.get('HealthCheckPort', 'Unknown')}
  Path: {tg.get('HealthCheckPath', 'Unknown')}
  Interval: {tg.get('HealthCheckIntervalSeconds', 'Unknown')}
  Timeout: {tg.get('HealthCheckTimeoutSeconds', 'Unknown')}
  Healthy Threshold: {tg.get('HealthyThresholdCount', 'Unknown')}
  Unhealthy Threshold: {tg.get('UnhealthyThresholdCount', 'Unknown')}
"""
    
    # Add load balancer ARNs if available
    if 'LoadBalancerArns' in tg and tg['LoadBalancerArns']:
        formatted += "\nAssociated Load Balancers:\n"
        for arn in tg['LoadBalancerArns']:
            formatted += f"  {arn}\n"
    
    return formatted


def format_listener(listener: Dict[str, Any]) -> str:
    """Format a listener into a readable string.
    
    Args:
        listener: Listener data dictionary
        
    Returns:
        Formatted string representation of the listener
    """
    formatted = f"""
Listener ARN: {listener.get('ListenerArn', 'Unknown')}
Protocol: {listener.get('Protocol', 'Unknown')}
Port: {listener.get('Port', 'Unknown')}
"""
    
    # Add default actions
    default_actions = listener.get('DefaultActions', [])
    if default_actions:
        formatted += "Default Actions:\n"
        for action in default_actions:
            action_type = action.get('Type', 'Unknown')
            formatted += f"  Type: {action_type}\n"
            
            if action_type == 'forward':
                if 'TargetGroupArn' in action:
                    formatted += f"  Target Group: {action.get('TargetGroupArn', 'Unknown')}\n"
                elif 'ForwardConfig' in action:
                    tg_configs = action.get('ForwardConfig', {}).get('TargetGroups', [])
                    for tg_config in tg_configs:
                        weight = tg_config.get('Weight', 1)
                        formatted += f"  Target Group: {tg_config.get('TargetGroupArn', 'Unknown')} (Weight: {weight})\n"
            
            elif action_type == 'redirect':
                redirect = action.get('RedirectConfig', {})
                formatted += f"  Redirect: {redirect.get('Protocol', 'Unknown')}://{redirect.get('Host', 'Unknown')}:{redirect.get('Port', 'Unknown')}{redirect.get('Path', 'Unknown')}\n"
                formatted += f"  Status Code: {redirect.get('StatusCode', 'Unknown')}\n"
            
            elif action_type == 'fixed-response':
                fixed = action.get('FixedResponseConfig', {})
                formatted += f"  Status Code: {fixed.get('StatusCode', 'Unknown')}\n"
                formatted += f"  Content Type: {fixed.get('ContentType', 'Unknown')}\n"
    
    # Add SSL policy if present
    if 'SslPolicy' in listener:
        formatted += f"SSL Policy: {listener.get('SslPolicy', 'N/A')}\n"
    
    # Add certificates if present
    certificates = listener.get('Certificates', [])
    if certificates:
        formatted += "Certificates:\n"
        for cert in certificates:
            formatted += f"  {cert.get('CertificateArn', 'Unknown')}\n"
    
    return formatted


def format_target_health(target_health: List[Dict[str, Any]]) -> str:
    """Format target health descriptions into a readable string.
    
    Args:
        target_health: List of target health descriptions
        
    Returns:
        Formatted string representation of target health
    """
    if not target_health:
        return "No targets registered"
    
    formatted = "\nTarget Health:\n"
    
    for th in target_health:
        target = th.get('Target', {})
        health = th.get('TargetHealth', {})
        
        target_id = target.get('Id', 'Unknown')
        port = target.get('Port', 'Unknown')
        health_state = health.get('State', 'Unknown')
        reason = health.get('Reason', '')
        description = health.get('Description', '')
        
        formatted += f"  {target_id}:{port} - {health_state}"
        if reason:
            formatted += f" ({reason})"
        if description:
            formatted += f": {description}"
        formatted += "\n"
    
    return formatted


def format_load_balancer_summary(lb: Dict[str, Any]) -> str:
    """Format a load balancer into a concise summary string.
    
    Args:
        lb: Load balancer data dictionary
        
    Returns:
        Formatted summary string representation of the load balancer
    """
    lb_type = lb.get('Type', 'Unknown').lower()
    
    formatted = f"{lb.get('LoadBalancerName', 'Unknown')} "
    formatted += f"({lb_type.upper()}) - "
    formatted += f"{lb.get('DNSName', 'Unknown')} - "
    
    # Add state
    if isinstance(lb.get('State'), dict):
        formatted += f"{lb.get('State', {}).get('Code', 'Unknown')} - "
    else:
        formatted += f"{lb.get('State', 'Unknown')} - "
    
    # Add VPC if available
    if 'VpcId' in lb:
        formatted += f"VPC: {lb.get('VpcId', 'Unknown')}"
    
    return formatted 