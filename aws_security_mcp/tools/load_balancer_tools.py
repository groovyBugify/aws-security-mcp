"""AWS Elastic Load Balancing tools.

This module provides tools for interacting with AWS Elastic Load Balancing services:
- Classic Load Balancers (ELB)
- Application Load Balancers (ALB)
- Network Load Balancers (NLB)
- Gateway Load Balancers (GWLB)
"""

import json
import logging
import datetime
from typing import Any, Dict, List, Optional, Union

from aws_security_mcp.services import load_balancer
from aws_security_mcp.tools import register_tool

logger = logging.getLogger(__name__)


# Custom JSON encoder to handle datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        return super().default(obj)


def serialize_to_json(data: Any) -> str:
    """Serialize data to JSON string using the DateTimeEncoder.
    
    Args:
        data: Data to serialize to JSON
        
    Returns:
        JSON string representation of the data
    """
    return json.dumps(data, cls=DateTimeEncoder)


@register_tool('get_load_balancers')
async def get_load_balancers(
    load_balancer_type: Optional[str] = None,
    arns: Optional[List[str]] = None,
    names: Optional[List[str]] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> str:
    """Get load balancers with optional filtering.
    
    Searches ELBv2 first (ALB, NLB, GWLB), then falls back to classic ELB if needed.
    Returns ARNs as the primary identifier.
    
    Args:
        load_balancer_type: Filter by type ('classic', 'application', 'network', 'gateway')
        arns: Filter by load balancer ARNs (preferred method)
        names: Filter by load balancer names (fallback method)
        next_token: Token for pagination
        max_items: Maximum items to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with load balancer information and pagination details
        
    Examples:
        # Single account (default)
        get_load_balancers(load_balancer_type="application")
        
        # Cross-account access
        get_load_balancers(load_balancer_type="application", session_context="123456789012_aws_dev")
    """
    logger.info(
        "Getting load balancers with %s",
        {
            "load_balancer_type": load_balancer_type,
            "arns": arns,
            "names": names,
            "next_token": next_token,
            "max_items": max_items,
            "session_context": session_context
        }
    )
    
    try:
        result = load_balancer.get_load_balancers(
            load_balancer_type=load_balancer_type,
            arns=arns,
            names=names,
            next_token=next_token,
            max_items=max_items,
            session_context=session_context
        )
        
        # The service now returns simplified objects with focus on ARNs
        return serialize_to_json(result)
    except Exception as e:
        logger.error("Error in get_load_balancers: %s", e)
        return serialize_to_json({
            "error": str(e),
            "load_balancers": [],
            "next_token": None
        })


@register_tool('describe_load_balancer')
async def describe_load_balancer(load_balancer_arn: str, session_context: Optional[str] = None) -> str:
    """Get detailed information about a specific load balancer.
    
    Args:
        load_balancer_arn: ARN of the load balancer
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with load balancer information
        
    Examples:
        # Single account (default)
        describe_load_balancer("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456")
        
        # Cross-account access
        describe_load_balancer("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456", session_context="123456789012_aws_dev")
    """
    logger.info("Describing load balancer with ARN: %s", load_balancer_arn)
    
    if not load_balancer_arn.startswith('arn:aws:elasticloadbalancing:'):
        return serialize_to_json({
            "error": f"Invalid load balancer ARN format: {load_balancer_arn}",
            "load_balancer": None
        })
    
    try:
        result = load_balancer.search_load_balancer(load_balancer_arn, session_context=session_context)
        if result:
            return serialize_to_json({"load_balancer": result})
        else:
            return serialize_to_json({
                "error": f"Load balancer not found with ARN: {load_balancer_arn}",
                "load_balancer": None
            })
    except Exception as e:
        logger.error("Error in describe_load_balancer: %s", e)
        return serialize_to_json({
            "error": str(e),
            "load_balancer": None
        })


@register_tool('describe_instance_health')
async def describe_instance_health(
    load_balancer_name: str,
    instance_ids: Optional[List[str]] = None,
    session_context: Optional[str] = None
) -> str:
    """Describe the health of instances for a Classic Load Balancer.
    
    Args:
        load_balancer_name: Name of the Classic Load Balancer
        instance_ids: Optional list of instance IDs to filter by
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with instance health information
        
    Examples:
        # Single account (default)
        describe_instance_health("my-classic-lb")
        
        # Cross-account access
        describe_instance_health("my-classic-lb", session_context="123456789012_aws_dev")
    """
    logger.info(
        "Describing instance health for Classic Load Balancer: %s, instances: %s",
        load_balancer_name, instance_ids
    )
    
    try:
        result = load_balancer.describe_instance_health(
            load_balancer_name=load_balancer_name,
            instance_ids=instance_ids,
            session_context=session_context
        )
        return serialize_to_json({"instance_states": result})
    except Exception as e:
        logger.error("Error in describe_instance_health: %s", e)
        return serialize_to_json({
            "error": str(e),
            "instance_states": []
        })


@register_tool('get_target_groups')
async def get_target_groups(
    load_balancer_arn: Optional[str] = None,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> str:
    """Get target groups with optional filtering by load balancer ARN.
    
    Args:
        load_balancer_arn: Optional load balancer ARN to filter by
        next_token: Token for pagination
        max_items: Maximum items to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with target group information and pagination details
        
    Examples:
        # Single account (default)
        get_target_groups()
        
        # Cross-account access
        get_target_groups(session_context="123456789012_aws_dev")
    """
    logger.info(
        "Getting target groups with %s",
        {
            "load_balancer_arn": load_balancer_arn,
            "next_token": next_token,
            "max_items": max_items,
            "session_context": session_context
        }
    )
    
    try:
        result = load_balancer.get_all_target_groups(
            load_balancer_arn=load_balancer_arn,
            next_token=next_token,
            max_items=max_items,
            session_context=session_context
        )
        return serialize_to_json(result)
    except Exception as e:
        logger.error("Error in get_target_groups: %s", e)
        return serialize_to_json({
            "error": str(e),
            "target_groups": [],
            "next_token": None
        })


@register_tool('describe_target_health')
async def describe_target_health(
    target_group_arn: str,
    targets: Optional[List[Dict[str, str]]] = None,
    session_context: Optional[str] = None
) -> str:
    """Describe the health of targets in a target group.
    
    Args:
        target_group_arn: ARN of the target group
        targets: Optional list of targets to describe
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with target health information
        
    Examples:
        # Single account (default)
        describe_target_health("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/1234567890123456")
        
        # Cross-account access
        describe_target_health("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/1234567890123456", session_context="123456789012_aws_dev")
    """
    logger.info(
        "Describing target health for: %s, targets: %s",
        target_group_arn, targets
    )
    
    try:
        result = load_balancer.describe_target_health(
            target_group_arn=target_group_arn,
            targets=targets,
            session_context=session_context
        )
        return serialize_to_json({"target_health_descriptions": result})
    except Exception as e:
        logger.error("Error in describe_target_health: %s", e)
        return serialize_to_json({
            "error": str(e),
            "target_health_descriptions": []
        })


@register_tool('describe_listeners')
async def describe_listeners(
    load_balancer_arn: str,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> str:
    """Describe listeners for a load balancer.
    
    Args:
        load_balancer_arn: ARN of the load balancer
        next_token: Token for pagination
        max_items: Maximum items to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with listener information
        
    Examples:
        # Single account (default)
        describe_listeners("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456")
        
        # Cross-account access
        describe_listeners("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456", session_context="123456789012_aws_dev")
    """
    logger.info(
        "Describing listeners for ARN: %s with %s",
        load_balancer_arn,
        {
            "next_token": next_token,
            "max_items": max_items,
            "session_context": session_context
        }
    )
    
    try:
        if not load_balancer_arn.startswith('arn:aws:elasticloadbalancing:'):
            return serialize_to_json({
                "error": f"Invalid load balancer ARN format: {load_balancer_arn}",
                "listeners": [],
                "next_token": None
            })
        
        lb = load_balancer.search_load_balancer(load_balancer_arn, session_context=session_context)
        if not lb:
            return serialize_to_json({
                "error": f"Load balancer not found with ARN: {load_balancer_arn}",
                "listeners": [],
                "next_token": None
            })
        
        if "LoadBalancerArn" in lb:
            lb_arn = lb["LoadBalancerArn"]
            
            if not next_token and (max_items is None or max_items >= 100):
                result = load_balancer.describe_listeners(load_balancer_arn=lb_arn, session_context=session_context)
                if "error" in result:
                    return serialize_to_json({
                        "error": result["error"],
                        "listeners": [],
                        "next_token": None
                    })
                return serialize_to_json({
                    "listeners": result["listeners"],
                    "next_token": None
                })
            
            result = load_balancer.get_all_listeners(
                load_balancer_arn=lb_arn,
                next_token=next_token,
                max_items=max_items,
                session_context=session_context
            )
            return serialize_to_json(result)
        else:
            return serialize_to_json({
                "message": "Classic Load Balancers use ports instead of listeners",
                "load_balancer": lb,
                "listeners": [],
                "next_token": None
            })
    except Exception as e:
        logger.error("Error in describe_listeners: %s", e)
        return serialize_to_json({
            "error": str(e),
            "listeners": [],
            "next_token": None
        })


@register_tool('describe_load_balancer_listeners')
async def describe_load_balancer_listeners(
    load_balancer_arn: str,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> str:
    """Describe listeners for a load balancer using its ARN.
    
    Args:
        load_balancer_arn: The ARN of the load balancer
        next_token: Token for pagination
        max_items: Maximum items to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with listener information
        
    Examples:
        # Single account (default)
        describe_load_balancer_listeners("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456")
        
        # Cross-account access
        describe_load_balancer_listeners("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456", session_context="123456789012_aws_dev")
    """
    logger.info(
        "Directly describing listeners for load balancer ARN: %s with %s",
        load_balancer_arn,
        {
            "next_token": next_token,
            "max_items": max_items,
            "session_context": session_context
        }
    )
    
    try:
        if not load_balancer_arn.startswith('arn:aws:elasticloadbalancing:'):
            return serialize_to_json({
                "error": f"Invalid load balancer ARN format: {load_balancer_arn}",
                "listeners": [],
                "next_token": None
            })
        
        if ':loadbalancer/app/' in load_balancer_arn or ':loadbalancer/net/' in load_balancer_arn or ':loadbalancer/gwy/' in load_balancer_arn:
            if not next_token and (max_items is None or max_items >= 100):
                result = load_balancer.describe_listeners(load_balancer_arn=load_balancer_arn, session_context=session_context)
                if "error" in result:
                    return serialize_to_json({
                        "error": result["error"],
                        "listeners": [],
                        "next_token": None
                    })
                return serialize_to_json({
                    "listeners": result["listeners"],
                    "next_token": None
                })
            
            result = load_balancer.get_all_listeners(
                load_balancer_arn=load_balancer_arn,
                next_token=next_token,
                max_items=max_items,
                session_context=session_context
            )
            return serialize_to_json(result)
        else:
            return serialize_to_json({
                "message": "Classic Load Balancers use ports instead of listeners",
                "listeners": [],
                "next_token": None
            })
    except Exception as e:
        logger.error("Error in describe_load_balancer_listeners: %s", e)
        return serialize_to_json({
            "error": str(e),
            "listeners": [],
            "next_token": None
        })


@register_tool('describe_rules')
async def describe_rules(
    listener_arn: str,
    next_token: Optional[str] = None,
    max_items: int = 50,
    session_context: Optional[str] = None
) -> str:
    """Describe rules for a listener.
    
    Args:
        listener_arn: ARN of the listener
        next_token: Token for pagination
        max_items: Maximum items to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with rule information
        
    Examples:
        # Single account (default)
        describe_rules("arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/1234567890123456/1234567890123456")
        
        # Cross-account access
        describe_rules("arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/1234567890123456/1234567890123456", session_context="123456789012_aws_dev")
    """
    logger.info(
        "Describing rules for listener: %s with %s",
        listener_arn,
        {
            "next_token": next_token,
            "max_items": max_items,
            "session_context": session_context
        }
    )
    
    try:
        result = load_balancer.get_all_rules(
            listener_arn=listener_arn,
            next_token=next_token,
            max_items=max_items,
            session_context=session_context
        )
        return serialize_to_json(result)
    except Exception as e:
        logger.error("Error in describe_rules: %s", e)
        return serialize_to_json({
            "error": str(e),
            "rules": [],
            "next_token": None
        })


@register_tool('search_load_balancer')
async def search_load_balancer(identifier: str, session_context: Optional[str] = None) -> str:
    """Search for a load balancer by ARN, name, or DNS name.
    
    Searches ELBv2 first, then falls back to classic ELB if needed.
    
    Args:
        identifier: Load balancer ARN, name, or DNS name
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with load balancer information
        
    Examples:
        # Single account (default)
        search_load_balancer("my-load-balancer")
        
        # Cross-account access
        search_load_balancer("my-load-balancer", session_context="123456789012_aws_dev")
    """
    logger.info("Searching for load balancer with identifier: %s", identifier)
    
    try:
        result = load_balancer.search_load_balancer(identifier, session_context=session_context)
        if result:
            # Only return essential information, with ARN as the primary identifier
            simplified_lb = {
                "LoadBalancerArn": result.get("LoadBalancerArn", ""),
                "LoadBalancerName": result.get("LoadBalancerName", ""),
                "DNSName": result.get("DNSName", ""),
                "Type": result.get("Type", "classic") if "Type" in result else "classic"
            }
            return serialize_to_json({"load_balancer": simplified_lb})
        else:
            return serialize_to_json({
                "error": f"Load balancer not found with identifier: {identifier}",
                "load_balancer": None
            })
    except Exception as e:
        logger.error("Error in search_load_balancer: %s", e)
        return serialize_to_json({
            "error": str(e),
            "load_balancer": None
        })


@register_tool('describe_listeners_by_arns')
async def describe_listeners_by_arns(
    listener_arns: List[str],
    session_context: Optional[str] = None
) -> str:
    """Describe listeners by their ARNs.
    
    Args:
        listener_arns: List of listener ARNs
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with listener information
        
    Examples:
        # Single account (default)
        describe_listeners_by_arns(["arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/1234567890123456/1234567890123456"])
        
        # Cross-account access
        describe_listeners_by_arns(["arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/1234567890123456/1234567890123456"], session_context="123456789012_aws_dev")
    """
    logger.info("Describing listeners with ARNs: %s", listener_arns)
    
    if not listener_arns:
        return serialize_to_json({
            "error": "No listener ARNs provided",
            "listeners": []
        })
    
    try:
        result = load_balancer.describe_listeners(listener_arns=listener_arns, session_context=session_context)
        return serialize_to_json(result)
    except Exception as e:
        logger.error("Error in describe_listeners_by_arns: %s", e)
        return serialize_to_json({
            "error": str(e),
            "listeners": []
        })


@register_tool('get_load_balancer_by_arn')
async def get_load_balancer_by_arn(load_balancer_arn: str, session_context: Optional[str] = None) -> str:
    """Get load balancer by its ARN.
    
    Args:
        load_balancer_arn: ARN of the load balancer
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with load balancer information
        
    Examples:
        # Single account (default)
        get_load_balancer_by_arn("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456")
        
        # Cross-account access
        get_load_balancer_by_arn("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456", session_context="123456789012_aws_dev")
    """
    logger.info("Getting load balancer by ARN: %s", load_balancer_arn)
    
    if not load_balancer_arn.startswith('arn:aws:elasticloadbalancing:'):
        return serialize_to_json({
            "error": f"Invalid load balancer ARN format: {load_balancer_arn}",
            "load_balancer": None
        })
    
    try:
        result = load_balancer.search_load_balancer(load_balancer_arn, session_context=session_context)
        if result:
            return serialize_to_json({"load_balancer": result})
        else:
            return serialize_to_json({
                "error": f"Load balancer not found with ARN: {load_balancer_arn}",
                "load_balancer": None
            })
    except Exception as e:
        logger.error("Error in get_load_balancer_by_arn: %s", e)
        return serialize_to_json({
            "error": str(e),
            "load_balancer": None
        }) 