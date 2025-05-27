"""Shield Service Wrapper for AWS Security MCP.

This wrapper consolidates all Shield operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing Shield functions to reuse them
from aws_security_mcp.tools.shield_tools import (
    get_shield_subscription_status as _get_shield_subscription_status,
    list_shield_protected_resources as _list_shield_protected_resources,
    list_shield_protections as _list_shield_protections,
    get_shield_protection_details as _get_shield_protection_details,
    list_shield_attacks as _list_shield_attacks,
    get_shield_attack_details as _get_shield_attack_details,
    get_shield_summary as _get_shield_summary
)

logger = logging.getLogger(__name__)

@register_tool()
async def shield_security_operations(operation: str, **params) -> str:
    """Shield Security Operations Hub - Comprehensive DDoS protection and attack monitoring.
    
    🛡️ SUBSCRIPTION MANAGEMENT:
    - get_subscription_status: Get Shield Advanced subscription status and billing information
    
    🔒 PROTECTION MONITORING:
    - list_protected_resources: List resources protected by Shield Advanced with type grouping
    - list_protections: List Shield protection configurations and settings
    - get_protection_details: Get detailed protection info for specific resource
    
    ⚔️ ATTACK ANALYSIS:
    - list_attacks: List DDoS attacks detected by Shield with timeline analysis
    - get_attack_details: Get detailed attack information with vectors and mitigation
    
    📊 COMPREHENSIVE OVERVIEW:
    - get_summary: Get complete Shield status with all key metrics
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🛡️ Check Shield subscription:
    operation="get_subscription_status"
    
    🔒 List all protected resources:
    operation="list_protected_resources", limit=100
    
    📋 Get protection configurations:
    operation="list_protections", limit=50
    
    🔍 Check specific resource protection:
    operation="get_protection_details", resource_arn="arn:aws:cloudfront::123456789012:distribution/EDFDVBD6EXAMPLE"
    
    ⚔️ List recent attacks:
    operation="list_attacks", days=7, limit=20
    
    🔍 Get attack details:
    operation="get_attack_details", attack_id="AttackId-12345678-1234-1234-1234-123456789012"
    
    📊 Get complete overview:
    operation="get_summary"
    
    Args:
        operation: The Shield operation to perform (see descriptions above)
        
        # Resource parameters:
        resource_arn: ARN of resource for protection details
        
        # Attack parameters:
        attack_id: ID of attack for detailed analysis
        days: Number of days to look back for attacks (default: 30)
        
        # Pagination parameters:
        limit: Maximum number of items to return (default: 100)
        next_token: Pagination token for large result sets
        
    Returns:
        JSON formatted response with operation results and Shield security insights
    """
    
    logger.info(f"Shield operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "get_subscription_status":
            result = await _get_shield_subscription_status()
            return json.dumps(result)
            
        elif operation == "list_protected_resources":
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            result = await _list_shield_protected_resources(
                limit=limit,
                next_token=next_token
            )
            return json.dumps(result)
            
        elif operation == "list_protections":
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            result = await _list_shield_protections(
                limit=limit,
                next_token=next_token
            )
            return json.dumps(result)
            
        elif operation == "get_protection_details":
            resource_arn = params.get("resource_arn")
            if not resource_arn:
                return json.dumps({
                    "error": "resource_arn parameter is required for get_protection_details",
                    "usage": "operation='get_protection_details', resource_arn='arn:aws:cloudfront::123456789012:distribution/EDFDVBD6EXAMPLE'"
                })
            
            result = await _get_shield_protection_details(resource_arn=resource_arn)
            return json.dumps(result)
            
        elif operation == "list_attacks":
            days = params.get("days", 30)
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            result = await _list_shield_attacks(
                days=days,
                limit=limit,
                next_token=next_token
            )
            return json.dumps(result)
            
        elif operation == "get_attack_details":
            attack_id = params.get("attack_id")
            if not attack_id:
                return json.dumps({
                    "error": "attack_id parameter is required for get_attack_details",
                    "usage": "operation='get_attack_details', attack_id='AttackId-12345678-1234-1234-1234-123456789012'"
                })
            
            result = await _get_shield_attack_details(attack_id=attack_id)
            return json.dumps(result)
            
        elif operation == "get_summary":
            result = await _get_shield_summary()
            return json.dumps(result)
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "get_subscription_status", "list_protected_resources", "list_protections",
                "get_protection_details", "list_attacks", "get_attack_details",
                "get_summary"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "get_subscription_status": "operation='get_subscription_status'",
                    "list_protected_resources": "operation='list_protected_resources', limit=100",
                    "get_protection_details": "operation='get_protection_details', resource_arn='arn:aws:cloudfront::123456789012:distribution/EXAMPLE'",
                    "list_attacks": "operation='list_attacks', days=7, limit=20"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in Shield operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing Shield operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_shield_operations() -> str:
    """Discover all available Shield operations with detailed usage examples.
    
    This tool provides comprehensive documentation of Shield operations available
    through the shield_security_operations tool, including parameter requirements
    and practical usage examples for DDoS protection and attack monitoring.
    
    Returns:
        Detailed catalog of Shield operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Shield",
        "description": "DDoS protection service for AWS resources with advanced threat detection and mitigation",
        "wrapper_tool": "shield_security_operations",
        "supported_features": {
            "ddos_protection": "Advanced DDoS protection for AWS resources",
            "attack_detection": "Real-time attack detection and analysis",
            "mitigation": "Automatic and manual DDoS mitigation capabilities",
            "response_team": "Access to AWS DDoS Response Team (DRT)",
            "cost_protection": "DDoS cost protection for scaling charges"
        },
        "operation_categories": {
            "subscription_management": {
                "get_subscription_status": {
                    "description": "Get Shield Advanced subscription status and billing information",
                    "parameters": {},
                    "examples": [
                        "shield_security_operations(operation='get_subscription_status')"
                    ]
                }
            },
            "protection_monitoring": {
                "list_protected_resources": {
                    "description": "List resources protected by Shield Advanced with type grouping and analysis",
                    "parameters": {
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of protected resources to return"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching next set of resources"}
                    },
                    "examples": [
                        "shield_security_operations(operation='list_protected_resources')",
                        "shield_security_operations(operation='list_protected_resources', limit=50)",
                        "shield_security_operations(operation='list_protected_resources', limit=100, next_token='token123')"
                    ]
                },
                "list_protections": {
                    "description": "List Shield protection configurations and settings",
                    "parameters": {
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of protections to return"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching next set of protections"}
                    },
                    "examples": [
                        "shield_security_operations(operation='list_protections')",
                        "shield_security_operations(operation='list_protections', limit=25)"
                    ]
                },
                "get_protection_details": {
                    "description": "Get detailed protection information for a specific resource",
                    "parameters": {
                        "resource_arn": {"type": "str", "required": True, "description": "ARN of the resource to get protection details for"}
                    },
                    "examples": [
                        "shield_security_operations(operation='get_protection_details', resource_arn='arn:aws:cloudfront::123456789012:distribution/EDFDVBD6EXAMPLE')",
                        "shield_security_operations(operation='get_protection_details', resource_arn='arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188')",
                        "shield_security_operations(operation='get_protection_details', resource_arn='arn:aws:ec2:us-east-1:123456789012:eip-allocation/eipalloc-12345678')"
                    ]
                }
            },
            "attack_analysis": {
                "list_attacks": {
                    "description": "List DDoS attacks detected by Shield with timeline analysis and statistics",
                    "parameters": {
                        "days": {"type": "int", "default": 30, "description": "Number of days to look back for attacks"},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of attacks to return"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching next set of attacks"}
                    },
                    "examples": [
                        "shield_security_operations(operation='list_attacks')",
                        "shield_security_operations(operation='list_attacks', days=7, limit=20)",
                        "shield_security_operations(operation='list_attacks', days=90, limit=50)",
                        "shield_security_operations(operation='list_attacks', days=1)"
                    ]
                },
                "get_attack_details": {
                    "description": "Get detailed attack information with vectors, mitigation actions, and timeline",
                    "parameters": {
                        "attack_id": {"type": "str", "required": True, "description": "ID of the attack to get details for"}
                    },
                    "examples": [
                        "shield_security_operations(operation='get_attack_details', attack_id='AttackId-12345678-1234-1234-1234-123456789012')"
                    ]
                }
            },
            "comprehensive_overview": {
                "get_summary": {
                    "description": "Get complete Shield status with all key metrics, protections, and recent activity",
                    "parameters": {},
                    "examples": [
                        "shield_security_operations(operation='get_summary')"
                    ]
                }
            }
        },
        "shield_security_insights": {
            "common_operations": [
                "Check subscription status: operation='get_subscription_status'",
                "List protected resources: operation='list_protected_resources'",
                "Monitor recent attacks: operation='list_attacks', days=7",
                "Get complete overview: operation='get_summary'"
            ],
            "ddos_protection_patterns": [
                "Monitor subscription status and billing regularly",
                "Review protected resources and ensure critical assets are covered",
                "Analyze attack patterns and trends over time",
                "Validate DRT access for emergency response",
                "Keep emergency contacts updated for incident response",
                "Review protection effectiveness after attacks",
                "Monitor cost protection benefits and scaling charges",
                "Coordinate with AWS DRT during active attacks"
            ],
            "supported_resource_types": [
                "CloudFront distributions",
                "Route 53 hosted zones", 
                "Elastic Load Balancers (ALB, NLB, CLB)",
                "EC2 Elastic IP addresses",
                "AWS Global Accelerator accelerators"
            ],
            "attack_types_detected": [
                "Volumetric attacks (floods, amplification)",
                "Protocol attacks (SYN floods, fragmented packet attacks)",
                "Application layer attacks (HTTP floods, slow connections)",
                "Reflection attacks (DNS, NTP, SSDP amplification)",
                "Multi-vector attacks (combination of attack types)"
            ],
            "mitigation_capabilities": [
                "Automatic DDoS detection and mitigation",
                "Traffic engineering and rate limiting",
                "Origin cloaking and traffic scrubbing",
                "Proactive engagement of DRT during attacks",
                "Real-time attack notifications and reporting",
                "Post-attack analysis and recommendations",
                "Cost protection for DDoS-related scaling",
                "Integration with AWS WAF for application layer protection"
            ],
            "security_best_practices": [
                "Enable Shield Advanced on all internet-facing resources",
                "Configure DRT access with appropriate IAM permissions",
                "Set up emergency contacts for 24/7 incident response",
                "Implement CloudWatch monitoring for DDoS metrics",
                "Use AWS WAF with Shield for application layer protection",
                "Regularly review and test incident response procedures",
                "Monitor attack trends and adjust protection accordingly",
                "Document DDoS response playbooks and procedures"
            ],
            "compliance_considerations": [
                "Maintain logs of all DDoS attacks and responses",
                "Document mitigation actions taken during incidents",
                "Regular review of protection coverage and effectiveness",
                "Ensure emergency contact information is current",
                "Track DDoS-related costs and protection benefits",
                "Validate incident response procedures regularly",
                "Maintain evidence of proactive DDoS protection measures"
            ],
            "monitoring_and_alerting": [
                "CloudWatch metrics for DDoS attack detection",
                "SNS notifications for attack events",
                "Integration with security incident management systems",
                "Real-time dashboards for attack monitoring",
                "Automated response workflows for common attack patterns",
                "Regular reporting on protection status and effectiveness"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 