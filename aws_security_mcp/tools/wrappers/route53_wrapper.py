"""Route53 Service Wrapper for AWS Security MCP.

This wrapper consolidates all AWS Route53 operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing Route53 functions to reuse them
from aws_security_mcp.tools.route53_tools import (
    list_hosted_zones as _list_hosted_zones,
    get_hosted_zone_details as _get_hosted_zone_details,
    list_resource_record_sets as _list_resource_record_sets,
    list_health_checks as _list_health_checks,
    list_traffic_policies as _list_traffic_policies,
    check_subdomain_takeover_vulnerability as _check_subdomain_takeover_vulnerability,
    find_ip_address_details as _find_ip_address_details,
    analyze_domain_security as _analyze_domain_security
)

logger = logging.getLogger(__name__)

@register_tool()
async def route53_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """Route53 Security Operations Hub - Comprehensive AWS Route53 DNS security monitoring.
    
    🌐 HOSTED ZONE MANAGEMENT:
    - list_hosted_zones: List all Route53 hosted zones with configuration details
    - get_hosted_zone_details: Get comprehensive details about a specific hosted zone
    
    📋 DNS RECORD ANALYSIS:
    - list_resource_record_sets: List DNS records in a specific hosted zone
    
    🔍 HEALTH & MONITORING:
    - list_health_checks: List Route53 health checks and their configurations
    - list_traffic_policies: List Route53 traffic policies for advanced routing
    
    🚨 SECURITY ANALYSIS:
    - check_subdomain_takeover: Check domain/subdomain for takeover vulnerabilities
    - find_ip_details: Find details about an IP address and associated resources
    - analyze_domain_security: Comprehensive security analysis of a domain
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🌐 List all hosted zones:
    operation="list_hosted_zones"
    
    🔍 Get hosted zone details:
    operation="get_hosted_zone_details", zone_id="Z1234567890ABC"
    
    📋 List DNS records in zone:
    operation="list_resource_record_sets", zone_id="Z1234567890ABC"
    
    🔍 List health checks:
    operation="list_health_checks"
    
    📊 List traffic policies:
    operation="list_traffic_policies"
    
    🚨 Check subdomain takeover:
    operation="check_subdomain_takeover", domain_name="subdomain.example.com"
    
    🔍 Find IP address details:
    operation="find_ip_details", ip_address="192.168.1.1"
    
    🛡️ Analyze domain security:
    operation="analyze_domain_security", domain_name="example.com"
    
    Args:
        operation: The Route53 operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access
        
        # Zone parameters:
        zone_id: Route53 hosted zone ID (with or without /hostedzone/ prefix)
        limit: Maximum number of items to return (default varies by operation)
        next_token: Pagination token for continued requests
        
        # Domain/IP parameters:
        domain_name: Domain name for security analysis or subdomain takeover checks
        ip_address: IP address for detailed lookup and analysis
        
    Returns:
        JSON formatted response with operation results and Route53 security insights
    """
    
    logger.info(f"Route53 operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_hosted_zones":
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            return await _list_hosted_zones(limit=limit, next_token=next_token, session_context=session_context)
            
        elif operation == "get_hosted_zone_details":
            zone_id = params.get("zone_id")
            if not zone_id:
                return json.dumps({
                    "error": "zone_id parameter is required for get_hosted_zone_details",
                    "usage": "operation='get_hosted_zone_details', zone_id='Z1234567890ABC'"
                })
            
            return await _get_hosted_zone_details(zone_id=zone_id, session_context=session_context)
            
        elif operation == "list_resource_record_sets":
            zone_id = params.get("zone_id")
            if not zone_id:
                return json.dumps({
                    "error": "zone_id parameter is required for list_resource_record_sets",
                    "usage": "operation='list_resource_record_sets', zone_id='Z1234567890ABC'"
                })
            
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            return await _list_resource_record_sets(
                zone_id=zone_id,
                limit=limit,
                next_token=next_token,
                session_context=session_context
            )
            
        elif operation == "list_health_checks":
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            return await _list_health_checks(limit=limit, next_token=next_token, session_context=session_context)
            
        elif operation == "list_traffic_policies":
            limit = params.get("limit", 100)
            next_token = params.get("next_token")
            
            return await _list_traffic_policies(limit=limit, next_token=next_token, session_context=session_context)
            
        elif operation == "check_subdomain_takeover":
            domain_name = params.get("domain_name")
            if not domain_name:
                return json.dumps({
                    "error": "domain_name parameter is required for check_subdomain_takeover",
                    "usage": "operation='check_subdomain_takeover', domain_name='subdomain.example.com'"
                })
            
            return await _check_subdomain_takeover_vulnerability(domain_name=domain_name, session_context=session_context)
            
        elif operation == "find_ip_details":
            ip_address = params.get("ip_address")
            if not ip_address:
                return json.dumps({
                    "error": "ip_address parameter is required for find_ip_details",
                    "usage": "operation='find_ip_details', ip_address='192.168.1.1'"
                })
            
            return await _find_ip_address_details(ip_address=ip_address, session_context=session_context)
            
        elif operation == "analyze_domain_security":
            domain_name = params.get("domain_name")
            if not domain_name:
                return json.dumps({
                    "error": "domain_name parameter is required for analyze_domain_security",
                    "usage": "operation='analyze_domain_security', domain_name='example.com'"
                })
            
            return await _analyze_domain_security(domain_name=domain_name, session_context=session_context)
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_hosted_zones", "get_hosted_zone_details", "list_resource_record_sets",
                "list_health_checks", "list_traffic_policies", "check_subdomain_takeover",
                "find_ip_details", "analyze_domain_security"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_hosted_zones": "operation='list_hosted_zones'",
                    "get_hosted_zone_details": "operation='get_hosted_zone_details', zone_id='Z1234567890ABC'",
                    "list_resource_record_sets": "operation='list_resource_record_sets', zone_id='Z1234567890ABC'",
                    "check_subdomain_takeover": "operation='check_subdomain_takeover', domain_name='subdomain.example.com'",
                    "analyze_domain_security": "operation='analyze_domain_security', domain_name='example.com'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in Route53 operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing Route53 operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_route53_operations(session_context: Optional[str] = None) -> str:
    """Discover all available AWS Route53 operations with detailed usage examples.
    
    This tool provides comprehensive documentation of Route53 operations available
    through the route53_security_operations tool, including parameter requirements
    and practical usage examples for DNS security monitoring and domain protection.
    
    Returns:
        Detailed catalog of Route53 operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Route53 (Domain Name System)",
        "description": "DNS management, domain security monitoring, and subdomain takeover protection",
        "wrapper_tool": "route53_security_operations",
        "supported_features": {
            "hosted_zone_management": "Monitor and analyze Route53 hosted zones and configurations",
            "dns_record_analysis": "Comprehensive analysis of DNS records and routing policies",
            "health_monitoring": "Track health checks and traffic policies for availability",
            "security_assessment": "Detect subdomain takeover vulnerabilities and domain security issues"
        },
        "operation_categories": {
            "hosted_zone_management": {
                "list_hosted_zones": {
                    "description": "List all Route53 hosted zones with configuration details",
                    "parameters": {
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of zones to return"},
                        "next_token": {"type": "str", "description": "Pagination token from previous request"}
                    },
                    "examples": [
                        "route53_security_operations(operation='list_hosted_zones')",
                        "route53_security_operations(operation='list_hosted_zones', limit=50)",
                        "route53_security_operations(operation='list_hosted_zones', next_token='abc123')"
                    ],
                    "returns": [
                        "Complete list of hosted zones with metadata",
                        "Zone IDs, names, and record counts",
                        "Private zone indicators and comments",
                        "Pagination information for large datasets"
                    ]
                },
                "get_hosted_zone_details": {
                    "description": "Get comprehensive details about a specific hosted zone",
                    "parameters": {
                        "zone_id": {"type": "str", "required": True, "description": "Route53 hosted zone ID (with or without /hostedzone/ prefix)"}
                    },
                    "examples": [
                        "route53_security_operations(operation='get_hosted_zone_details', zone_id='Z1234567890ABC')",
                        "route53_security_operations(operation='get_hosted_zone_details', zone_id='/hostedzone/Z1234567890ABC')"
                    ],
                    "returns": [
                        "Detailed zone configuration and settings",
                        "Name servers and delegation set information",
                        "VPC associations for private zones",
                        "Zone tags and metadata",
                        "Record count and zone status"
                    ]
                }
            },
            "dns_record_analysis": {
                "list_resource_record_sets": {
                    "description": "List DNS records in a specific hosted zone",
                    "parameters": {
                        "zone_id": {"type": "str", "required": True, "description": "Route53 hosted zone ID"},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of records to return"},
                        "next_token": {"type": "str", "description": "Pagination token for continued requests"}
                    },
                    "examples": [
                        "route53_security_operations(operation='list_resource_record_sets', zone_id='Z1234567890ABC')",
                        "route53_security_operations(operation='list_resource_record_sets', zone_id='Z1234567890ABC', limit=50)"
                    ],
                    "returns": [
                        "Complete list of DNS records (A, AAAA, CNAME, MX, TXT, etc.)",
                        "Record values, TTL settings, and routing policies",
                        "Alias targets and health check associations",
                        "Geo-location and weighted routing configurations"
                    ]
                }
            },
            "health_monitoring": {
                "list_health_checks": {
                    "description": "List Route53 health checks and their configurations",
                    "parameters": {
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of health checks to return"},
                        "next_token": {"type": "str", "description": "Pagination token from previous request"}
                    },
                    "examples": [
                        "route53_security_operations(operation='list_health_checks')",
                        "route53_security_operations(operation='list_health_checks', limit=25)"
                    ],
                    "returns": [
                        "Complete list of health checks with configurations",
                        "Health check types (HTTP, HTTPS, TCP, calculated, CloudWatch)",
                        "Target endpoints, paths, and monitoring intervals",
                        "Health check status and failure thresholds"
                    ]
                },
                "list_traffic_policies": {
                    "description": "List Route53 traffic policies for advanced routing",
                    "parameters": {
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of policies to return"},
                        "next_token": {"type": "str", "description": "Pagination token from previous request"}
                    },
                    "examples": [
                        "route53_security_operations(operation='list_traffic_policies')",
                        "route53_security_operations(operation='list_traffic_policies', limit=10)"
                    ],
                    "returns": [
                        "List of traffic policies with metadata",
                        "Policy IDs, names, and latest versions",
                        "Policy comments and descriptions",
                        "Traffic routing configurations"
                    ]
                }
            },
            "security_assessment": {
                "check_subdomain_takeover": {
                    "description": "Check domain/subdomain for takeover vulnerabilities",
                    "parameters": {
                        "domain_name": {"type": "str", "required": True, "description": "Domain or subdomain name to check"}
                    },
                    "examples": [
                        "route53_security_operations(operation='check_subdomain_takeover', domain_name='subdomain.example.com')",
                        "route53_security_operations(operation='check_subdomain_takeover', domain_name='api.company.io')"
                    ],
                    "returns": [
                        "Vulnerability assessment with risk indicators",
                        "DNS record analysis and CNAME target validation",
                        "Service identification (AWS, GitHub, Heroku, etc.)",
                        "Resolution status and potential takeover risks",
                        "Detailed security recommendations"
                    ]
                },
                "find_ip_details": {
                    "description": "Find details about an IP address and associated AWS resources",
                    "parameters": {
                        "ip_address": {"type": "str", "required": True, "description": "IP address to analyze"}
                    },
                    "examples": [
                        "route53_security_operations(operation='find_ip_details', ip_address='192.168.1.1')",
                        "route53_security_operations(operation='find_ip_details', ip_address='43.205.186.36')"
                    ],
                    "returns": [
                        "Comprehensive AWS resource identification (EC2, ELB, RDS, Lambda, NAT Gateway, ECS, etc.)",
                        "Route53 DNS records pointing to the IP",
                        "Security group configurations and network interface details",
                        "VPC and subnet information with resource ownership",
                        "Resource tags and metadata for all associated services",
                        "Complete resource type classification and descriptions"
                    ]
                },
                "analyze_domain_security": {
                    "description": "Comprehensive security analysis of a domain",
                    "parameters": {
                        "domain_name": {"type": "str", "required": True, "description": "Domain name to analyze"}
                    },
                    "examples": [
                        "route53_security_operations(operation='analyze_domain_security', domain_name='example.com')",
                        "route53_security_operations(operation='analyze_domain_security', domain_name='api.company.io')"
                    ],
                    "returns": [
                        "Complete DNS security posture assessment",
                        "Subdomain takeover vulnerability analysis",
                        "Associated AWS resources and security configurations",
                        "Email security (SPF, DMARC) validation",
                        "Security recommendations and risk mitigation"
                    ]
                }
            }
        },
        "route53_security_insights": {
            "common_operations": [
                "List hosted zones: operation='list_hosted_zones'",
                "Analyze domain security: operation='analyze_domain_security', domain_name='example.com'",
                "Check subdomain takeover: operation='check_subdomain_takeover', domain_name='sub.example.com'",
                "Find IP details: operation='find_ip_details', ip_address='192.168.1.1'"
            ],
            "security_monitoring_patterns": [
                "Regular audit of DNS configurations and record types",
                "Monitor for subdomain takeover vulnerabilities",
                "Track changes in DNS records and routing policies",
                "Validate health check configurations and failover settings",
                "Review traffic policies for security implications",
                "Monitor for unauthorized DNS modifications"
            ],
            "dns_security_best_practices": [
                "Implement DNS Security Extensions (DNSSEC) where possible",
                "Regular audit of CNAME records for abandoned services",
                "Use Route53 Resolver DNS Firewall for malicious domain blocking",
                "Implement proper SPF, DKIM, and DMARC records for email security",
                "Monitor for DNS hijacking and unauthorized zone transfers",
                "Use private hosted zones for internal DNS resolution",
                "Implement least privilege access for Route53 management",
                "Regular review of health checks and failover configurations"
            ],
            "compliance_considerations": [
                "Ensure DNS configurations meet regulatory requirements",
                "Implement proper logging and monitoring for DNS queries",
                "Validate data residency requirements for DNS infrastructure",
                "Monitor for compliance with organizational DNS policies",
                "Ensure proper backup and disaster recovery for DNS",
                "Implement appropriate access controls and audit trails"
            ],
            "vulnerability_categories": [
                "Subdomain takeover risks (abandoned CNAME targets)",
                "DNS cache poisoning and spoofing vulnerabilities",
                "Zone transfer security and unauthorized access",
                "Weak or missing email security records (SPF/DMARC)",
                "Exposed internal DNS information",
                "Insecure health check configurations",
                "Traffic policy security implications"
            ],
            "integration_with_aws_services": [
                "CloudTrail for DNS API call monitoring",
                "CloudWatch for DNS query logging and metrics",
                "Config for DNS configuration compliance",
                "Security Hub for centralized DNS security findings",
                "GuardDuty for DNS-based threat detection"
            ]
        },
        "advanced_security_features": {
            "subdomain_takeover_detection": [
                "Automated scanning of CNAME records for vulnerable targets",
                "Service-specific vulnerability patterns (AWS, GitHub, etc.)",
                "DNS resolution validation and orphaned resource detection",
                "ELB and CloudFront endpoint validation",
                "Comprehensive risk assessment and remediation guidance"
            ],
            "domain_security_analysis": [
                "Complete DNS record inventory and security assessment",
                "Associated AWS resource security validation",
                "Email security configuration analysis",
                "Cross-service security correlation",
                "Risk-based security recommendations"
            ],
            "ip_address_intelligence": [
                "Comprehensive AWS resource association and ownership validation",
                "Multi-service resource type identification (EC2, ELB, RDS, Lambda, NAT Gateway, ECS)",
                "Security group and network ACL analysis",
                "Route53 record correlation and mapping",
                "Geographic and network-based risk assessment",
                "Resource relationship mapping and dependency analysis"
            ]
        },
        "automation_opportunities": [
            "Automated subdomain takeover monitoring and alerting",
            "DNS configuration compliance checking",
            "Health check validation and optimization",
            "Security record (SPF/DMARC) monitoring",
            "Orphaned DNS record detection and cleanup"
        ]
    }
    
    return json.dumps(operations_catalog, indent=2) 