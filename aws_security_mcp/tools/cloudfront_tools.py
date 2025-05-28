"""CloudFront tools for AWS Security MCP."""

import logging
import json
import re
from typing import Optional, List, Dict, Any, Tuple

from aws_security_mcp.services import cloudfront
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)


def parse_cloudfront_domain(domain_name: str) -> Optional[str]:
    """Parse a CloudFront domain name to extract the distribution ID.
    
    Args:
        domain_name: The CloudFront domain name (e.g., d1234abcdef8ghi.cloudfront.net)
        
    Returns:
        The CloudFront distribution ID or None if not a valid CloudFront domain
    """
    # CloudFront domains follow the pattern: [distribution_id].cloudfront.net
    cloudfront_regex = r'^([a-z0-9]+)\.cloudfront\.net$'
    match = re.match(cloudfront_regex, domain_name.lower())
    if match:
        return match.group(1)
    return None


@register_tool()
async def list_distributions(limit: int = 1000, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List CloudFront distributions in the AWS account.
    
    Args:
        limit: Maximum number of distributions to return (default: 1000)
        next_token: Token for pagination (from previous request)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with CloudFront distributions
        
    Examples:
        # Single account (default)
        list_distributions()
        
        # Cross-account access
        list_distributions(session_context="123456789012_aws_dev")
    """
    logger.info(f"Listing CloudFront distributions (limit={limit}, next_token={next_token}, session_context={session_context})")
    
    try:
        # Pass limit directly - the service will handle the type conversion internally 
        response = cloudfront.list_distributions(max_items=limit, next_token=next_token, session_context=session_context)
        distributions = response.get("distributions", [])
        next_token = response.get("next_token")
        is_truncated = response.get("is_truncated", False)
        
        if not distributions:
            return json.dumps({
                "summary": "No CloudFront distributions found",
                "count": 0,
                "distributions": []
            })
        
        formatted_distributions = []
        for distribution in distributions:
            # Extract basic information
            distribution_id = distribution.get('Id', 'Unknown')
            domain_name = distribution.get('DomainName', 'Unknown')
            status = distribution.get('Status', 'Unknown')
            enabled = distribution.get('Enabled', False)
            
            # Get origins
            origins = distribution.get('Origins', {}).get('Items', [])
            origin_count = len(origins)
            
            # Get cache behaviors
            cache_behaviors = distribution.get('CacheBehaviors', {}).get('Items', [])
            cache_behavior_count = len(cache_behaviors)
            
            # Format as JSON object
            dist_data = {
                "distribution_id": distribution_id,
                "domain_name": domain_name,
                "status": status,
                "enabled": enabled,
                "origin_count": origin_count,
                "cache_behavior_count": cache_behavior_count
            }
            
            # Add origins summary
            if origins:
                dist_data["origins"] = []
                for origin in origins:  # Include all origins
                    origin_id = origin.get('Id', 'Unknown')
                    origin_domain = origin.get('DomainName', 'Unknown')
                    dist_data["origins"].append({
                        "id": origin_id,
                        "domain_name": origin_domain
                    })
            
            # Add aliases if available
            aliases = distribution.get('Aliases', {}).get('Items', [])
            if aliases:
                dist_data["aliases"] = aliases  # Include all aliases
            
            formatted_distributions.append(dist_data)
        
        result = {
            "summary": f"Found {len(distributions)} CloudFront distribution(s)",
            "count": len(distributions),
            "distributions": formatted_distributions,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_token
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing CloudFront distributions: {e}")
        return json.dumps({
            "error": {
                "message": f"Error listing CloudFront distributions: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def get_distribution_details(distribution_id: str, session_context: Optional[str] = None) -> str:
    """Get detailed information about a specific CloudFront distribution.
    
    Args:
        distribution_id: ID of the CloudFront distribution or domain name
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with distribution details
        
    Examples:
        # Single account (default)
        get_distribution_details("E1A2B3C4D5E6F7")
        
        # Cross-account access
        get_distribution_details("E1A2B3C4D5E6F7", session_context="123456789012_aws_dev")
    """
    logger.info(f"Getting details for CloudFront distribution: {distribution_id}")
    
    try:
        # Check if input is a domain name rather than a distribution ID
        actual_distribution_id = distribution_id
        
        # Handle CloudFront domain name format (d1234abcdef8ghi.cloudfront.net)
        if '.cloudfront.net' in distribution_id.lower():
            parsed_id = parse_cloudfront_domain(distribution_id)
            if parsed_id:
                logger.info(f"Parsed CloudFront domain {distribution_id} to distribution ID: {parsed_id}")
                actual_distribution_id = parsed_id
        
        distribution = cloudfront.get_distribution(actual_distribution_id, session_context=session_context)
        
        if not distribution:
            error_msg = f"CloudFront distribution '{distribution_id}' not found"
            if actual_distribution_id != distribution_id:
                error_msg += f" (parsed domain to distribution ID '{actual_distribution_id}')"
            
            return json.dumps({
                "error": {
                    "message": error_msg,
                    "type": "ResourceNotFound"
                }
            })
        
        # Extract distribution configuration
        config = distribution.get('DistributionConfig', {})
        
        # Basic information
        result = {
            "distribution_id": distribution.get('Id', 'Unknown'),
            "domain_name": distribution.get('DomainName', 'Unknown'),
            "arn": distribution.get('ARN', 'Unknown'),
            "status": distribution.get('Status', 'Unknown'),
            "enabled": config.get('Enabled', False),
            "http_version": config.get('HttpVersion', 'Unknown'),
            "price_class": config.get('PriceClass', 'Unknown')
        }
        
        # HTTPS/SSL information
        viewer_cert = config.get('ViewerCertificate', {})
        if viewer_cert:
            cert_source = "Unknown"
            
            if "CloudFrontDefaultCertificate" in viewer_cert and viewer_cert["CloudFrontDefaultCertificate"]:
                cert_source = "CloudFront Default"
            elif "IAMCertificateId" in viewer_cert and viewer_cert["IAMCertificateId"]:
                cert_source = f"IAM: {viewer_cert['IAMCertificateId']}"
            elif "ACMCertificateArn" in viewer_cert and viewer_cert["ACMCertificateArn"]:
                cert_source = f"ACM: {viewer_cert['ACMCertificateArn']}"
            
            result["certificate"] = {
                "source": cert_source,
                "ssl_support_method": viewer_cert.get('SSLSupportMethod', 'Unknown'),
                "minimum_protocol_version": viewer_cert.get('MinimumProtocolVersion', 'Unknown')
            }
        
        # Origins
        origins = config.get('Origins', {}).get('Items', [])
        if origins:
            result["origins"] = []
            for origin in origins:
                origin_data = {
                    "id": origin.get('Id', 'Unknown'),
                    "domain_name": origin.get('DomainName', 'Unknown')
                }
                
                # S3 origin specific
                if "S3OriginConfig" in origin:
                    origin_data["type"] = "S3"
                    if "OriginAccessIdentity" in origin["S3OriginConfig"]:
                        origin_data["origin_access_identity"] = origin['S3OriginConfig']['OriginAccessIdentity']
                
                # Custom origin specific
                if "CustomOriginConfig" in origin:
                    origin_data["type"] = "Custom"
                    custom_origin = origin["CustomOriginConfig"]
                    origin_data["http_port"] = custom_origin.get('HTTPPort', 'Unknown')
                    origin_data["https_port"] = custom_origin.get('HTTPSPort', 'Unknown')
                    origin_data["origin_protocol_policy"] = custom_origin.get('OriginProtocolPolicy', 'Unknown')
                
                result["origins"].append(origin_data)
        
        # Default cache behavior
        default_cache = config.get('DefaultCacheBehavior', {})
        if default_cache:
            result["default_cache_behavior"] = {
                "target_origin_id": default_cache.get('TargetOriginId', 'Unknown'),
                "viewer_protocol_policy": default_cache.get('ViewerProtocolPolicy', 'Unknown'),
                "allowed_methods": default_cache.get('AllowedMethods', {}).get('Items', ['Unknown']),
                "cached_methods": default_cache.get('AllowedMethods', {}).get('CachedMethods', {}).get('Items', ['Unknown'])
            }
            
            forwarded = default_cache.get('ForwardedValues', {})
            result["default_cache_behavior"]["forwarded_values"] = {
                "query_string": forwarded.get('QueryString', False),
                "cookies": forwarded.get('Cookies', {}).get('Forward', 'Unknown'),
                "headers": forwarded.get('Headers', {}).get('Items', [])
            }
        
        # Cache behaviors
        cache_behaviors = config.get('CacheBehaviors', {}).get('Items', [])
        if cache_behaviors:
            result["cache_behaviors"] = []
            for behavior in cache_behaviors:
                behavior_data = {
                    "path_pattern": behavior.get('PathPattern', 'Unknown'),
                    "target_origin_id": behavior.get('TargetOriginId', 'Unknown'),
                    "viewer_protocol_policy": behavior.get('ViewerProtocolPolicy', 'Unknown')
                }
                result["cache_behaviors"].append(behavior_data)
        
        # Restrictions
        restrictions = config.get('Restrictions', {}).get('GeoRestriction', {})
        if restrictions:
            result["geo_restrictions"] = {
                "type": restrictions.get('RestrictionType', 'None'),
                "locations": restrictions.get('Items', [])
            }
        
        # Aliases
        aliases = config.get('Aliases', {}).get('Items', [])
        if aliases:
            result["aliases"] = aliases
        
        # Tags
        tags = cloudfront.get_distribution_tags(actual_distribution_id, session_context=session_context)
        if tags:
            result["tags"] = tags
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error getting CloudFront distribution details: {e}")
        return json.dumps({
            "error": {
                "message": f"Error getting details for CloudFront distribution '{distribution_id}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def list_cache_policies(limit: int = 100, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List CloudFront cache policies.
    
    Args:
        limit: Maximum number of policies to return (default: 100)
        next_token: Token for pagination (from previous request)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with cache policies
        
    Examples:
        # Single account (default)
        list_cache_policies()
        
        # Cross-account access
        list_cache_policies(session_context="123456789012_aws_dev")
    """
    logger.info(f"Listing CloudFront cache policies (limit={limit}, next_token={next_token}, session_context={session_context})")
    
    try:
        # Ensure max_items is passed as a string as expected by the service module
        response = cloudfront.list_cache_policies(max_items=str(limit), next_token=next_token, session_context=session_context)
        policies = response.get("policies", [])
        next_token = response.get("next_token")
        is_truncated = response.get("is_truncated", False)
        
        if not policies:
            return json.dumps({
                "summary": "No CloudFront cache policies found",
                "count": 0,
                "policies": []
            })
        
        formatted_policies = []
        for policy in policies:
            # Extract basic information
            policy_id = policy.get('Id', 'Unknown')
            policy_name = policy.get('CachePolicy', {}).get('CachePolicyConfig', {}).get('Name', 'Unknown')
            comment = policy.get('CachePolicy', {}).get('CachePolicyConfig', {}).get('Comment', '')
            
            # Format as JSON object
            policy_data = {
                "policy_id": policy_id,
                "name": policy_name
            }
            
            if comment:
                policy_data["comment"] = comment
            
            formatted_policies.append(policy_data)
        
        result = {
            "summary": f"Found {len(policies)} CloudFront cache policy(s)",
            "count": len(policies),
            "policies": formatted_policies,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_token
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing CloudFront cache policies: {e}")
        if "Parameter validation failed" in str(e):
            return json.dumps({
                "error": {
                    "message": f"Error listing CloudFront cache policies: {str(e)}",
                    "type": "ParameterValidationError",
                    "details": "This might be due to an invalid parameter type. Please ensure all parameters have the correct type."
                }
            })
        return json.dumps({
            "error": {
                "message": f"Error listing CloudFront cache policies: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def list_origin_request_policies(limit: int = 100, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List CloudFront origin request policies.
    
    Args:
        limit: Maximum number of policies to return (default: 100)
        next_token: Token for pagination (from previous request)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with origin request policies
        
    Examples:
        # Single account (default)
        list_origin_request_policies()
        
        # Cross-account access
        list_origin_request_policies(session_context="123456789012_aws_dev")
    """
    logger.info(f"Listing CloudFront origin request policies (limit={limit}, next_token={next_token}, session_context={session_context})")
    
    try:
        # Ensure max_items is passed as a string as expected by the service module
        response = cloudfront.list_origin_request_policies(max_items=str(limit), next_token=next_token, session_context=session_context)
        policies = response.get("policies", [])
        next_token = response.get("next_token")
        is_truncated = response.get("is_truncated", False)
        
        if not policies:
            return json.dumps({
                "summary": "No CloudFront origin request policies found",
                "count": 0,
                "policies": []
            })
        
        formatted_policies = []
        for policy in policies:
            # Extract basic information
            policy_id = policy.get('Id', 'Unknown')
            policy_name = policy.get('OriginRequestPolicy', {}).get('OriginRequestPolicyConfig', {}).get('Name', 'Unknown')
            comment = policy.get('OriginRequestPolicy', {}).get('OriginRequestPolicyConfig', {}).get('Comment', '')
            
            # Format as JSON object
            policy_data = {
                "policy_id": policy_id,
                "name": policy_name
            }
            
            if comment:
                policy_data["comment"] = comment
            
            formatted_policies.append(policy_data)
        
        result = {
            "summary": f"Found {len(policies)} CloudFront origin request policy(s)",
            "count": len(policies),
            "policies": formatted_policies,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_token
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing CloudFront origin request policies: {e}")
        if "Parameter validation failed" in str(e):
            return json.dumps({
                "error": {
                    "message": f"Error listing CloudFront origin request policies: {str(e)}",
                    "type": "ParameterValidationError",
                    "details": "This might be due to an invalid parameter type. Please ensure all parameters have the correct type."
                }
            })
        return json.dumps({
            "error": {
                "message": f"Error listing CloudFront origin request policies: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def list_response_headers_policies(limit: int = 100, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """List CloudFront response headers policies.
    
    Args:
        limit: Maximum number of policies to return (default: 100)
        next_token: Token for pagination (from previous request)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with response headers policies
        
    Examples:
        # Single account (default)
        list_response_headers_policies()
        
        # Cross-account access
        list_response_headers_policies(session_context="123456789012_aws_dev")
    """
    logger.info(f"Listing CloudFront response headers policies (limit={limit}, next_token={next_token}, session_context={session_context})")
    
    try:
        # Ensure max_items is passed as a string as expected by the service module
        response = cloudfront.list_response_headers_policies(max_items=str(limit), next_token=next_token, session_context=session_context)
        policies = response.get("policies", [])
        next_token = response.get("next_token")
        is_truncated = response.get("is_truncated", False)
        
        if not policies:
            return json.dumps({
                "summary": "No CloudFront response headers policies found",
                "count": 0,
                "policies": []
            })
        
        formatted_policies = []
        for policy in policies:
            # Extract basic information
            policy_id = policy.get('Id', 'Unknown')
            policy_name = policy.get('ResponseHeadersPolicy', {}).get('ResponseHeadersPolicyConfig', {}).get('Name', 'Unknown')
            comment = policy.get('ResponseHeadersPolicy', {}).get('ResponseHeadersPolicyConfig', {}).get('Comment', '')
            
            # Format as JSON object
            policy_data = {
                "policy_id": policy_id,
                "name": policy_name
            }
            
            if comment:
                policy_data["comment"] = comment
            
            formatted_policies.append(policy_data)
        
        result = {
            "summary": f"Found {len(policies)} CloudFront response headers policy(s)",
            "count": len(policies),
            "policies": formatted_policies,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_token
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error listing CloudFront response headers policies: {e}")
        if "Parameter validation failed" in str(e):
            return json.dumps({
                "error": {
                    "message": f"Error listing CloudFront response headers policies: {str(e)}",
                    "type": "ParameterValidationError",
                    "details": "This might be due to an invalid parameter type. Please ensure all parameters have the correct type."
                }
            })
        return json.dumps({
            "error": {
                "message": f"Error listing CloudFront response headers policies: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def get_distribution_invalidations(distribution_id: str, limit: int = 100, next_token: Optional[str] = None, session_context: Optional[str] = None) -> str:
    """Get invalidations for a specific CloudFront distribution.
    
    Args:
        distribution_id: ID of the CloudFront distribution
        limit: Maximum number of invalidations to return (default: 100)
        next_token: Token for pagination (from previous request)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with invalidation details
        
    Examples:
        # Single account (default)
        get_distribution_invalidations("E1A2B3C4D5E6F7")
        
        # Cross-account access
        get_distribution_invalidations("E1A2B3C4D5E6F7", session_context="123456789012_aws_dev")
    """
    logger.info(f"Getting invalidations for CloudFront distribution: {distribution_id} (limit={limit}, next_token={next_token}, session_context={session_context})")
    
    try:
        # Ensure max_items is passed as a string as expected by the service module
        response = cloudfront.list_invalidations(distribution_id=distribution_id, max_items=str(limit), next_token=next_token, session_context=session_context)
        invalidations = response.get("invalidations", [])
        next_token = response.get("next_token")
        is_truncated = response.get("is_truncated", False)
        
        if not invalidations:
            return json.dumps({
                "summary": f"No invalidations found for CloudFront distribution '{distribution_id}'",
                "distribution_id": distribution_id,
                "count": 0,
                "invalidations": []
            })
        
        formatted_invalidations = []
        for invalidation in invalidations:
            invalidation_id = invalidation.get('Id', 'Unknown')
            status = invalidation.get('Status', 'Unknown')
            create_time = invalidation.get('CreateTime', 'Unknown')
            
            invalidation_data = {
                "invalidation_id": invalidation_id,
                "status": status,
                "create_time": str(create_time) if create_time else None
            }
            
            formatted_invalidations.append(invalidation_data)
        
        result = {
            "summary": f"Found {len(invalidations)} invalidation(s) for CloudFront distribution '{distribution_id}'",
            "distribution_id": distribution_id,
            "count": len(invalidations),
            "invalidations": formatted_invalidations,
            "pagination": {
                "is_truncated": is_truncated,
                "next_token": next_token
            } if is_truncated else None
        }
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error getting CloudFront invalidations: {e}")
        if "Parameter validation failed" in str(e):
            return json.dumps({
                "error": {
                    "message": f"Error getting invalidations for CloudFront distribution '{distribution_id}': {str(e)}",
                    "type": "ParameterValidationError",
                    "details": "This might be due to an invalid parameter type. Please ensure all parameters have the correct type."
                }
            })
        return json.dumps({
            "error": {
                "message": f"Error getting invalidations for CloudFront distribution '{distribution_id}': {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def search_distribution(identifier: str, session_context: Optional[str] = None) -> str:
    """Search for a CloudFront distribution by domain name, distribution ID, or alias.
    
    This tool searches for CloudFront distributions using the provided identifier,
    which can be a CloudFront domain name (e.g., d1234abcdef8ghi.cloudfront.net),
    a distribution ID (e.g., E1A2B3C4D5E6F7), or a custom domain alias.
    
    Args:
        identifier: CloudFront domain name, distribution ID, or alias
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with distribution details if found
        
    Examples:
        # Single account (default)
        search_distribution("example.com")
        
        # Cross-account access
        search_distribution("example.com", session_context="123456789012_aws_dev")
    """
    logger.info(f"Searching for CloudFront distribution with identifier: {identifier}")
    
    try:
        # Check if input might be a CloudFront domain
        if '.cloudfront.net' in identifier.lower():
            # Extract distribution ID from the domain if possible
            distribution_id = parse_cloudfront_domain(identifier)
            if distribution_id:
                logger.info(f"Parsed CloudFront domain {identifier} to distribution ID: {distribution_id}")
        
        # Search for the distribution
        distribution = cloudfront.search_distribution(identifier, session_context=session_context)
        
        if not distribution:
            return json.dumps({
                "error": {
                    "message": f"CloudFront distribution not found with identifier: {identifier}",
                    "type": "ResourceNotFound"
                }
            })
        
        # Extract distribution configuration
        config = distribution.get('DistributionConfig', {})
        
        # Basic information
        result = {
            "distribution_id": distribution.get('Id', 'Unknown'),
            "domain_name": distribution.get('DomainName', 'Unknown'),
            "arn": distribution.get('ARN', 'Unknown'),
            "status": distribution.get('Status', 'Unknown'),
            "enabled": config.get('Enabled', False),
            "http_version": config.get('HttpVersion', 'Unknown'),
            "price_class": config.get('PriceClass', 'Unknown')
        }
        
        # HTTPS/SSL information
        viewer_cert = config.get('ViewerCertificate', {})
        if viewer_cert:
            cert_source = "Unknown"
            
            if "CloudFrontDefaultCertificate" in viewer_cert and viewer_cert["CloudFrontDefaultCertificate"]:
                cert_source = "CloudFront Default"
            elif "IAMCertificateId" in viewer_cert and viewer_cert["IAMCertificateId"]:
                cert_source = f"IAM: {viewer_cert['IAMCertificateId']}"
            elif "ACMCertificateArn" in viewer_cert and viewer_cert["ACMCertificateArn"]:
                cert_source = f"ACM: {viewer_cert['ACMCertificateArn']}"
            
            result["certificate"] = {
                "source": cert_source,
                "ssl_support_method": viewer_cert.get('SSLSupportMethod', 'Unknown'),
                "minimum_protocol_version": viewer_cert.get('MinimumProtocolVersion', 'Unknown')
            }
        
        # Origins
        origins = config.get('Origins', {}).get('Items', [])
        if origins:
            result["origins"] = []
            for origin in origins:
                origin_data = {
                    "id": origin.get('Id', 'Unknown'),
                    "domain_name": origin.get('DomainName', 'Unknown')
                }
                
                # S3 origin specific
                if "S3OriginConfig" in origin:
                    origin_data["type"] = "S3"
                    if "OriginAccessIdentity" in origin["S3OriginConfig"]:
                        origin_data["origin_access_identity"] = origin['S3OriginConfig']['OriginAccessIdentity']
                
                # Custom origin specific
                if "CustomOriginConfig" in origin:
                    origin_data["type"] = "Custom"
                    custom_origin = origin["CustomOriginConfig"]
                    origin_data["http_port"] = custom_origin.get('HTTPPort', 'Unknown')
                    origin_data["https_port"] = custom_origin.get('HTTPSPort', 'Unknown')
                    origin_data["origin_protocol_policy"] = custom_origin.get('OriginProtocolPolicy', 'Unknown')
                
                result["origins"].append(origin_data)
        
        # Aliases
        aliases = config.get('Aliases', {}).get('Items', [])
        if aliases:
            result["aliases"] = aliases
        
        # Tags
        tags = cloudfront.get_distribution_tags(distribution.get('Id', ''), session_context=session_context)
        if tags:
            result["tags"] = tags
        
        return json.dumps({
            "message": f"Found CloudFront distribution matching: {identifier}",
            "distribution": result
        })
    except Exception as e:
        logger.error(f"Error searching for CloudFront distribution: {e}")
        return json.dumps({
            "error": {
                "message": f"Error searching for CloudFront distribution with identifier '{identifier}': {str(e)}",
                "type": type(e).__name__
            }
        })
