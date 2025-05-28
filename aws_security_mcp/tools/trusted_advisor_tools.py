"""MCP tools for AWS Trusted Advisor security checks and recommendations."""

import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.services import trusted_advisor
from aws_security_mcp.tools import register_tool

logger = logging.getLogger(__name__)

@register_tool()
async def get_trusted_advisor_security_checks(session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get all security-related checks from AWS Trusted Advisor.
    
    This tool retrieves all security and fault tolerance checks available in AWS Trusted Advisor.
    Security checks help identify vulnerabilities and security risks in your AWS environment.
    
    Args:
        session_context: Optional session key for cross-account access
    
    Returns:
        Dict containing security checks information
    """
    logger.info("Getting Trusted Advisor security checks")
    result = await trusted_advisor.get_security_checks(session_context=session_context)
    
    # Format the response to focus on security details
    if result["success"]:
        formatted_checks = []
        for check in result.get("checks", []):
            formatted_check = {
                "id": check.get("id"),
                "name": check.get("name"),
                "category": check.get("category"),
                "description": check.get("description"),
                "status": check.get("status"),
                "risk_level": check.get("riskLevel", "unknown"),
                "resource_count": check.get("resourcesSummary", {}).get("resourcesCount", 0),
                "resources_flagged": check.get("resourcesSummary", {}).get("resourcesFlagged", 0),
                "last_updated": check.get("lastUpdatedAt")
            }
            formatted_checks.append(formatted_check)
        
        result["checks"] = formatted_checks
    
    return result

@register_tool()
async def list_trusted_advisor_security_recommendations(session_context: Optional[str] = None) -> Dict[str, Any]:
    """List all security recommendations from AWS Trusted Advisor.
    
    This tool retrieves security-focused recommendations that help you follow AWS
    best practices for security and compliance. These recommendations identify
    potential vulnerabilities and suggest mitigations.
    
    Args:
        session_context: Optional session key for cross-account access
    
    Returns:
        Dict containing security recommendations information
    """
    logger.info("Listing Trusted Advisor security recommendations")
    result = await trusted_advisor.list_security_recommendations(session_context=session_context)
    
    # Format the response to focus on security details
    if result["success"]:
        formatted_recommendations = []
        for rec in result.get("recommendations", []):
            formatted_rec = {
                "id": rec.get("recommendationId"),
                "name": rec.get("name"),
                "description": rec.get("description"),
                "categories": rec.get("categories", []),
                "risk_level": rec.get("pillarSpecificInfo", {}).get("SecurityPillar", {}).get("riskLevel", "unknown"),
                "affected_resources_count": rec.get("resourcesCount", 0),
                "last_updated": rec.get("lastUpdatedAt")
            }
            formatted_recommendations.append(formatted_rec)
        
        result["recommendations"] = formatted_recommendations
    
    return result

@register_tool()
async def get_trusted_advisor_recommendation_details(recommendation_id: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get detailed information about a specific Trusted Advisor security recommendation.
    
    This tool provides comprehensive details about a security recommendation,
    including its description, impact, and remediation suggestions.
    
    Args:
        recommendation_id: The ID of the recommendation to retrieve
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict containing recommendation details
    """
    logger.info(f"Getting details for Trusted Advisor recommendation: {recommendation_id}")
    result = await trusted_advisor.get_recommendation_details(recommendation_id, session_context=session_context)
    
    # Format the response to focus on security details
    if result["success"]:
        rec = result.get("recommendation", {})
        formatted_rec = {
            "id": rec.get("recommendationId"),
            "name": rec.get("name"),
            "description": rec.get("description"),
            "categories": rec.get("categories", []),
            "risk_level": rec.get("pillarSpecificInfo", {}).get("SecurityPillar", {}).get("riskLevel", "unknown"),
            "affected_resources_count": rec.get("resourcesCount", 0),
            "last_updated": rec.get("lastUpdatedAt"),
            "remediation": {
                "recommendation_text": rec.get("recommendationText"),
                "steps": rec.get("remediationSteps", [])
            }
        }
        
        result["recommendation"] = formatted_rec
    
    return result

@register_tool()
async def list_trusted_advisor_affected_resources(recommendation_id: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List resources affected by a specific Trusted Advisor security recommendation.
    
    This tool retrieves all AWS resources that are flagged by a particular security
    recommendation, allowing you to identify and remediate specific security issues.
    
    Args:
        recommendation_id: The ID of the recommendation
        session_context: Optional session key for cross-account access
        
    Returns:
        Dict containing affected resources information
    """
    logger.info(f"Listing affected resources for Trusted Advisor recommendation: {recommendation_id}")
    result = await trusted_advisor.list_recommendation_resources(recommendation_id, session_context=session_context)
    
    # Format the response to focus on security details
    if result["success"]:
        formatted_resources = []
        for resource in result.get("resources", []):
            formatted_resource = {
                "id": resource.get("resourceId"),
                "arn": resource.get("resourceArn"),
                "status": resource.get("status"),
                "region": resource.get("region"),
                "metadata": resource.get("metadata", {}),
                "updated_at": resource.get("updatedAt")
            }
            formatted_resources.append(formatted_resource)
        
        result["resources"] = formatted_resources
    
    return result 