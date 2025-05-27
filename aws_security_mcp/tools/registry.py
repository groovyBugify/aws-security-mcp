"""Tool registration management for AWS Security MCP.

This module provides selective tool registration to reduce MCP communication
overhead while maintaining functionality through service wrappers.
"""

from typing import Set

# Service wrapper tools that consolidate operations - this is our ONLY approach
# No more individual tools, everything goes through service wrappers for consistency

# Service wrapper tools that consolidate multiple operations
SERVICE_WRAPPER_TOOLS: Set[str] = {
    # ✅ Implemented wrapper tools
    "guardduty_security_operations",
    "discover_guardduty_operations",
    "ec2_security_operations", 
    "discover_ec2_operations",
    "load_balancer_operations",
    "discover_load_balancer_operations", 
    "cloudfront_operations",
    "discover_cloudfront_operations",
    "ecs_security_operations",
    "discover_ecs_operations",
    "ecr_security_operations",
    "discover_ecr_operations",
    "iam_security_operations",
    "discover_iam_operations",
    "lambda_security_operations",
    "discover_lambda_operations",
    "access_analyzer_security_operations",
    "discover_access_analyzer_operations",
    "organizations_security_operations",
    "discover_organizations_operations",
    "s3_security_operations",
    "discover_s3_operations",
    "route53_security_operations",
    "discover_route53_operations",
    "securityhub_security_operations",
    "discover_securityhub_operations",
    "shield_security_operations",
    "discover_shield_operations",
    "waf_security_operations",
    "discover_waf_operations",
    "trusted_advisor_security_operations",
    "discover_trusted_advisor_operations",
    
    # 🚧 Future wrappers (to be implemented)
    "account_security_operations",  # For account-level tools
    "discover_account_operations",
    "resource_tagging_operations",
    "discover_resource_tagging_operations",
}

# All utility functions are now part of service wrappers - no separate utility tools needed

def get_selected_tools() -> Set[str]:
    """Get the complete set of tools that should be registered with MCP.
    
    All tools are now service wrappers for consistency and streamlined design.
    
    Returns:
        Set of tool names that should be registered
    """
    return SERVICE_WRAPPER_TOOLS

# No need for explicit exclusion logic - we simply don't register individual tools

def should_register_tool(tool_name: str) -> bool:
    """Determine if a tool should be registered with MCP.
    
    Simple logic: only register service wrapper tools.
    
    Args:
        tool_name: Name of the tool to check
        
    Returns:
        True if tool should be registered, False otherwise
    """
    return tool_name in SERVICE_WRAPPER_TOOLS

# No utility functions needed - keep it simple 