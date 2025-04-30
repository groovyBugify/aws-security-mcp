"""MCP tools implementation for AWS security services."""

from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

# Type for tool functions
ToolFunc = TypeVar('ToolFunc', bound=Callable[..., Any])

# Registry to store all registered tools
_TOOLS_REGISTRY: Dict[str, Callable] = {}

def register_tool(name: Optional[str] = None) -> Callable[[ToolFunc], ToolFunc]:
    """Decorator to register an MCP tool function.
    
    Args:
        name: Optional custom name for the tool. If None, function name is used.
        
    Returns:
        Decorator function that registers the tool.
    """
    def decorator(func: ToolFunc) -> ToolFunc:
        tool_name = name or func.__name__
        _TOOLS_REGISTRY[tool_name] = func
        return func
    return decorator

def get_all_tools() -> Dict[str, Callable]:
    """Get all registered MCP tools.
    
    Returns:
        Dictionary of tool name to function mapping.
    """
    return _TOOLS_REGISTRY

# Import all tool modules to register their tools
import aws_security_mcp.tools.s3_tools
import aws_security_mcp.tools.iam_tools  # Re-added IAM tools module
import aws_security_mcp.tools.ec2_tools
import aws_security_mcp.tools.securityhub_tools
import aws_security_mcp.tools.lambda_tools
import aws_security_mcp.tools.guardduty_tools
import aws_security_mcp.tools.access_analyzer_tools
import aws_security_mcp.tools.load_balancer_tools
import aws_security_mcp.tools.cloudfront_tools
import aws_security_mcp.tools.route53_tools
import aws_security_mcp.tools.waf_tools
import aws_security_mcp.tools.shield_tools
import aws_security_mcp.tools.resource_tagging_tools
# Import new tool modules
import aws_security_mcp.tools.trusted_advisor_tools
import aws_security_mcp.tools.ecr_tools
import aws_security_mcp.tools.ecs_tools 