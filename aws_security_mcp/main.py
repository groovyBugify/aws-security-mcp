"""Entry point for AWS Security MCP server."""

import importlib
import logging
import sys
from typing import Dict, List, Optional

try:
    from fastapi import FastAPI
    import uvicorn
except ImportError:
    print("ERROR: Missing required dependencies.")
    print("Please install required packages using:")
    print("  uv pip install -r requirements.txt")
    sys.exit(1)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("ERROR: Missing MCP package required for Claude Desktop integration.")
    print("Please install the MCP package using:")
    print("  uv pip install mcp>=1.0.0")
    sys.exit(1)

from aws_security_mcp.config import config
from aws_security_mcp.tools import get_all_tools

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.server.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP("aws-security")

def register_tools() -> None:
    """Register all MCP tools from tool modules."""
    # Import tools modules
    logger.info("Registering MCP tools...")
    
    # List of tool modules to import
    tool_modules = [
        "aws_security_mcp.tools.guardduty_tools",
        "aws_security_mcp.tools.securityhub_tools",
        "aws_security_mcp.tools.access_analyzer_tools",
        "aws_security_mcp.tools.iam_tools",
        "aws_security_mcp.tools.ec2_tools",
        "aws_security_mcp.tools.load_balancer_tools",
        "aws_security_mcp.tools.cloudfront_tools",
        "aws_security_mcp.tools.route53_tools",
        "aws_security_mcp.tools.lambda_tools",
        "aws_security_mcp.tools.s3_tools",
        "aws_security_mcp.tools.waf_tools",
        "aws_security_mcp.tools.shield_tools",
        "aws_security_mcp.tools.resource_tagging_tools",
        "aws_security_mcp.tools.trusted_advisor_tools",
        "aws_security_mcp.tools.ecr_tools",
        "aws_security_mcp.tools.ecs_tools",
        "aws_security_mcp.tools.org_tools",
    ]
    
    # Import each module and register its tools
    for module_name in tool_modules:
        try:
            # Dynamic import
            importlib.import_module(module_name)
            logger.info(f"Imported tools from {module_name}")
        except ImportError as e:
            logger.warning(f"Could not import {module_name}: {e}")
    
    # Register all tools with the MCP server
    all_tools = get_all_tools()
    for tool_name, tool_func in all_tools.items():
        logger.info(f"Registering tool: {tool_name}")
        mcp.tool(name=tool_name)(tool_func)

# For FastAPI HTTP server mode (not used with Claude Desktop but kept for reference)
app = FastAPI(
    title="AWS CloudSecurity MCP",
    description="MCP Server to inspect everything related to AWS Cloud Security!",
    version="0.1.0",
)

@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "AWS Security MCP is running"}

@app.get("/tools")
async def list_tools():
    """List all available MCP tools."""
    return {"tools": list(mcp.registered_tools.keys())}

def run_http_app() -> None:
    """Run the MCP server in HTTP mode."""
    # Register tools
    register_tools()
    
    # Start the HTTP server
    uvicorn.run(
        "aws_security_mcp.main:app",
        host=config.server.host,
        port=config.server.port,
        reload=config.server.debug,
    )

def run_mcp_stdio() -> None:
    """Run the MCP server in stdio mode for Claude Desktop."""
    # Register tools
    register_tools()
    
    # Run MCP server with stdio transport (required for Claude Desktop)
    mcp.run(transport='stdio')

if __name__ == "__main__":
    # Use stdio transport for MCP when running directly
    # This is required for Claude Desktop integration
    run_mcp_stdio() 