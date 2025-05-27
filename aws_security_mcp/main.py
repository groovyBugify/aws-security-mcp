"""Entry point for AWS Security MCP server."""

import importlib
import logging
import sys
import signal
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
from aws_security_mcp.services.base import clear_client_cache

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.server.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP("aws-security")

# Global flag for graceful shutdown
_shutdown_flag = False

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global _shutdown_flag
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    _shutdown_flag = True
    cleanup_resources()
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

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

def cleanup_resources() -> None:
    """Clean up AWS client resources."""
    try:
        clear_client_cache()
        logger.info("Cleaned up AWS client cache")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def run_http_app() -> None:
    """Run the MCP server in HTTP mode."""
    try:
        # Register tools
        register_tools()
        
        # Start the HTTP server
        uvicorn.run(
            "aws_security_mcp.main:app",
            host=config.server.host,
            port=config.server.port,
            reload=config.server.debug,
        )
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        cleanup_resources()

def run_mcp_stdio() -> None:
    """Run the MCP server in stdio mode for Claude Desktop."""
    try:
        # Register tools
        register_tools()
        logger.info("Starting MCP server with stdio transport...")
        
        # Run MCP server with stdio transport (required for Claude Desktop)
        mcp.run(transport='stdio')
    except KeyboardInterrupt:
        logger.info("Server shutdown requested via keyboard interrupt")
    except (BrokenPipeError, ConnectionResetError) as e:
        logger.warning(f"Client disconnected unexpectedly: {e}")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        # For anyio.BrokenResourceError, log but don't crash
        if "BrokenResourceError" in str(type(e)):
            logger.error("Stream broken - client likely disconnected")
    finally:
        # Clean up resources
        cleanup_resources()

if __name__ == "__main__":
    # Use stdio transport for MCP when running directly
    # This is required for Claude Desktop integration
    run_mcp_stdio() 