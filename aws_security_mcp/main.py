"""Entry point for AWS Security MCP server."""

import importlib
import logging
import sys
import signal
from typing import Any, Dict, List, Optional

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
    from mcp.server import Server  # For SSE transport
except ImportError:
    print("ERROR: Missing MCP package required for Claude Desktop integration.")
    print("Please install the MCP package using:")
    print("  uv pip install mcp>=1.0.0")
    sys.exit(1)

# SSE transport imports
try:
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Route, Mount
    from starlette.responses import JSONResponse, RedirectResponse
    SSE_AVAILABLE = True
except ImportError:
    SSE_AVAILABLE = False

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

async def validate_aws_credentials() -> Dict[str, Any]:
    """Validate that basic AWS credentials are working.
    
    Returns:
        Dict with validation results
    """
    if not config.server.startup_quiet:
        logger.info("Validating AWS credentials...")
    
    try:
        from aws_security_mcp.services.base import get_client
        
        # Test basic STS access
        sts_client = get_client('sts')
        identity = sts_client.get_caller_identity()
        
        if not config.server.startup_quiet:
            logger.info("AWS credentials validated successfully")
            logger.debug(f"Identity: Account={identity['Account']}, ARN={identity['Arn']}")
        
        return {
            "success": True,
            "identity": identity,
            "account_id": identity['Account'],
            "arn": identity['Arn']
        }
        
    except Exception as e:
        logger.error(f"AWS credential validation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def initialize_cross_account_sessions() -> Dict[str, Any]:
    """Initialize cross-account sessions if auto-setup is enabled.
    
    Returns:
        Dict with session initialization results
    """
    if not config.cross_account.auto_setup_on_startup:
        if not config.server.startup_quiet:
            logger.info("Cross-account auto-setup disabled, skipping session initialization")
        return {
            "success": True,
            "sessions_created": 0,
            "accounts_processed": 0,
            "message": "Auto-setup disabled"
        }
    
    if not config.server.startup_quiet:
        logger.info("Initializing cross-account credential sessions...")
    
    try:
        # Import the credentials service
        from aws_security_mcp.services import credentials
        
        # Set up cross-account sessions
        result = await credentials.setup_cross_account_sessions()
        
        if result.get("success"):
            sessions_created = result.get("sessions_created", 0)
            sessions_failed = result.get("sessions_failed", 0)
            accounts_processed = result.get("accounts_processed", 0)
            
            if not config.server.startup_quiet:
                if sessions_created > 0:
                    logger.info(f"Multi-account access enabled for {sessions_created} accounts")
                
                if sessions_failed > 0:
                    logger.warning(f"Failed to access {sessions_failed} accounts - check role permissions")
            
            # Always log debug details
            logger.debug(f"Cross-account session initialization complete:")
            logger.debug(f"  Accounts processed: {accounts_processed}")
            logger.debug(f"  Sessions created: {sessions_created}")
            logger.debug(f"  Sessions failed: {sessions_failed}")
                
            return result
        else:
            error = result.get("error", "Unknown error")
            logger.warning(f"Cross-account session initialization failed: {error}")
            if not config.server.startup_quiet:
                logger.info("You can still set up sessions manually using credentials_security_operations")
            return result
    
    except Exception as e:
        logger.error(f"Error during cross-account session initialization: {e}")
        if not config.server.startup_quiet:
            logger.info("Cross-account access will not be available until sessions are set up manually")
        return {
            "success": False,
            "error": str(e),
            "sessions_created": 0,
            "accounts_processed": 0
        }

async def setup_aws_environment() -> Dict[str, Any]:
    """Set up AWS environment by validating credentials and initializing sessions.
    
    Returns:
        Dict with setup results and session information
    """
    if not config.server.startup_quiet:
        logger.info("Setting up AWS environment...")
    
    # Step 1: Validate basic AWS credentials
    credential_validation = await validate_aws_credentials()
    if not credential_validation.get("success"):
        return {
            "success": False,
            "error": f"AWS credential validation failed: {credential_validation.get('error')}",
            "credentials_valid": False,
            "sessions_available": False
        }
    
    # Step 2: Initialize cross-account sessions
    session_result = await initialize_cross_account_sessions()
    sessions_created = session_result.get("sessions_created", 0)
    
    # Determine success criteria
    aws_setup_success = credential_validation.get("success", False)
    multi_account_available = session_result.get("success", False) and sessions_created > 0
    
    return {
        "success": aws_setup_success,
        "credentials_valid": credential_validation.get("success", False),
        "account_id": credential_validation.get("account_id"),
        "arn": credential_validation.get("arn"),
        "sessions_available": multi_account_available,
        "sessions_created": sessions_created,
        "accounts_processed": session_result.get("accounts_processed", 0),
        "session_setup_success": session_result.get("success", False)
    }

def register_tools_conditionally(aws_setup_result: Dict[str, Any]) -> None:
    """Register MCP tools conditionally based on AWS environment setup.
    
    Args:
        aws_setup_result: Results from AWS environment setup
    """
    from aws_security_mcp.tools.registry import should_register_tool
    
    credentials_valid = aws_setup_result.get("credentials_valid", False)
    sessions_available = aws_setup_result.get("sessions_available", False)
    
    if not config.server.startup_quiet:
        logger.info("Registering MCP tools...")
        logger.debug(f"AWS credentials valid: {credentials_valid}")
        logger.debug(f"Multi-account sessions available: {sessions_available}")
    
    if not credentials_valid:
        logger.error("Cannot register tools - AWS credentials are invalid")
        return
    
    # List of tool modules to import
    tool_modules = [
        # Always needed
        "aws_security_mcp.tools.credentials_tools",
        "aws_security_mcp.tools.wrappers.credentials_wrapper",
        
        # Core service modules (require basic AWS access)
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
        
        # Service wrapper modules
        "aws_security_mcp.tools.wrappers.guardduty_wrapper",
        "aws_security_mcp.tools.wrappers.ec2_wrapper",
        "aws_security_mcp.tools.wrappers.load_balancer_wrapper",
        "aws_security_mcp.tools.wrappers.cloudfront_wrapper",
        "aws_security_mcp.tools.wrappers.ecs_wrapper",
        "aws_security_mcp.tools.wrappers.ecr_wrapper",
        "aws_security_mcp.tools.wrappers.iam_wrapper",
        "aws_security_mcp.tools.wrappers.lambda_wrapper",
        "aws_security_mcp.tools.wrappers.access_analyzer_wrapper",
        "aws_security_mcp.tools.wrappers.resource_tagging_wrapper",
        "aws_security_mcp.tools.wrappers.org_wrapper",
        "aws_security_mcp.tools.wrappers.s3_wrapper",
        "aws_security_mcp.tools.wrappers.route53_wrapper",
        "aws_security_mcp.tools.wrappers.securityhub_wrapper",
        "aws_security_mcp.tools.wrappers.shield_wrapper",
        "aws_security_mcp.tools.wrappers.waf_wrapper",
        "aws_security_mcp.tools.wrappers.trusted_advisor_wrapper",
    ]
    
    # Import tool modules
    imported_count = 0
    for module_name in tool_modules:
        try:
            importlib.import_module(module_name)
            logger.debug(f"Imported tools from {module_name}")
            imported_count += 1
        except ImportError as e:
            logger.warning(f"Could not import {module_name}: {e}")
    
    logger.debug(f"Imported {imported_count}/{len(tool_modules)} tool modules")
    
    # Get all available tools
    all_tools = get_all_tools()
    logger.debug(f"Total available tools: {len(all_tools)}")
    
    # Register tools conditionally
    registered_count = 0
    excluded_count = 0
    safe_tools_count = 0
    
    for tool_name, tool_func in all_tools.items():
        should_register = should_register_tool(tool_name)
        
        # Always register safe credential tools
        if tool_name in ["refresh_aws_session", "connected_aws_accounts", 
                        "aws_session_operations", "discover_aws_session_operations"]:
            if should_register:
                logger.debug(f"Registering safe credential tool: {tool_name}")
                mcp.tool(name=tool_name)(tool_func)
                registered_count += 1
                safe_tools_count += 1
            continue
        
        # Register other tools based on registry and credential status
        if should_register:
            logger.debug(f"Registering tool: {tool_name}")
            mcp.tool(name=tool_name)(tool_func)
            registered_count += 1
        else:
            logger.debug(f"Excluding tool: {tool_name}")
            excluded_count += 1
    
    # Log registration statistics
    if not config.server.startup_quiet:
        logger.info(f"Tool registration complete: {registered_count} tools registered")
        if sessions_available:
            logger.info(f"Multi-account tools available (sessions: {aws_setup_result.get('sessions_created', 0)})")
        else:
            logger.debug("Multi-account sessions not available - some tools may have limited functionality")
    
    # Always log debug statistics
    logger.debug(f"Tool Registration Summary:")
    logger.debug(f"  Registered: {registered_count}")
    logger.debug(f"  Safe credential tools: {safe_tools_count}")
    logger.debug(f"  Excluded: {excluded_count}")
    logger.debug(f"  Tool reduction: {len(all_tools)} → {registered_count}")

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

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "aws-security-mcp"}

@app.get("/tools")
async def list_tools():
    """List all available MCP tools."""
    try:
        # Try different possible attributes for registered tools
        if hasattr(mcp, 'registered_tools'):
            tools = list(mcp.registered_tools.keys())
        elif hasattr(mcp, '_tools'):
            tools = list(mcp._tools.keys())
        elif hasattr(mcp, 'tools'):
            tools = list(mcp.tools.keys())
        else:
            # Fallback to getting tools from the tools module
            from aws_security_mcp.tools import get_all_tools
            all_tools = get_all_tools()
            tools = list(all_tools.keys())
        
        return {
            "tools": tools,
            "total_count": len(tools),
            "message": "Available MCP tools"
        }
    except Exception as e:
        # Return a safe response if there's any error
        return {
            "tools": [],
            "total_count": 0,
            "error": str(e),
            "message": "Unable to retrieve tools list"
        }

def cleanup_resources() -> None:
    """Clean up AWS client resources."""
    try:
        clear_client_cache()
        logger.info("Cleaned up AWS client cache")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def run_sse_server() -> None:
    """Run the MCP server in SSE mode using FastMCP's built-in SSE support."""
    if not SSE_AVAILABLE:
        logger.error("SSE transport dependencies not available. Please install starlette>=0.27.0")
        sys.exit(1)
    
    try:
        if not config.server.startup_quiet:
            logger.info("Starting AWS Security MCP SSE Server...")
        
        # Set up AWS environment and register tools conditionally
        import asyncio
        try:
            aws_setup_result = asyncio.run(setup_aws_environment())
            register_tools_conditionally(aws_setup_result)
            
            if not aws_setup_result.get("success"):
                logger.error("AWS environment setup failed. Server will start with limited functionality.")
            elif not config.server.startup_quiet:
                # Show a clean startup summary
                sessions_count = aws_setup_result.get('sessions_created', 0)
                if sessions_count > 0:
                    logger.info(f"AWS Security MCP ready: {sessions_count} accounts accessible")
                else:
                    logger.info("AWS Security MCP ready: Single account mode")
            
        except Exception as e:
            logger.error(f"Could not set up AWS environment: {e}")
            if not config.server.startup_quiet:
                logger.info("Starting server without AWS tools...")
        
        # Create SSE app with health endpoint
        from starlette.applications import Starlette
        from starlette.routing import Route, Mount
        from starlette.responses import JSONResponse
        
        async def health_check(request):
            """Health check endpoint for ECS/ALB health checks."""
            return JSONResponse({"status": "healthy", "service": "aws-security-mcp"})
        
        # Get the base SSE app from FastMCP
        sse_app = mcp.sse_app()
        
        # Create a new Starlette app that includes both SSE and health endpoints
        app = Starlette(
            routes=[
                Route("/health", health_check, methods=["GET"]),
                Mount("/", sse_app),
            ]
        )
        
        if not config.server.startup_quiet:
            logger.info("SSE endpoint available at: /sse")
            logger.info("Health check available at: /health")
            logger.info(f"Use: npx @modelcontextprotocol/inspector http://127.0.0.1:8000/sse")
            logger.debug("Note: Load balancer should be configured to not redirect /sse to /sse/")
        
        # Run the combined app with uvicorn
        import uvicorn
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="warning" if config.server.minimal_logging else config.server.log_level,
            access_log=not config.server.minimal_logging
        )
        
    except KeyboardInterrupt:
        logger.info("SSE server shutdown requested")
    except Exception as e:
        logger.error(f"SSE server error: {e}")
        import traceback
        logger.error(f"SSE server traceback: {traceback.format_exc()}")
    finally:
        cleanup_resources()

def run_http_app() -> None:
    """Run the MCP server in HTTP mode."""
    try:
        # Set up AWS environment and register tools conditionally
        import asyncio
        try:
            aws_setup_result = asyncio.run(setup_aws_environment())
            register_tools_conditionally(aws_setup_result)
            
            if not aws_setup_result.get("success"):
                logger.error("AWS environment setup failed. Server will start with limited functionality.")
            elif not config.server.startup_quiet:
                # Show a clean startup summary
                sessions_count = aws_setup_result.get('sessions_created', 0)
                if sessions_count > 0:
                    logger.info(f"AWS Security MCP ready: {sessions_count} accounts accessible")
                else:
                    logger.info("AWS Security MCP ready: Single account mode")
            
        except Exception as e:
            logger.error(f"Could not set up AWS environment: {e}")
            if not config.server.startup_quiet:
                logger.info("Starting server without AWS tools...")
        
        # Start the HTTP server
        uvicorn.run(
            "aws_security_mcp.main:app",
            host="0.0.0.0",
            port=8000,
            reload=config.server.debug,
            log_level="warning" if config.server.minimal_logging else config.server.log_level,
            access_log=not config.server.minimal_logging
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
        if not config.server.startup_quiet:
            logger.info("Starting MCP server...")
        
        # Set up AWS environment and register tools conditionally
        import asyncio
        try:
            aws_setup_result = asyncio.run(setup_aws_environment())
            register_tools_conditionally(aws_setup_result)
            
            if not aws_setup_result.get("success"):
                logger.error("AWS environment setup failed. Server will start with limited functionality.")
            elif not config.server.startup_quiet:
                # Show a clean startup summary
                sessions_count = aws_setup_result.get('sessions_created', 0)
                if sessions_count > 0:
                    logger.info(f"AWS Security MCP ready: {sessions_count} accounts accessible")
                else:
                    logger.info("AWS Security MCP ready: Single account mode")
            
        except Exception as e:
            logger.error(f"Could not set up AWS environment: {e}")
            if not config.server.startup_quiet:
                logger.info("Starting server without AWS tools...")
        
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

def print_usage():
    """Print usage information."""
    print("AWS Security MCP Server")
    print("Usage: python aws_security_mcp/main.py [mode]")
    print("")
    print("Modes:")
    print("  stdio  - Standard I/O transport (default, for Claude Desktop)")
    print("  http   - HTTP REST API server")
    print("  sse    - Server-Sent Events transport (MCP over HTTP)")
    print("")
    print("Examples:")
    print("  python aws_security_mcp/main.py stdio   # Claude Desktop")
    print("  python aws_security_mcp/main.py http    # REST API on port 8000")
    print("  python aws_security_mcp/main.py sse     # SSE on port 8001")

if __name__ == "__main__":
    # Check for mode argument
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        if mode in ["help", "-h", "--help"]:
            print_usage()
            sys.exit(0)
        elif mode == "sse":
            run_sse_server()
        elif mode == "http":
            run_http_app()
        elif mode == "stdio":
            run_mcp_stdio()
        else:
            print(f"Error: Unknown mode '{mode}'")
            print("")
            print_usage()
            sys.exit(1)
    else:
        # Default to stdio for Claude Desktop compatibility
        run_mcp_stdio() 