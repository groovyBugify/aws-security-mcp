"""MCP tools for AWS cross-account credential management."""

import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.services import credentials
from aws_security_mcp.services.base import get_client, get_available_sessions
from aws_security_mcp.tools import register_tool

logger = logging.getLogger(__name__)

@register_tool()
async def refresh_aws_session() -> Dict[str, Any]:
    """Refresh AWS cross-account sessions for multi-account access.
    
    This tool automatically discovers organization accounts and establishes
    fresh credential sessions for cross-account security monitoring.
    
    Returns:
        Dict containing session refresh results
    """
    logger.info("Refreshing AWS cross-account sessions")
    
    try:
        # Set up fresh cross-account sessions
        result = await credentials.setup_cross_account_sessions()
        
        if result.get("success"):
            sessions_created = result.get("sessions_created", 0)
            sessions_failed = result.get("sessions_failed", 0)
            accounts_processed = result.get("accounts_processed", 0)
            
            return {
                "success": True,
                "message": "AWS sessions refreshed successfully",
                "accounts_processed": accounts_processed,
                "sessions_created": sessions_created,
                "sessions_failed": sessions_failed,
                "active_sessions": result.get("active_sessions", [])
            }
        else:
            return {
                "success": False,
                "message": "Failed to refresh AWS sessions",
                "error": result.get("error", "Unknown error")
            }
    
    except Exception as e:
        logger.error(f"Error refreshing AWS sessions: {e}")
        return {
            "success": False,
            "message": "Error refreshing AWS sessions",
            "error": str(e)
        }

@register_tool()
async def connected_aws_accounts() -> Dict[str, Any]:
    """Get list of connected AWS accounts with valid sessions.
    
    This tool returns information about AWS accounts that the MCP server
    currently has valid credential sessions for, including session keys
    that can be used in other operations.
    
    Returns:
        Dict containing connected account information with session keys
    """
    logger.info("Getting connected AWS accounts")
    
    try:
        # Get current user identity from STS
        sts_client = get_client('sts')
        identity = sts_client.get_caller_identity()
        current_user_arn = identity.get('Arn', 'Unknown')
        current_account_id = identity.get('Account', 'Unknown')
        
        # Get active sessions
        sessions_result = await credentials.get_active_sessions()
        
        if not sessions_result.get("success"):
            return {
                "success": False,
                "message": "Failed to retrieve session information",
                "error": sessions_result.get("error", "Unknown error")
            }
        
        sessions = sessions_result.get("sessions", [])
        
        # Format response with session keys for client use
        connected_accounts = []
        for session in sessions:
            if not session.get("is_expired", True):  # Only include non-expired sessions
                account_info = {
                    "account_id": session.get("account_id"),
                    "account_name": session.get("account_name"),
                    "session_key": session.get("session_key"),
                    "session_status": "active",
                    "time_remaining_minutes": session.get("time_remaining_minutes")
                }
                connected_accounts.append(account_info)
        
        # Add current account information
        current_account_info = {
            "account_id": current_account_id,
            "account_name": "current",
            "session_key": "default",
            "session_status": "active",
            "is_current_account": True
        }
        
        return {
            "success": True,
            "current_user_arn": current_user_arn,
            "current_account_id": current_account_id,
            "connected_accounts_count": len(connected_accounts),
            "connected_accounts": connected_accounts,
            "current_account": current_account_info,
            "usage_note": "Use 'session_key' in other tools to specify which account to query"
        }
    
    except Exception as e:
        logger.error(f"Error getting connected AWS accounts: {e}")
        return {
            "success": False,
            "message": "Error retrieving connected accounts",
            "error": str(e)
        }

@register_tool()
async def list_available_sessions() -> Dict[str, Any]:
    """List all available cross-account sessions with their keys and metadata.
    
    This tool provides detailed information about all available sessions
    that can be used with other MCP tools by specifying the session_key.
    
    Returns:
        Dict containing available sessions with usage information
    """
    logger.info("Listing available cross-account sessions")
    
    try:
        # Get session information
        session_info = get_available_sessions()
        
        if not session_info:
            return {
                "success": True,
                "message": "No cross-account sessions available",
                "session_count": 0,
                "sessions": [],
                "usage_examples": [
                    "First run: refresh_aws_session() to establish cross-account sessions",
                    "Then use session keys in other tools: ec2_security_operations(operation='describe_instances', session_context='123456789012_aws_dev')"
                ]
            }
        
        # Format session information for client use
        formatted_sessions = []
        for session_key, info in session_info.items():
            formatted_sessions.append({
                "session_key": session_key,
                "account_id": info["account_id"],
                "account_name": info["account_name"],
                "expiration": info["expiration"],
                "time_remaining_minutes": info["time_remaining_minutes"],
                "usage_example": f"Use session_context='{session_key}' in other tools"
            })
        
        # Sort by account name for better readability
        formatted_sessions.sort(key=lambda x: x["account_name"])
        
        return {
            "success": True,
            "session_count": len(formatted_sessions),
            "sessions": formatted_sessions,
            "usage_instructions": {
                "how_to_use": "Add 'session_context' parameter to any tool call",
                "example": "ec2_security_operations(operation='describe_instances', session_context='123456789012_aws_dev')",
                "default_behavior": "Without session_context, tools use the current account",
                "session_management": "Sessions auto-refresh when near expiration"
            }
        }
    
    except Exception as e:
        logger.error(f"Error listing available sessions: {e}")
        return {
            "success": False,
            "message": "Error retrieving session information",
            "error": str(e)
        } 