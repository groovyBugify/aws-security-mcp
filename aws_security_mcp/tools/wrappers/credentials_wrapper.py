"""Credentials Service Wrapper for AWS Security MCP.

This wrapper provides safe access to AWS cross-account credential operations
with limited, secure functionality for session management.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import safe credential functions
from aws_security_mcp.tools.credentials_tools import (
    refresh_aws_session as _refresh_aws_session,
    connected_aws_accounts as _connected_aws_accounts,
    list_available_sessions as _list_available_sessions
)

logger = logging.getLogger(__name__)

@register_tool()
async def aws_session_operations(operation: str, **params) -> str:
    """AWS Session Operations Hub - Safe multi-account session management.
    
    🔄 SESSION REFRESH:
    - refresh_session: Refresh AWS cross-account sessions for multi-account access
    
    📊 SESSION STATUS:
    - connected_accounts: Get list of connected AWS accounts with valid sessions
    - list_sessions: List all available sessions with their keys and metadata
    
    💡 USAGE EXAMPLES:
    
    🔄 Refresh AWS sessions:
    operation="refresh_session"
    
    📊 Check connected accounts:
    operation="connected_accounts"
    
    📋 List available sessions with keys:
    operation="list_sessions"
    
    Args:
        operation: The session operation to perform (refresh_session, connected_accounts, or list_sessions)
        
    Returns:
        JSON formatted response with operation results and session keys for other tools
    """
    
    logger.info(f"AWS session operation requested: {operation}")
    
    try:
        if operation == "refresh_session":
            result = await _refresh_aws_session()
            return json.dumps(result, default=str)
            
        elif operation == "connected_accounts":
            result = await _connected_aws_accounts()
            return json.dumps(result, default=str)
            
        elif operation == "list_sessions":
            result = await _list_available_sessions()
            return json.dumps(result, default=str)
            
        else:
            return json.dumps({
                "error": f"Unknown session operation: {operation}",
                "available_operations": [
                    "refresh_session",
                    "connected_accounts", 
                    "list_sessions"
                ],
                "usage": "Use discover_aws_session_operations() to see detailed usage examples"
            })
            
    except Exception as e:
        logger.error(f"Error in AWS session operation '{operation}': {e}")
        return json.dumps({
            "error": str(e),
            "operation": operation,
            "parameters": params
        })

@register_tool()
async def discover_aws_session_operations() -> str:
    """Discover available AWS session operations with usage examples.
    
    This tool provides documentation of safe session operations available
    through the aws_session_operations tool for multi-account access.
    
    Returns:
        Detailed catalog of session operations with examples
    """
    
    operations_catalog = {
        "service": "AWS Session Management",
        "description": "Safe multi-account session operations for AWS Security MCP",
        "wrapper_tool": "aws_session_operations",
        "security_level": "Safe - Read-only session information",
        "operation_categories": {
            "session_refresh": {
                "refresh_session": {
                    "description": "Refresh AWS cross-account sessions for multi-account access",
                    "parameters": {},
                    "examples": [
                        "aws_session_operations(operation='refresh_session')"
                    ],
                    "returns": [
                        "Session refresh results",
                        "Number of accounts processed",
                        "Successfully created sessions count",
                        "Failed sessions count",
                        "List of active session keys"
                    ],
                    "safety": "Safe - Refreshes existing sessions without exposing credentials"
                }
            },
            "session_status": {
                "connected_accounts": {
                    "description": "Get list of connected AWS accounts with valid sessions",
                    "parameters": {},
                    "examples": [
                        "aws_session_operations(operation='connected_accounts')"
                    ],
                    "returns": [
                        "Current user ARN",
                        "Connected accounts count",
                        "List of connected accounts (ID, name, status only)",
                        "Timestamp of last update"
                    ],
                    "safety": "Safe - Only returns basic account information, no credentials"
                },
                "list_sessions": {
                    "description": "List all available sessions with their keys and metadata",
                    "parameters": {},
                    "examples": [
                        "aws_session_operations(operation='list_sessions')"
                    ],
                    "returns": [
                        "Session keys",
                        "Session metadata",
                        "List of session keys"
                    ],
                    "safety": "Safe - Only returns session keys and metadata, no credentials"
                }
            }
        },
        "usage_patterns": {
            "startup_workflow": [
                "1. Server automatically refreshes sessions on startup",
                "2. Use connected_accounts to verify multi-account access",
                "3. Sessions are automatically maintained in background"
            ],
            "monitoring_workflow": [
                "1. Check connected_accounts to see available accounts",
                "2. Use refresh_session if manual refresh is needed",
                "3. Monitor logs for session status and errors"
            ]
        },
        "security_features": [
            "No credential exposure - credentials never returned to client",
            "Read-only session information only",
            "Automatic session management in background",
            "Safe operations suitable for client access"
        ],
        "background_operations": [
            "Automatic organization account discovery",
            "Cross-account role assumption using 'aws-security-mcp-cross-account-access'",
            "Session storage and management",
            "Automatic credential refresh before expiration"
        ]
    }
    
    return json.dumps(operations_catalog, indent=2) 