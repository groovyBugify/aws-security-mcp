"""AWS Cross-Account Credentials Service for AWS Security MCP.

This service manages cross-account access by discovering organization accounts,
assuming roles, storing sessions, and automatically refreshing credentials.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import json

from botocore.exceptions import ClientError
import boto3

from aws_security_mcp.config import config
from aws_security_mcp.services.base import get_client

logger = logging.getLogger(__name__)

# Global session storage
_account_sessions: Dict[str, Dict[str, Any]] = {}
_session_metadata: Dict[str, Dict[str, Any]] = {}

# Role name to assume in target accounts
CROSS_ACCOUNT_ROLE_NAME = "aws-security-mcp-cross-account-access"
SESSION_NAME = "aws-security-mcp-session"
SESSION_DURATION_SECONDS = 3600  # 1 hour
REFRESH_THRESHOLD_MINUTES = 10   # Refresh when less than 10 minutes remaining

def create_progress_bar(current: int, total: int, width: Optional[int] = None, fill_char: str = "█", empty_char: str = "░") -> str:
    """Create a visual progress bar.
    
    Args:
        current: Current progress value
        total: Total target value
        width: Width of the progress bar in characters (defaults to total, capped at 50)
        fill_char: Character to use for filled portions
        empty_char: Character to use for empty portions
        
    Returns:
        Formatted progress bar string
    """
    if total == 0:
        return f"[{empty_char}]"
    
    # Use total as width if not specified, but cap at reasonable maximum for readability
    if width is None:
        width = min(total, 50)  # Cap at 50 characters for very large account counts
    
    # Ensure minimum width of 3 for very small account counts
    width = max(width, 3)
    
    filled = int((current / total) * width)
    empty = width - filled
    
    return f"[{fill_char * filled}{empty_char * empty}]"

class CredentialSession:
    """Represents a cross-account credential session."""
    
    def __init__(self, account_id: str, account_name: str, role_arn: str, 
                 credentials: Dict[str, Any], expiration: datetime):
        self.account_id = account_id
        self.account_name = account_name
        self.role_arn = role_arn
        self.credentials = credentials
        self.expiration = expiration
        self.session = None
        self._create_session()
    
    def _create_session(self) -> None:
        """Create boto3 session from credentials."""
        self.session = boto3.Session(
            aws_access_key_id=self.credentials['AccessKeyId'],
            aws_secret_access_key=self.credentials['SecretAccessKey'],
            aws_session_token=self.credentials['SessionToken'],
            region_name=config.aws.aws_region
        )
    
    def is_expired(self) -> bool:
        """Check if credentials are expired or will expire soon."""
        if not self.expiration:
            return True
        
        now = datetime.now(timezone.utc)
        threshold = now + timedelta(minutes=REFRESH_THRESHOLD_MINUTES)
        return self.expiration <= threshold
    
    def get_client(self, service_name: str):
        """Get boto3 client for this session."""
        if self.is_expired():
            raise ValueError(f"Session for account {self.account_id} has expired")
        return self.session.client(service_name)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary representation."""
        return {
            "account_id": self.account_id,
            "account_name": self.account_name,
            "role_arn": self.role_arn,
            "expiration": self.expiration.isoformat() if self.expiration else None,
            "is_expired": self.is_expired(),
            "time_remaining": str(self.expiration - datetime.now(timezone.utc)) if self.expiration else None
        }

def generate_session_key(account_id: str, account_name: str) -> str:
    """Generate a safe, predictable session key from account information.
    
    Args:
        account_id: AWS account ID
        account_name: AWS account name (may contain spaces/special chars)
        
    Returns:
        Safe session key for storage and lookup
    """
    # Sanitize account name: replace spaces and special chars with underscores
    sanitized_name = re.sub(r'[^a-zA-Z0-9\-]', '_', account_name.strip())
    # Remove multiple consecutive underscores
    sanitized_name = re.sub(r'_+', '_', sanitized_name)
    # Remove leading/trailing underscores
    sanitized_name = sanitized_name.strip('_')
    
    # Ensure it's not empty
    if not sanitized_name:
        sanitized_name = f"account_{account_id}"
    
    # Create session key: account_id for uniqueness, name for readability
    session_key = f"{account_id}_{sanitized_name}"
    
    return session_key

def get_session_info() -> Dict[str, Dict[str, Any]]:
    """Get information about all available sessions for client discovery.
    
    Returns:
        Dict mapping session keys to session metadata
    """
    global _account_sessions
    
    session_info = {}
    
    for session_key, session in _account_sessions.items():
        if not session.is_expired():
            session_info[session_key] = {
                "account_id": session.account_id,
                "account_name": session.account_name,
                "session_key": session_key,
                "expiration": session.expiration.isoformat() if session.expiration else None,
                "time_remaining_minutes": int((session.expiration - datetime.now(timezone.utc)).total_seconds() / 60) if session.expiration else None
            }
    
    return session_info

async def discover_organization_accounts() -> Dict[str, Any]:
    """Discover all accounts in the AWS organization.
    
    Returns:
        Dict containing organization accounts or error information
    """
    try:
        client = get_client('organizations')
        
        # Use paginator to handle pagination
        paginator = client.get_paginator('list_accounts')
        
        all_accounts = []
        
        # Iterate through pages
        for page in paginator.paginate():
            accounts = page.get('Accounts', [])
            all_accounts.extend(accounts)
        
        # Filter active accounts only
        active_accounts = [
            account for account in all_accounts 
            if account.get('Status') == 'ACTIVE'
        ]
        
        logger.info(f"Discovered {len(active_accounts)} active accounts in organization")
        
        return {
            "success": True,
            "accounts": active_accounts,
            "total_count": len(all_accounts),
            "active_count": len(active_accounts)
        }
    
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        
        if error_code == 'AWSOrganizationsNotInUseException':
            logger.warning("AWS Organizations is not in use for this account")
            return {
                "success": False,
                "error": "AWS Organizations is not enabled for this account",
                "error_code": error_code,
                "accounts": []
            }
        elif error_code == 'AccessDeniedException':
            logger.error("Access denied when listing organization accounts")
            return {
                "success": False,
                "error": "Access denied - insufficient permissions to list organization accounts",
                "error_code": error_code,
                "accounts": []
            }
        else:
            logger.error(f"Error discovering organization accounts: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": error_code,
                "accounts": []
            }

async def assume_cross_account_role(account_id: str, account_name: str) -> Dict[str, Any]:
    """Assume cross-account role in target account.
    
    Args:
        account_id: Target AWS account ID
        account_name: Target AWS account name
        
    Returns:
        Dict containing assumed role credentials or error information
    """
    try:
        sts_client = get_client('sts')
        
        # Construct role ARN
        role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"
        
        # Assume role
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=SESSION_NAME,
            DurationSeconds=SESSION_DURATION_SECONDS
        )
        
        credentials = response.get('Credentials', {})
        expiration = credentials.get('Expiration')
        
        # Convert expiration to UTC if needed
        if expiration and expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        
        # Only log at debug level for individual accounts
        logger.debug(f"Successfully assumed role in account {account_id} ({account_name})")
        
        return {
            "success": True,
            "account_id": account_id,
            "account_name": account_name,
            "role_arn": role_arn,
            "credentials": {
                'AccessKeyId': credentials.get('AccessKeyId'),
                'SecretAccessKey': credentials.get('SecretAccessKey'),
                'SessionToken': credentials.get('SessionToken')
            },
            "expiration": expiration,
            "assumed_role_user": response.get('AssumedRoleUser', {})
        }
    
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        
        # Only log warnings for failures, not info
        logger.debug(f"Failed to assume role in account {account_id} ({account_name}): {str(e)}")
        
        return {
            "success": False,
            "account_id": account_id,
            "account_name": account_name,
            "role_arn": f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}",
            "error": str(e),
            "error_code": error_code
        }

async def setup_cross_account_sessions() -> Dict[str, Any]:
    """Set up cross-account sessions for all organization accounts.
    
    Returns:
        Dict containing session setup results
    """
    global _account_sessions, _session_metadata
    
    logger.info("Setting up cross-account sessions...")
    
    # First, discover organization accounts
    accounts_result = await discover_organization_accounts()
    
    if not accounts_result["success"]:
        return {
            "success": False,
            "error": accounts_result.get("error", "Failed to discover organization accounts"),
            "sessions_created": 0,
            "sessions_failed": 0,
            "accounts_processed": 0
        }
    
    accounts = accounts_result["accounts"]
    
    if not accounts:
        return {
            "success": True,
            "message": "No accounts found in organization",
            "sessions_created": 0,
            "sessions_failed": 0,
            "accounts_processed": 0
        }
    
    successful_sessions = 0
    failed_sessions = 0
    session_details = []
    total_accounts = len(accounts)
    processed_accounts = 0
    
    # Progress tracking
    progress_lock = asyncio.Lock()
    
    async def update_progress(success: bool = False, failed: bool = False):
        nonlocal processed_accounts, successful_sessions, failed_sessions
        async with progress_lock:
            processed_accounts += 1
            if success:
                successful_sessions += 1
            elif failed:
                failed_sessions += 1
            
            # Show progress bar
            if not config.server.startup_quiet:
                progress_bar = create_progress_bar(processed_accounts, total_accounts)
                status_text = f"{successful_sessions} successful"
                if failed_sessions > 0:
                    status_text += f", {failed_sessions} failed"
                
                # Use \r to overwrite the same line
                print(f"\rAssuming roles: {progress_bar} {processed_accounts}/{total_accounts} accounts ({status_text})", end="", flush=True)
    
    # Show initial progress
    if not config.server.startup_quiet:
        progress_bar = create_progress_bar(0, total_accounts)
        print(f"\rAssuming roles: {progress_bar} 0/{total_accounts} accounts", end="", flush=True)
    
    # Process accounts concurrently with rate limiting
    semaphore = asyncio.Semaphore(5)  # Limit concurrent requests
    
    async def process_account(account: Dict[str, Any]) -> Dict[str, Any]:
        async with semaphore:
            account_id = account.get('Id')
            account_name = account.get('Name')
            
            # Skip current account
            current_account = get_client('sts').get_caller_identity().get('Account')
            if account_id == current_account:
                logger.debug(f"Skipping current account {account_id} ({account_name})")
                await update_progress()
                return {
                    "account_id": account_id,
                    "account_name": account_name,
                    "status": "skipped",
                    "reason": "current_account"
                }
            
            # Attempt to assume role
            assume_result = await assume_cross_account_role(account_id, account_name)
            
            if assume_result["success"]:
                # Create credential session
                session = CredentialSession(
                    account_id=account_id,
                    account_name=account_name,
                    role_arn=assume_result["role_arn"],
                    credentials=assume_result["credentials"],
                    expiration=assume_result["expiration"]
                )
                
                # Store session
                session_key = generate_session_key(account_id, account_name)
                _account_sessions[session_key] = session
                _session_metadata[session_key] = session.to_dict()
                
                await update_progress(success=True)
                return {
                    "account_id": account_id,
                    "account_name": account_name,
                    "session_key": session_key,
                    "status": "success",
                    "expiration": assume_result["expiration"].isoformat() if assume_result["expiration"] else None
                }
            else:
                await update_progress(failed=True)
                return {
                    "account_id": account_id,
                    "account_name": account_name,
                    "status": "failed",
                    "error": assume_result.get("error", "Unknown error"),
                    "error_code": assume_result.get("error_code", "Unknown")
                }
    
    # Process all accounts
    tasks = [process_account(account) for account in accounts]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Exception during account processing: {result}")
            failed_sessions += 1
            continue
        
        session_details.append(result)
    
    # Finish progress line and add final summary
    if not config.server.startup_quiet:
        print()  # New line after progress bar
        
        # Final consolidated summary log
        if successful_sessions == 0 and failed_sessions == 0:
            logger.info("Cross-account setup complete: No accounts required role assumption")
        elif failed_sessions == 0:
            logger.info(f"Cross-account setup complete: {successful_sessions}/{total_accounts} accounts accessible")
        else:
            logger.info(f"Cross-account setup complete: {successful_sessions} successful, {failed_sessions} failed ({total_accounts} total)")
    
    return {
        "success": True,
        "sessions_created": successful_sessions,
        "sessions_failed": failed_sessions,
        "accounts_processed": len(accounts),
        "session_details": session_details,
        "active_sessions": list(_account_sessions.keys())
    }

async def refresh_expired_sessions() -> Dict[str, Any]:
    """Refresh expired or soon-to-expire sessions.
    
    Returns:
        Dict containing refresh results
    """
    global _account_sessions, _session_metadata
    
    if not _account_sessions:
        return {
            "success": True,
            "message": "No sessions to refresh",
            "refreshed_count": 0,
            "failed_count": 0
        }
    
    refreshed_count = 0
    failed_count = 0
    refresh_details = []
    expired_sessions = [session_key for session_key, session in _account_sessions.items() if session.is_expired()]
    
    if not expired_sessions:
        return {
            "success": True,
            "message": "No sessions need refreshing",
            "refreshed_count": 0,
            "failed_count": 0
        }
    
    total_sessions = len(expired_sessions)
    processed_sessions = 0
    
    if not config.server.startup_quiet:
        logger.info(f"Refreshing {total_sessions} expired sessions...")
        # Show initial progress
        progress_bar = create_progress_bar(0, total_sessions)
        print(f"\rRefreshing sessions: {progress_bar} 0/{total_sessions} sessions", end="", flush=True)
    
    for session_key, session in list(_account_sessions.items()):
        if session.is_expired():
            logger.debug(f"Refreshing expired session: {session_key}")
            
            # Attempt to refresh
            assume_result = await assume_cross_account_role(
                session.account_id, 
                session.account_name
            )
            
            processed_sessions += 1
            
            if assume_result["success"]:
                # Create new session
                new_session = CredentialSession(
                    account_id=session.account_id,
                    account_name=session.account_name,
                    role_arn=assume_result["role_arn"],
                    credentials=assume_result["credentials"],
                    expiration=assume_result["expiration"]
                )
                
                # Replace old session
                _account_sessions[session_key] = new_session
                _session_metadata[session_key] = new_session.to_dict()
                
                refreshed_count += 1
                refresh_details.append({
                    "session_key": session_key,
                    "account_id": session.account_id,
                    "account_name": session.account_name,
                    "status": "refreshed",
                    "new_expiration": assume_result["expiration"].isoformat() if assume_result["expiration"] else None
                })
                
                logger.debug(f"Successfully refreshed session: {session_key}")
            else:
                failed_count += 1
                refresh_details.append({
                    "session_key": session_key,
                    "account_id": session.account_id,
                    "account_name": session.account_name,
                    "status": "failed",
                    "error": assume_result.get("error", "Unknown error")
                })
                
                logger.debug(f"Failed to refresh session {session_key}: {assume_result.get('error')}")
            
            # Update progress bar
            if not config.server.startup_quiet:
                progress_bar = create_progress_bar(processed_sessions, total_sessions)
                status_text = f"{refreshed_count} successful"
                if failed_count > 0:
                    status_text += f", {failed_count} failed"
                
                print(f"\rRefreshing sessions: {progress_bar} {processed_sessions}/{total_sessions} sessions ({status_text})", end="", flush=True)
    
    # Finish progress line and add final summary
    if not config.server.startup_quiet:
        print()  # New line after progress bar
        
        # Consolidated refresh summary
        if failed_count == 0:
            logger.info(f"Session refresh complete: {refreshed_count} sessions refreshed successfully")
        else:
            logger.info(f"Session refresh complete: {refreshed_count} successful, {failed_count} failed")
    
    return {
        "success": True,
        "refreshed_count": refreshed_count,
        "failed_count": failed_count,
        "total_sessions": len(_account_sessions),
        "refresh_details": refresh_details
    }

async def get_active_sessions() -> Dict[str, Any]:
    """Get information about all active cross-account sessions.
    
    Returns:
        Dict containing active session information
    """
    global _account_sessions, _session_metadata
    
    if not _account_sessions:
        return {
            "success": True,
            "message": "No active sessions",
            "session_count": 0,
            "sessions": []
        }
    
    session_info = []
    
    for session_key, session in _account_sessions.items():
        session_dict = session.to_dict()
        session_dict["session_key"] = session_key
        session_info.append(session_dict)
    
    # Sort by account name for better readability
    session_info.sort(key=lambda x: x["account_name"])
    
    return {
        "success": True,
        "session_count": len(session_info),
        "sessions": session_info
    }

def get_session_for_account(account_identifier: str) -> Optional[CredentialSession]:
    """Get credential session for a specific account.
    
    Args:
        account_identifier: Account ID, account name, or session key
        
    Returns:
        CredentialSession if found and valid, None otherwise
    """
    global _account_sessions
    
    # Try direct session key lookup
    if account_identifier in _account_sessions:
        session = _account_sessions[account_identifier]
        if not session.is_expired():
            return session
    
    # Try to find by account ID or name
    for session_key, session in _account_sessions.items():
        if (session.account_id == account_identifier or 
            session.account_name == account_identifier):
            if not session.is_expired():
                return session
    
    return None

def clear_all_sessions() -> None:
    """Clear all stored sessions."""
    global _account_sessions, _session_metadata
    
    logger.info("Clearing all cross-account sessions")
    _account_sessions.clear()
    _session_metadata.clear() 