"""AWS Cross-Account Credentials Service for AWS Security MCP.

This service manages cross-account access by discovering organization accounts,
assuming roles, storing sessions, and automatically refreshing credentials.
"""

import asyncio
import logging
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import json

from botocore.exceptions import ClientError
from botocore.config import Config
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
# Note: Session duration is now configured in config.yaml (cross_account.session_duration_seconds)

# Shared STS client with connection pooling
_sts_client = None
_client_lock = threading.Lock()

class ThreadSafeCounter:
    """Thread-safe counter for tracking failures."""
    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()
    
    def get_and_increment(self):
        with self._lock:
            current = self._value
            self._value += 1
            return current
    
    def reset(self):
        with self._lock:
            self._value = 0

# Global counter for failed account logging
failed_account_counter = ThreadSafeCounter()

def get_optimized_sts_client():
    """Get a shared STS client with connection pooling and retry configuration."""
    global _sts_client
    
    if _sts_client is None:
        with _client_lock:
            if _sts_client is None:
                # Create boto3 config with connection pooling and retry logic
                boto_config = Config(
                    max_pool_connections=config.cross_account.connection_pool_size,
                    retries={
                        'max_attempts': config.cross_account.retry_max_attempts,
                        'mode': 'adaptive'
                    },
                    region_name=config.aws.aws_region
                )
                
                # Create optimized STS client
                if config.aws.has_profile:
                    session = boto3.Session(profile_name=config.aws.aws_profile)
                    _sts_client = session.client('sts', config=boto_config)
                else:
                    _sts_client = boto3.client('sts', config=boto_config)
                
                logger.debug(f"Created optimized STS client with {config.cross_account.connection_pool_size} connection pool")
    
    return _sts_client

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
        threshold = now + timedelta(minutes=config.cross_account.refresh_threshold_minutes)
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

def discover_organization_accounts_sync() -> Dict[str, Any]:
    """Discover all accounts in the AWS organization synchronously.
    
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

async def discover_organization_accounts() -> Dict[str, Any]:
    """Discover all accounts in the AWS organization (async wrapper).
    
    Returns:
        Dict containing organization accounts or error information
    """
    import asyncio
    
    # Run the synchronous version in a thread to avoid blocking
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, discover_organization_accounts_sync)

def assume_cross_account_role_sync(account_id: str, account_name: str) -> Dict[str, Any]:
    """Assume cross-account role in target account with retry logic.
    
    Args:
        account_id: Target AWS account ID
        account_name: Target AWS account name
        
    Returns:
        Dict containing assumed role credentials or error information
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"
    
    for attempt in range(config.cross_account.retry_max_attempts):
        try:
            sts_client = get_optimized_sts_client()
            
            # Assume role
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=SESSION_NAME,
                DurationSeconds=config.cross_account.session_duration_seconds
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
            
            # Check if this is a retryable error
            retryable_errors = ['Throttling', 'ThrottlingException', 'RequestTimeout', 'ServiceUnavailable']
            
            if error_code in retryable_errors and attempt < config.cross_account.retry_max_attempts - 1:
                # Apply exponential backoff
                sleep_time = config.cross_account.retry_backoff_factor ** attempt
                logger.debug(f"Retrying assume role for account {account_id} in {sleep_time:.2f}s (attempt {attempt + 1})")
                time.sleep(sleep_time)
                continue
            
            # Log first few failures at WARNING level to help diagnose issues
            if failed_account_counter.get_and_increment() < 3:
                logger.warning(f"Failed to assume role in account {account_id} ({account_name}): {error_code} - {str(e)}")
            else:
                logger.debug(f"Failed to assume role in account {account_id} ({account_name}): {str(e)}")
            
            return {
                "success": False,
                "account_id": account_id,
                "account_name": account_name,
                "role_arn": role_arn,
                "error": str(e),
                "error_code": error_code,
                "attempts": attempt + 1
            }
        
        except Exception as e:
            # Non-AWS errors are not retryable
            if failed_account_counter.get_and_increment() < 3:
                logger.warning(f"Non-retryable error assuming role in account {account_id} ({account_name}): {str(e)}")
            else:
                logger.debug(f"Non-retryable error assuming role in account {account_id} ({account_name}): {str(e)}")
            return {
                "success": False,
                "account_id": account_id,
                "account_name": account_name,
                "role_arn": role_arn,
                "error": str(e),
                "error_code": "NonRetryableError",
                "attempts": attempt + 1
            }
    
    # Should not reach here, but just in case
    return {
        "success": False,
        "account_id": account_id,
        "account_name": account_name,
        "role_arn": role_arn,
        "error": "Maximum retry attempts exceeded",
        "error_code": "MaxRetriesExceeded"
    }

async def setup_cross_account_sessions() -> Dict[str, Any]:
    """Set up cross-account sessions for all organization accounts using ThreadPoolExecutor.
    
    Returns:
        Dict containing session setup results
    """
    global _account_sessions, _session_metadata
    
    logger.info("Setting up cross-account sessions...")
    
    # First, discover organization accounts (run synchronously since we're already optimizing for ThreadPool)
    accounts_result = discover_organization_accounts_sync()
    
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
    
    # Get current account to skip it
    current_account = get_client('sts').get_caller_identity().get('Account')
    
    # Filter out current account
    target_accounts = [acc for acc in accounts if acc.get('Id') != current_account]
    
    if not target_accounts:
        return {
            "success": True,
            "message": "Only current account found in organization",
            "sessions_created": 0,
            "sessions_failed": 0,
            "accounts_processed": len(accounts)
        }
    
    total_accounts = len(target_accounts)
    logger.info(f"Processing {total_accounts} target accounts (excluding current account)")
    
    # Reset failure counter for this session setup
    global failed_account_counter
    failed_account_counter.reset()
    
    # Progress tracking (thread-safe)
    processed_accounts = 0
    successful_sessions = 0
    failed_sessions = 0
    progress_lock = threading.Lock()
    
    def update_progress_threadsafe(success: bool = False, failed: bool = False):
        nonlocal processed_accounts, successful_sessions, failed_sessions
        with progress_lock:
            processed_accounts += 1
            if success:
                successful_sessions += 1
            elif failed:
                failed_sessions += 1
            
            # Show progress bar at configured intervals
            update_interval = config.cross_account.progress_update_interval
            if (not config.server.startup_quiet and 
                (update_interval == 0 or processed_accounts % update_interval == 0 or 
                 processed_accounts == total_accounts)):
                
                progress_bar = create_progress_bar(processed_accounts, total_accounts)
                status_text = f"{successful_sessions} successful"
                if failed_sessions > 0:
                    status_text += f", {failed_sessions} failed"
                
                print(f"\rAssuming roles: {progress_bar} {processed_accounts}/{total_accounts} accounts ({status_text})", end="", flush=True)
    
    def process_account_sync(account: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single account synchronously."""
        account_id = account.get('Id')
        account_name = account.get('Name')
        
        try:
            # Attempt to assume role
            assume_result = assume_cross_account_role_sync(account_id, account_name)
            
            if assume_result["success"]:
                # Create credential session
                session = CredentialSession(
                    account_id=account_id,
                    account_name=account_name,
                    role_arn=assume_result["role_arn"],
                    credentials=assume_result["credentials"],
                    expiration=assume_result["expiration"]
                )
                
                # Store session (thread-safe)
                session_key = generate_session_key(account_id, account_name)
                with progress_lock:  # Protect shared session storage
                    _account_sessions[session_key] = session
                    _session_metadata[session_key] = session.to_dict()
                
                update_progress_threadsafe(success=True)
                return {
                    "account_id": account_id,
                    "account_name": account_name,
                    "session_key": session_key,
                    "status": "success",
                    "expiration": assume_result["expiration"].isoformat() if assume_result["expiration"] else None
                }
            else:
                update_progress_threadsafe(failed=True)
                return {
                    "account_id": account_id,
                    "account_name": account_name,
                    "status": "failed",
                    "error": assume_result.get("error", "Unknown error"),
                    "error_code": assume_result.get("error_code", "Unknown"),
                    "attempts": assume_result.get("attempts", 1)
                }
        
        except Exception as e:
            logger.error(f"Exception processing account {account_id} ({account_name}): {e}")
            update_progress_threadsafe(failed=True)
            return {
                "account_id": account_id,
                "account_name": account_name,
                "status": "failed",
                "error": str(e),
                "error_code": "ProcessingException"
            }
    
    # Show initial progress
    if not config.server.startup_quiet:
        progress_bar = create_progress_bar(0, total_accounts)
        print(f"\rAssuming roles: {progress_bar} 0/{total_accounts} accounts", end="", flush=True)
    
    # Determine concurrency level
    max_workers = config.cross_account.max_concurrent_assumptions
    if max_workers == 0:  # 0 means unlimited
        max_workers = min(len(target_accounts), 100)  # Cap at 100 for safety
    
    logger.debug(f"Using ThreadPoolExecutor with {max_workers} workers")
    
    # Process accounts with ThreadPoolExecutor for true concurrency
    session_details = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_account = {
            executor.submit(process_account_sync, account): account
            for account in target_accounts
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_account):
            try:
                result = future.result()
                session_details.append(result)
            except Exception as e:
                account = future_to_account[future]
                logger.error(f"Exception in future for account {account.get('Id', 'Unknown')}: {e}")
                session_details.append({
                    "account_id": account.get('Id', 'Unknown'),
                    "account_name": account.get('Name', 'Unknown'),
                    "status": "failed",
                    "error": str(e),
                    "error_code": "FutureException"
                })
    
    # Finish progress line and add final summary
    if not config.server.startup_quiet:
        print()  # New line after progress bar
    
    processing_time = time.time() - start_time
    
    # Final consolidated summary log
    if not config.server.startup_quiet:
        if successful_sessions == 0 and failed_sessions == 0:
            logger.info("Cross-account setup complete: No accounts required role assumption")
        elif failed_sessions == 0:
            logger.info(f"Cross-account setup complete: {successful_sessions}/{total_accounts} accounts accessible in {processing_time:.2f}s")
        else:
            logger.info(f"Cross-account setup complete: {successful_sessions} successful, {failed_sessions} failed ({total_accounts} total) in {processing_time:.2f}s")
            
            # Show error summary for failed attempts
            if failed_sessions > 0:
                error_counts = {}
                for detail in session_details:
                    if detail.get("status") == "failed":
                        error_code = detail.get("error_code", "Unknown")
                        error_counts[error_code] = error_counts.get(error_code, 0) + 1
                
                if error_counts:
                    error_summary = ", ".join([f"{code}: {count}" for code, count in error_counts.items()])
                    logger.warning(f"Common failure reasons: {error_summary}")
        
        if successful_sessions > 0:
            throughput = successful_sessions / processing_time
            logger.debug(f"Performance: {throughput:.1f} successful assumptions/second")
    
    return {
        "success": True,
        "sessions_created": successful_sessions,
        "sessions_failed": failed_sessions,
        "accounts_processed": len(accounts),
        "processing_time_seconds": processing_time,
        "throughput_per_second": successful_sessions / processing_time if processing_time > 0 else 0,
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
            assume_result = assume_cross_account_role_sync(
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

 