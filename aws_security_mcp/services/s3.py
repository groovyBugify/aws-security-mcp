"""S3 service module for AWS Security MCP.

This module provides functions for interacting with AWS S3.

CROSS-ACCOUNT ACCESS FIXES:
- Optimized session context handling to prevent loops
- Reduced concurrency for cross-account operations (max 3 workers vs 10)
- Added proper timeouts and error handling
- Removed redundant account-level public access block calls
- Added progressive delays between chunks for cross-account access
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Callable
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from aws_security_mcp.services.base import get_client, handle_aws_error, format_pagination_response

# Configure logging
logger = logging.getLogger(__name__)

# ThreadPoolExecutor for async operations - use a bounded pool to prevent resource leaks
from concurrent.futures import ThreadPoolExecutor
import functools

from aws_security_mcp.config import config

# Create a bounded thread pool to prevent resource exhaustion
_executor = ThreadPoolExecutor(
    max_workers=config.server.max_concurrent_requests, 
    thread_name_prefix="aws-s3"
)

async def run_in_executor(func: Callable, *args, **kwargs) -> Any:
    """Run a synchronous function in an executor to make it awaitable.
    
    Args:
        func: The synchronous function to call
        *args: Positional arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function
        
    Returns:
        The result of the function call
    """
    loop = asyncio.get_event_loop()
    # Use our bounded executor instead of the default None (unbounded)
    partial_func = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(_executor, partial_func)

def list_buckets(session_context: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all S3 buckets in the account using pagination.

    Args:
        session_context: Optional session key for cross-account access

    Returns:
        List of bucket dictionaries with name and creation date
    """
    try:
        client = get_client('s3', session_context=session_context)
        paginator = client.get_paginator('list_buckets')
        
        all_buckets = []
        # Iterate through each page of results without using PaginationConfig
        for page in paginator.paginate():
            if 'Buckets' in page:
                all_buckets.extend(page['Buckets'])
        
        return all_buckets
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error listing S3 buckets: {str(e)}")
        return []

def get_bucket_location(bucket_name: str, session_context: Optional[str] = None) -> str:
    """Get the region in which the bucket is located.

    Args:
        bucket_name: Name of the S3 bucket
        session_context: Optional session key for cross-account access

    Returns:
        Region name as string or 'us-east-1' if None
    """
    try:
        client = get_client('s3', session_context=session_context)
        response = client.get_bucket_location(Bucket=bucket_name)
        location = response.get('LocationConstraint')
        
        # If None or empty, location is 'us-east-1'
        if not location:
            return 'us-east-1'
        
        # If 'EU', convert to the current name
        if location == 'EU':
            return 'eu-west-1'
            
        return location
    except ClientError as e:
        logger.error(f"Error getting bucket location for {bucket_name}: {str(e)}")
        return 'unknown'

def get_bucket_policy(bucket_name: str, region: Optional[str] = None, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get the bucket policy if it exists.

    Args:
        bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing the policy or None if no policy exists
    """
    try:
        client = get_client('s3', region=region, session_context=session_context)
        response = client.get_bucket_policy(Bucket=bucket_name)
        
        # Convert the policy string to a dictionary
        if 'Policy' in response:
            return json.loads(response['Policy'])
        return None
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'NoSuchBucketPolicy':
            # This is not an error, it just means no policy exists
            return None
        logger.error(f"Error getting bucket policy for {bucket_name}: {str(e)}")
        return None

def get_bucket_acl(bucket_name: str, region: Optional[str] = None, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get the bucket ACL.

    Args:
        bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing the ACL information or None if error
    """
    try:
        client = get_client('s3', region=region, session_context=session_context)
        response = client.get_bucket_acl(Bucket=bucket_name)
        return response
    except ClientError as e:
        logger.error(f"Error getting bucket ACL for {bucket_name}: {str(e)}")
        return None

async def get_bucket_public_access_block(bucket_name: str, session_context: Optional[str] = None) -> Dict[str, bool]:
    """
    Get the public access block configuration for a specific bucket.
    
    Args:
        bucket_name: Name of the S3 bucket
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary containing the public access block settings for the bucket
        
    Raises:
        ClientError: If there's an issue accessing the bucket's public access block configuration
    """
    try:
        s3_client = get_client('s3', session_context=session_context)
        response = await run_in_executor(
            s3_client.get_public_access_block,
            Bucket=bucket_name
        )
        return response.get('PublicAccessBlockConfiguration', {})
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            # Return default values (all False) if no configuration exists
            return {
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False
            }
        elif e.response['Error']['Code'] == 'NoSuchBucket':
            logging.warning(f"Bucket {bucket_name} does not exist.")
            return {
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False
            }
        else:
            logging.error(f"Error getting public access block for bucket {bucket_name}: {str(e)}")
            raise

def get_account_public_access_block(session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get the account-level public access block settings.

    Args:
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing account-level public access block configuration or None if not set
    """
    try:
        # Get the account ID first to ensure we're working with the correct account
        sts_client = get_client('sts', session_context=session_context)
        caller_identity = sts_client.get_caller_identity()
        account_id = caller_identity.get('Account')
        
        logger.debug(f"Getting account public access block for account: {account_id}")
        
        # Use the same session context for s3control client
        s3control = get_client('s3control', session_context=session_context)
        response = s3control.get_public_access_block(AccountId=account_id)
        
        logger.debug(f"Successfully retrieved account public access block for account: {account_id}")
        return response
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'NoSuchPublicAccessBlockConfiguration':
            # This is not an error, it just means no configuration exists
            logger.debug(f"No account-level public access block configuration found")
            return None
        else:
            logger.error(f"Error getting account public access block: {error_code} - {str(e)}")
            return None
    except Exception as e:
        logger.error(f"Unexpected error getting account public access block: {str(e)}")
        return None

def get_bucket_encryption(bucket_name: str, region: Optional[str] = None, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket encryption settings.

    Args:
        bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing encryption settings or None if not configured
    """
    try:
        client = get_client('s3', region=region, session_context=session_context)
        response = client.get_bucket_encryption(Bucket=bucket_name)
        return response
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            # This is not an error, it just means no encryption is configured
            return None
        logger.error(f"Error getting bucket encryption for {bucket_name}: {str(e)}")
        return None

def get_bucket_versioning(bucket_name: str, region: Optional[str] = None, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket versioning settings.

    Args:
        bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing versioning settings or None if error
    """
    try:
        client = get_client('s3', region=region, session_context=session_context)
        response = client.get_bucket_versioning(Bucket=bucket_name)
        return response
    except ClientError as e:
        logger.error(f"Error getting bucket versioning for {bucket_name}: {str(e)}")
        return None

def get_bucket_logging(bucket_name: str, region: Optional[str] = None, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket logging settings.

    Args:
        bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing logging settings or None if error
    """
    try:
        client = get_client('s3', region=region, session_context=session_context)
        response = client.get_bucket_logging(Bucket=bucket_name)
        return response
    except ClientError as e:
        logger.error(f"Error getting bucket logging for {bucket_name}: {str(e)}")
        return None

def get_bucket_lifecycle(bucket_name: str, region: Optional[str] = None, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket lifecycle configuration.
        
    Args:
        bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients
        session_context: Optional session key for cross-account access
            
    Returns:
        Dictionary containing lifecycle configuration or None if not set
    """
    try:
        client = get_client('s3', region=region, session_context=session_context)
        response = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        return response
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'NoSuchLifecycleConfiguration':
            # This is not an error, it just means no lifecycle configuration exists
            return None
        logger.error(f"Error getting bucket lifecycle for {bucket_name}: {str(e)}")
        return None

def get_bucket_tagging(bucket_name: str, region: Optional[str] = None, session_context: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket tags.

    Args:
        bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing bucket tags or None if no tags exist
    """
    try:
        client = get_client('s3', region=region, session_context=session_context)
        response = client.get_bucket_tagging(Bucket=bucket_name)
        return response
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'NoSuchTagSet':
            # This is not an error, it just means no tags exist
            return None
        logger.error(f"Error getting bucket tags for {bucket_name}: {str(e)}")
        return None

def get_bucket_details(bucket_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get detailed information about a specific S3 bucket.

    Args:
        bucket_name: Name of the S3 bucket
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary with comprehensive bucket details
    """
    try:
        bucket_details = {
            'Name': bucket_name
        }
        
        # Get bucket location (region)
        region = get_bucket_location(bucket_name, session_context)
        bucket_details['Region'] = region
        
        # Get all the bucket details using regional client if needed
        policy = get_bucket_policy(bucket_name, region, session_context)
        if policy:
            bucket_details['Policy'] = policy
            
        acl = get_bucket_acl(bucket_name, region, session_context)
        if acl:
            bucket_details['ACL'] = acl
        
        # Get bucket-level public access block configuration
        try:
            # Use boto3 directly for synchronous call
            s3_client = get_client('s3', session_context=session_context)
            resp = s3_client.get_public_access_block(Bucket=bucket_name)
            if resp and 'PublicAccessBlockConfiguration' in resp:
                bucket_details['PublicAccessBlock'] = {
                    'PublicAccessBlockConfiguration': resp['PublicAccessBlockConfiguration']
                }
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                logger.warning(f"Could not get public access block for {bucket_name}: {str(e)}")
        except Exception as e:
            logger.warning(f"Could not get public access block for {bucket_name}: {str(e)}")
        
        encryption = get_bucket_encryption(bucket_name, region, session_context)
        if encryption:
            bucket_details['Encryption'] = encryption
        
        versioning = get_bucket_versioning(bucket_name, region, session_context)
        if versioning:
            bucket_details['Versioning'] = versioning
        
        logging = get_bucket_logging(bucket_name, region, session_context)
        if logging:
            bucket_details['Logging'] = logging
        
        lifecycle = get_bucket_lifecycle(bucket_name, region, session_context)
        if lifecycle:
            bucket_details['Lifecycle'] = lifecycle
            
        # Get bucket tags
        tagging = get_bucket_tagging(bucket_name, region, session_context)
        if tagging:
            bucket_details['Tagging'] = tagging
            
        # NOTE: Removed account-level public access block call here to prevent loops
        # The caller should get this separately if needed
        
        return bucket_details
    except Exception as e:
        logger.error(f"Error getting details for bucket {bucket_name}: {str(e)}")
        return {'Name': bucket_name, 'Error': str(e)}

def get_bucket_details_batch(
    bucket_names: List[str], 
    max_workers: int = 10,
    session_context: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    """Get detailed information about multiple S3 buckets in parallel.

    Args:
        bucket_names: List of bucket names to get details for
        max_workers: Maximum number of threads to use
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary mapping bucket names to their detailed information
    """
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create a future for each bucket
        future_to_bucket = {
            executor.submit(get_bucket_details, bucket_name, session_context): bucket_name
            for bucket_name in bucket_names
        }
        
        # Process the results as they complete
        for future in future_to_bucket:
            bucket_name = future_to_bucket[future]
            try:
                results[bucket_name] = future.result()
            except Exception as e:
                logger.error(f"Error processing bucket {bucket_name}: {str(e)}")
                results[bucket_name] = {'Name': bucket_name, 'Error': str(e)}
    
    return results

def is_bucket_public(bucket_name: str, account_public_access_block: Optional[Dict] = None, session_context: Optional[str] = None) -> Tuple[bool, Dict]:
    """Check if an S3 bucket is publicly accessible.
    
    Args:
        bucket_name: Name of the bucket to check
        account_public_access_block: Account-level public access block settings to avoid repeated API calls
        session_context: Optional session key for cross-account access
    
    Returns:
        Tuple containing:
        - Boolean indicating if the bucket is public
        - Assessment dictionary with details about the bucket's public access settings
    """
    assessment = {
        'bucket_name': bucket_name,
        'is_public': False,
        'public_access_block': None,
        'acl_public': False,
        'policy_public': False,
        'errors': []
    }
    
    try:
        logger.debug(f"Checking public access for bucket: {bucket_name}")
        
        # Store account-level public access block settings for context
        # NOTE: Account-level blocks don't completely prevent public access - they affect NEW policies/ACLs
        # but existing public configurations may still make buckets accessible
        if account_public_access_block:
            block_config = account_public_access_block.get('PublicAccessBlockConfiguration', {})
            assessment['account_level_blocks'] = block_config
            logger.debug(f"Account-level public access blocks: {block_config}")
        else:
            logger.debug(f"No account-level public access blocks configured")
        
        # Get bucket-level public access block configuration
        try:
            # Use synchronous version to avoid async issues in this function
            s3_client = get_client('s3', session_context=session_context)
            try:
                resp = s3_client.get_public_access_block(Bucket=bucket_name)
                public_access_block = resp.get('PublicAccessBlockConfiguration', {})
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    public_access_block = {
                        'BlockPublicAcls': False,
                        'IgnorePublicAcls': False,
                        'BlockPublicPolicy': False,
                        'RestrictPublicBuckets': False
                    }
                else:
                    raise
            
            assessment['public_access_block'] = public_access_block
            
            # If bucket-level blocks ALL public access settings, the bucket should not be public
            # However, we still check ACL/policy as there could be race conditions or misconfigurations
            if public_access_block:
                all_blocked = (public_access_block.get('BlockPublicAcls', False) and 
                              public_access_block.get('IgnorePublicAcls', False) and
                              public_access_block.get('BlockPublicPolicy', False) and
                              public_access_block.get('RestrictPublicBuckets', False))
                
                if all_blocked:
                    logger.debug(f"Bucket {bucket_name} has all public access blocks enabled - should not be public")
                    # Continue checking anyway to detect any misconfigurations
                    assessment['bucket_fully_blocked'] = True
                else:
                    assessment['bucket_fully_blocked'] = False
            else:
                assessment['bucket_fully_blocked'] = False
                    
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['AccessDenied', 'NoSuchBucket']:
                error_msg = f"Cannot access bucket {bucket_name}: {error_code}"
                logger.warning(error_msg)
                assessment['errors'].append(error_msg)
                # If we can't access the bucket, assume it's not public
                return False, assessment
            else:
                error_msg = f"Error getting public access block for {bucket_name}: {error_code}"
                logger.warning(error_msg)
                assessment['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error getting public access block for {bucket_name}: {str(e)}"
            logger.warning(error_msg)
            assessment['errors'].append(error_msg)
        
        # Check bucket ACL for public access (only if we have access)
        try:
            acl = get_bucket_acl(bucket_name, session_context=session_context)
            
            # Check for public grants in the ACL
            if acl and 'Grants' in acl:
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group' and 'URI' in grantee:
                        if grantee['URI'] in ['http://acs.amazonaws.com/groups/global/AllUsers', 
                                             'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                            assessment['acl_public'] = True
                            logger.debug(f"Bucket {bucket_name} has public ACL grant: {grantee['URI']}")
                            break
                            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['AccessDenied', 'NoSuchBucket']:
                error_msg = f"Cannot access ACL for bucket {bucket_name}: {error_code}"
                logger.debug(error_msg)  # Use debug for access denied, as it's common
                assessment['errors'].append(error_msg)
            else:
                error_msg = f"Error getting ACL for {bucket_name}: {error_code}"
                logger.warning(error_msg)
                assessment['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error getting ACL for {bucket_name}: {str(e)}"
            logger.warning(error_msg)
            assessment['errors'].append(error_msg)
        
        # Check bucket policy for public access (only if we have access)
        try:
            policy = get_bucket_policy(bucket_name, session_context=session_context)
            
            if policy:
                # Simple check for public policy statements
                for statement in policy.get('Statement', []):
                    principal = statement.get('Principal', {})
                    effect = statement.get('Effect', '')
                    
                    # Check if policy allows public access
                    if effect.upper() == 'ALLOW' and (
                        principal == '*' or 
                        principal == {"AWS": "*"} or 
                        (isinstance(principal, dict) and principal.get('AWS') == '*')
                    ):
                        assessment['policy_public'] = True
                        logger.debug(f"Bucket {bucket_name} has public policy")
                        break
                        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'NoSuchBucketPolicy':
                # This is normal for buckets without policies
                logger.debug(f"Bucket {bucket_name} has no bucket policy")
            elif error_code in ['AccessDenied', 'NoSuchBucket']:
                error_msg = f"Cannot access policy for bucket {bucket_name}: {error_code}"
                logger.debug(error_msg)  # Use debug for access denied
                assessment['errors'].append(error_msg)
            else:
                error_msg = f"Error getting policy for {bucket_name}: {error_code}"
                logger.warning(error_msg)
                assessment['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error analyzing policy for {bucket_name}: {str(e)}"
            logger.warning(error_msg)
            assessment['errors'].append(error_msg)
        
        # Determine if the bucket is public based on ACL and policy
        is_public = assessment['acl_public'] or assessment['policy_public']
        assessment['is_public'] = is_public
        
        # Check for critical misconfigurations: public bucket despite protection settings
        account_blocks = assessment.get('account_level_blocks', {})
        bucket_fully_blocked = assessment.get('bucket_fully_blocked', False)
        
        if is_public:
            assessment['critical_misconfiguration'] = False
            assessment['misconfiguration_reason'] = []
            
            # Check bucket-level misconfiguration (highest priority)
            if bucket_fully_blocked:
                assessment['critical_misconfiguration'] = True
                assessment['misconfiguration_reason'].append(
                    "Bucket is public despite having ALL public access blocks enabled at bucket level"
                )
                logger.error(f"CRITICAL: Bucket {bucket_name} is PUBLIC despite full bucket-level blocks!")
            
            # Check account-level misconfiguration
            elif account_blocks:
                should_be_blocked_acl = account_blocks.get('BlockPublicAcls') and assessment['acl_public']
                should_be_blocked_policy = account_blocks.get('BlockPublicPolicy') and assessment['policy_public']
                
                if should_be_blocked_acl or should_be_blocked_policy:
                    assessment['critical_misconfiguration'] = True
                    
                    if should_be_blocked_acl:
                        assessment['misconfiguration_reason'].append(
                            "Public ACL exists despite account-level BlockPublicAcls setting"
                        )
                    if should_be_blocked_policy:
                        assessment['misconfiguration_reason'].append(
                            "Public policy exists despite account-level BlockPublicPolicy setting"
                        )
                    
                    logger.warning(f"CRITICAL: Bucket {bucket_name} is PUBLIC despite account-level blocks! "
                                 f"Reasons: {assessment['misconfiguration_reason']}")
        else:
            assessment['critical_misconfiguration'] = False
        
        if is_public:
            log_level = logger.warning if assessment.get('critical_misconfiguration') else logger.info
            log_level(f"Bucket {bucket_name} is PUBLIC - ACL: {assessment['acl_public']}, "
                     f"Policy: {assessment['policy_public']}, "
                     f"Critical: {assessment.get('critical_misconfiguration', False)}")
        else:
            logger.debug(f"Bucket {bucket_name} is not public")
        
        return is_public, assessment
        
    except Exception as e:
        error_msg = f"Error checking if bucket {bucket_name} is public: {str(e)}"
        logger.error(error_msg)
        assessment['errors'].append(error_msg)
        return False, assessment

def find_public_buckets(max_workers: int = 10, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Find all public S3 buckets in the account.

    Args:
        max_workers: Maximum number of threads to use
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary with assessment results
    """
    try:
        # Start timing
        start_time = datetime.now()
        
        logger.info(f"Starting public buckets scan with session_context: {session_context is not None}")
        
        # Get account-level public access block settings first
        logger.debug("Getting account-level public access block settings...")
        account_public_access_block = get_account_public_access_block(session_context)
        
        # Store account-level blocks for context - they don't completely prevent public access
        # Account-level blocks affect NEW configurations but existing public configs may remain
        if account_public_access_block:
            block_config = account_public_access_block.get('PublicAccessBlockConfiguration', {})
            logger.info(f"Account-level public access blocks configured: {block_config}")
        else:
            logger.info("No account-level public access blocks configured")
        
        # List all buckets
        logger.debug("Listing all S3 buckets...")
        all_buckets = list_buckets(session_context)
        total_buckets = len(all_buckets)
        
        if total_buckets == 0:
            logger.info("No S3 buckets found in the account")
            return {
                'total_buckets': 0,
                'public_buckets_count': 0,
                'public_buckets': [],
                'account_public_access_block': account_public_access_block,
                'bucket_assessments': {},
                'scan_timestamp': datetime.now().isoformat(),
                'scan_time_seconds': (datetime.now() - start_time).total_seconds()
            }
        
        logger.info(f"Checking {total_buckets} S3 buckets for public access")
        
        # Reduce concurrency to prevent session conflicts - especially important for cross-account access
        if session_context:
            # For cross-account access, use much lower concurrency to prevent conflicts
            max_workers = min(3, max_workers, total_buckets)
            chunk_size = min(10, total_buckets)
        else:
            # For same-account access, we can use higher concurrency
            max_workers = min(max_workers, 10, total_buckets)
            chunk_size = min(20, total_buckets)
        
        logger.info(f"Using {max_workers} workers with chunk size {chunk_size}")
        
        # Check each bucket for public access
        public_buckets = []
        bucket_assessments = {}
        
        # Process in smaller batches to avoid overwhelming the API and prevent session conflicts
        for i in range(0, total_buckets, chunk_size):
            bucket_chunk = all_buckets[i:i+chunk_size]
            chunk_num = i//chunk_size + 1
            total_chunks = (total_buckets+chunk_size-1)//chunk_size
            
            logger.debug(f"Processing bucket chunk {chunk_num} of {total_chunks} ({len(bucket_chunk)} buckets)")
            
            # Use a smaller thread pool to prevent session conflicts
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Create a map of futures to buckets for this chunk
                futures = {}
                
                for bucket in bucket_chunk:
                    bucket_name = bucket['Name']
                    future = executor.submit(
                        is_bucket_public, 
                        bucket_name, 
                        account_public_access_block, 
                        session_context
                    )
                    futures[future] = bucket
                
                # Process results as they complete with timeout
                import concurrent.futures
                for future in concurrent.futures.as_completed(futures, timeout=300):  # 5 minute timeout
                    bucket = futures[future]
                    bucket_name = bucket['Name']
                    
                    try:
                        is_public, assessment = future.result(timeout=60)  # 1 minute timeout per bucket
                        bucket_assessments[bucket_name] = assessment
                        
                        if is_public:
                            public_buckets.append(bucket)
                            logger.info(f"Found public bucket: {bucket_name}")
                        else:
                            logger.debug(f"Bucket {bucket_name} is not public")
                            
                    except concurrent.futures.TimeoutError:
                        logger.error(f"Timeout checking if bucket {bucket_name} is public")
                        bucket_assessments[bucket_name] = {
                            'bucket_name': bucket_name,
                            'is_public': False,
                            'errors': ['Timeout during public access check']
                        }
                    except Exception as e:
                        logger.error(f"Error checking if bucket {bucket_name} is public: {str(e)}")
                        bucket_assessments[bucket_name] = {
                            'bucket_name': bucket_name,
                            'is_public': False,
                            'errors': [str(e)]
                        }
            
            # Add a small delay between chunks when using cross-account access to prevent rate limiting
            if session_context and chunk_num < total_chunks:
                import time
                time.sleep(0.5)
        
        # Compile the results
        public_buckets_count = len(public_buckets)
        
        # Calculate scan time
        scan_time_seconds = (datetime.now() - start_time).total_seconds()
        logger.info(f"Found {public_buckets_count} public buckets out of {total_buckets} total in {scan_time_seconds:.2f} seconds")
        
        return {
            'total_buckets': total_buckets,
            'public_buckets_count': public_buckets_count,
            'public_buckets': public_buckets,
            'account_public_access_block': account_public_access_block,
            'bucket_assessments': bucket_assessments,
            'scan_timestamp': datetime.now().isoformat(),
            'scan_time_seconds': scan_time_seconds
        }
    
    except Exception as e:
        logger.error(f"Error finding public buckets: {str(e)}")
        return {
            'error': str(e),
            'total_buckets': 0,
            'public_buckets_count': 0,
            'public_buckets': [],
            'scan_timestamp': datetime.now().isoformat(),
            'scan_time_seconds': 0
        }

def count_s3_buckets(session_context: Optional[str] = None) -> Dict[str, Any]:
    """Count S3 buckets by region.

    Returns:
        Dictionary with counts by region and total
    """
    try:
        # List all buckets
        all_buckets = list_buckets(session_context)
        total_buckets = len(all_buckets)
        
        # Get the region for each bucket
        region_counts = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Map bucket names to their regions
            bucket_to_region = {
                bucket['Name']: executor.submit(get_bucket_location, bucket['Name'], session_context)
                for bucket in all_buckets
            }
            
            # Count buckets by region
            for bucket_name, future in bucket_to_region.items():
                try:
                    region = future.result()
                    if region not in region_counts:
                        region_counts[region] = 0
                    region_counts[region] += 1
                except Exception as e:
                    logger.error(f"Error getting region for bucket {bucket_name}: {str(e)}")
                    # Count unknown regions
                    if 'unknown' not in region_counts:
                        region_counts['unknown'] = 0
                    region_counts['unknown'] += 1
        
        # Sort regions by count (descending)
        sorted_regions = [
            {'region': region, 'count': count}
            for region, count in sorted(region_counts.items(), key=lambda x: x[1], reverse=True)
        ]
        
        return {
            'total': total_buckets,
            'by_region': sorted_regions,
            'scan_timestamp': datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error counting S3 buckets: {str(e)}")
        return {
            'total': 0,
            'by_region': [],
            'error': str(e),
            'scan_timestamp': datetime.now().isoformat()
        } 