"""S3 service module for AWS Security MCP.

This module provides functions for interacting with AWS S3.
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

def list_buckets() -> List[Dict[str, Any]]:
    """List all S3 buckets in the account using pagination.

    Returns:
        List of bucket dictionaries with name and creation date
    """
    try:
        client = get_client('s3')
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

def get_bucket_location(bucket_name: str) -> str:
    """Get the region in which the bucket is located.

        Args:
        bucket_name: Name of the S3 bucket

        Returns:
        Region name as string or 'us-east-1' if None
    """
    try:
        client = get_client('s3')
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

def get_bucket_policy(bucket_name: str, region: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get the bucket policy if it exists.

        Args:
            bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients

        Returns:
        Dictionary containing the policy or None if no policy exists
        """
    try:
        client = get_client('s3', region=region)
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

def get_bucket_acl(bucket_name: str, region: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get the bucket ACL.

        Args:
            bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients

        Returns:
        Dictionary containing the ACL information or None if error
        """
    try:
        client = get_client('s3', region=region)
        response = client.get_bucket_acl(Bucket=bucket_name)
        return response
    except ClientError as e:
        logger.error(f"Error getting bucket ACL for {bucket_name}: {str(e)}")
        return None

async def get_bucket_public_access_block(bucket_name: str) -> Dict[str, bool]:
    """
    Get the public access block configuration for a specific bucket.
    
    Args:
        bucket_name: Name of the S3 bucket
        
    Returns:
        Dictionary containing the public access block settings for the bucket
        
    Raises:
        ClientError: If there's an issue accessing the bucket's public access block configuration
    """
    try:
        s3_client = boto3.client('s3')
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

def get_account_public_access_block() -> Optional[Dict[str, Any]]:
    """Get the account-level public access block settings.

        Returns:
        Dictionary containing account-level public access block configuration or None if not set
        """
    try:
        s3control = get_client('s3control')
        account_id = get_client('sts').get_caller_identity().get('Account')
        response = s3control.get_public_access_block(AccountId=account_id)
        return response
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'NoSuchPublicAccessBlockConfiguration':
            # This is not an error, it just means no configuration exists
            return None
        logger.error(f"Error getting account public access block: {str(e)}")
        return None

def get_bucket_encryption(bucket_name: str, region: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket encryption settings.

        Args:
            bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients

        Returns:
        Dictionary containing encryption settings or None if not configured
        """
    try:
        client = get_client('s3', region=region)
        response = client.get_bucket_encryption(Bucket=bucket_name)
        return response
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            # This is not an error, it just means no encryption is configured
            return None
        logger.error(f"Error getting bucket encryption for {bucket_name}: {str(e)}")
        return None

def get_bucket_versioning(bucket_name: str, region: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket versioning settings.

        Args:
            bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients

        Returns:
        Dictionary containing versioning settings or None if error
        """
    try:
        client = get_client('s3', region=region)
        response = client.get_bucket_versioning(Bucket=bucket_name)
        return response
    except ClientError as e:
        logger.error(f"Error getting bucket versioning for {bucket_name}: {str(e)}")
        return None

def get_bucket_logging(bucket_name: str, region: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket logging settings.

        Args:
            bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients

        Returns:
        Dictionary containing logging settings or None if error
        """
    try:
        client = get_client('s3', region=region)
        response = client.get_bucket_logging(Bucket=bucket_name)
        return response
    except ClientError as e:
        logger.error(f"Error getting bucket logging for {bucket_name}: {str(e)}")
        return None

def get_bucket_lifecycle(bucket_name: str, region: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get bucket lifecycle configuration.
        
        Args:
            bucket_name: Name of the S3 bucket
        region: Optional region to use for regional clients
            
        Returns:
        Dictionary containing lifecycle configuration or None if not set
        """
    try:
        client = get_client('s3', region=region)
        response = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        return response
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'NoSuchLifecycleConfiguration':
            # This is not an error, it just means no lifecycle configuration exists
            return None
        logger.error(f"Error getting bucket lifecycle for {bucket_name}: {str(e)}")
        return None

def get_bucket_details(bucket_name: str) -> Dict[str, Any]:
    """Get detailed information about a specific S3 bucket.

    Args:
        bucket_name: Name of the S3 bucket

    Returns:
        Dictionary with comprehensive bucket details
    """
    try:
        bucket_details = {
            'Name': bucket_name
        }
        
        # Get bucket location (region)
        region = get_bucket_location(bucket_name)
        bucket_details['Region'] = region
        
        # Get all the bucket details using regional client if needed
        policy = get_bucket_policy(bucket_name, region)
        if policy:
            bucket_details['Policy'] = policy
            
        acl = get_bucket_acl(bucket_name, region)
        if acl:
            bucket_details['ACL'] = acl
        
        # Note: We can't await here since this is a sync function
        # For async access to public_access_block, use get_bucket_details_async
        # Just provide a warning that public access block might not be included
        try:
            # Use boto3 directly for synchronous call
            s3_client = get_client('s3')
            resp = s3_client.get_public_access_block(Bucket=bucket_name)
            if resp and 'PublicAccessBlockConfiguration' in resp:
                bucket_details['PublicAccessBlock'] = {
                    'PublicAccessBlockConfiguration': resp['PublicAccessBlockConfiguration']
                }
        except Exception as e:
            # Not critical, just log and continue
            logger.warning(f"Could not get public access block for {bucket_name} synchronously: {str(e)}")
        
        encryption = get_bucket_encryption(bucket_name, region)
        if encryption:
            bucket_details['Encryption'] = encryption
        
        versioning = get_bucket_versioning(bucket_name, region)
        if versioning:
            bucket_details['Versioning'] = versioning
        
        logging = get_bucket_logging(bucket_name, region)
        if logging:
            bucket_details['Logging'] = logging
        
        lifecycle = get_bucket_lifecycle(bucket_name, region)
        if lifecycle:
            bucket_details['Lifecycle'] = lifecycle
            
        # Get account-level public access block settings
        account_public_access_block = get_account_public_access_block()
        if account_public_access_block:
            bucket_details['account_public_access_block'] = account_public_access_block
        
        return bucket_details
    except Exception as e:
        logger.error(f"Error getting details for bucket {bucket_name}: {str(e)}")
        return {'Name': bucket_name, 'Error': str(e)}

def get_bucket_details_batch(
    bucket_names: List[str], 
    max_workers: int = 10
) -> Dict[str, Dict[str, Any]]:
    """Get detailed information about multiple S3 buckets in parallel.

        Args:
        bucket_names: List of bucket names to get details for
        max_workers: Maximum number of threads to use

        Returns:
        Dictionary mapping bucket names to their detailed information
    """
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create a future for each bucket
        future_to_bucket = {
            executor.submit(get_bucket_details, bucket_name): bucket_name
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

def is_bucket_public(bucket_name: str, account_public_access_block: Optional[Dict] = None) -> Tuple[bool, Dict]:
    """Check if an S3 bucket is publicly accessible.
    
    Args:
        bucket_name: Name of the bucket to check
        account_public_access_block: Account-level public access block settings to avoid repeated API calls
    
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
        # Check account-level public access block settings first
        if account_public_access_block:
            block_config = account_public_access_block.get('PublicAccessBlockConfiguration', {})
            all_blocked = (block_config.get('BlockPublicAcls', False) and 
                          block_config.get('IgnorePublicAcls', False) and
                          block_config.get('BlockPublicPolicy', False) and
                          block_config.get('RestrictPublicBuckets', False))
            
            if all_blocked:
                # If account-level blocks all public access, the bucket cannot be public
                logger.debug(f"Bucket {bucket_name} protected by account-level public access blocks")
                assessment['account_level_blocks'] = block_config
                return False, assessment
        
        # Get bucket-level public access block configuration
        try:
            public_access_block = get_bucket_public_access_block(bucket_name)
            assessment['public_access_block'] = public_access_block
            
            # If bucket-level blocks all public access, the bucket cannot be public
            if public_access_block:
                block_config = public_access_block.get('PublicAccessBlockConfiguration', {})
                all_blocked = (block_config.get('BlockPublicAcls', False) and 
                              block_config.get('IgnorePublicAcls', False) and
                              block_config.get('BlockPublicPolicy', False) and
                              block_config.get('RestrictPublicBuckets', False))
                
                if all_blocked:
                    logger.debug(f"Bucket {bucket_name} protected by bucket-level public access blocks")
                    return False, assessment
        except Exception as e:
            error_msg = f"Error getting public access block for {bucket_name}: {str(e)}"
            logger.warning(error_msg)
            assessment['errors'].append(error_msg)
        
        # Check bucket ACL for public access
        try:
            acl = get_bucket_acl(bucket_name)
            
            # Check for public grants in the ACL
            if acl and 'Grants' in acl:
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group' and 'URI' in grantee:
                        if grantee['URI'] in ['http://acs.amazonaws.com/groups/global/AllUsers', 
                                             'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                            assessment['acl_public'] = True
                            break
        except Exception as e:
            error_msg = f"Error getting ACL for {bucket_name}: {str(e)}"
            logger.warning(error_msg)
            assessment['errors'].append(error_msg)
        
        # Check bucket policy for public access
        try:
            policy = get_bucket_policy(bucket_name)
            
            if policy and 'Policy' in policy:
                policy_json = json.loads(policy['Policy'])
                
                # Simple check for public policy statements
                for statement in policy_json.get('Statement', []):
                    principal = statement.get('Principal', {})
                    effect = statement.get('Effect', '')
                    
                    # Check if policy allows public access
                    if effect.upper() == 'ALLOW' and (
                        principal == '*' or 
                        principal == {"AWS": "*"} or 
                        (isinstance(principal, dict) and principal.get('AWS') == '*')
                    ):
                        assessment['policy_public'] = True
                        break
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                # This is normal for buckets without policies
                pass
            else:
                error_msg = f"Error getting policy for {bucket_name}: {str(e)}"
                logger.warning(error_msg)
                assessment['errors'].append(error_msg)
        except Exception as e:
            error_msg = f"Error analyzing policy for {bucket_name}: {str(e)}"
            logger.warning(error_msg)
            assessment['errors'].append(error_msg)
        
        # Determine if the bucket is public based on ACL and policy
        is_public = assessment['acl_public'] or assessment['policy_public']
        assessment['is_public'] = is_public
        
        return is_public, assessment
        
    except Exception as e:
        error_msg = f"Error checking if bucket {bucket_name} is public: {str(e)}"
        logger.error(error_msg)
        assessment['errors'].append(error_msg)
        return False, assessment

def find_public_buckets(max_workers: int = 10) -> Dict[str, Any]:
    """Find all public S3 buckets in the account.

    Args:
        max_workers: Maximum number of threads to use

    Returns:
        Dictionary with assessment results
    """
    try:
        # Start timing
        start_time = datetime.now()
        
        # Get account-level public access block settings first
        account_public_access_block = get_account_public_access_block()
        
        # Check if account-level blocks prevent public access entirely
        if account_public_access_block:
            block_config = account_public_access_block.get('PublicAccessBlockConfiguration', {})
            all_blocked = (block_config.get('BlockPublicAcls', False) and 
                           block_config.get('IgnorePublicAcls', False) and
                           block_config.get('BlockPublicPolicy', False) and
                           block_config.get('RestrictPublicBuckets', False))
            
            if all_blocked:
                logger.info("Account-level public access blocks prevent any buckets from being public")
                # Just count buckets for reporting
                all_buckets = list_buckets()
                total_buckets = len(all_buckets)
                return {
                    'total_buckets': total_buckets,
                    'public_buckets_count': 0,
                    'public_buckets': [],
                    'account_public_access_block': account_public_access_block,
                    'bucket_assessments': {},
                    'scan_timestamp': datetime.now().isoformat(),
                    'scan_time_seconds': (datetime.now() - start_time).total_seconds()
                }
        
        # List all buckets
        all_buckets = list_buckets()
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
        
        # Use a larger chunk size to reduce overhead
        chunk_size = min(50, total_buckets)
        max_workers = min(max_workers, chunk_size)
        
        # Check each bucket for public access
        public_buckets = []
        bucket_assessments = {}
        
        # Process in batches to avoid overwhelming the API but with fewer chunks
        for i in range(0, total_buckets, chunk_size):
            bucket_chunk = all_buckets[i:i+chunk_size]
            logger.debug(f"Processing bucket chunk {i//chunk_size + 1} of {(total_buckets+chunk_size-1)//chunk_size}")
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Create a map of futures to buckets for this chunk
                futures = {
                    executor.submit(is_bucket_public, bucket['Name'], account_public_access_block): bucket
                    for bucket in bucket_chunk
                }
                
                # Process results as they complete
                for future in futures:
                    bucket = futures[future]
                    bucket_name = bucket['Name']
                    
                    try:
                        is_public, assessment = future.result()
                        bucket_assessments[bucket_name] = assessment
                        
                        if is_public:
                            public_buckets.append(bucket)
                    except Exception as e:
                        logger.error(f"Error checking if bucket {bucket_name} is public: {str(e)}")
                        bucket_assessments[bucket_name] = {
                            'bucket_name': bucket_name,
                            'is_public': False,
                            'errors': [str(e)]
                        }
        
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

def count_s3_buckets() -> Dict[str, Any]:
    """Count S3 buckets by region.

    Returns:
        Dictionary with counts by region and total
    """
    try:
        # List all buckets
        all_buckets = list_buckets()
        total_buckets = len(all_buckets)
        
        # Get the region for each bucket
        region_counts = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Map bucket names to their regions
            bucket_to_region = {
                bucket['Name']: executor.submit(get_bucket_location, bucket['Name'])
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