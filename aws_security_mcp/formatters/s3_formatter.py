"""S3 formatter module for AWS Security MCP.

This module provides functions to format S3 bucket information
for better readability and security assessment.
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

def format_bucket_simple(bucket: Dict[str, Any]) -> Dict[str, Any]:
    """Format a bucket into a simplified representation.
    
    Args:
        bucket: Raw bucket data from AWS
    
    Returns:
        Dict containing simplified bucket representation
    """
    try:
        return {
            'name': bucket.get('Name'),
            'created': bucket.get('CreationDate', '').isoformat() if bucket.get('CreationDate') else None,
            'region': bucket.get('Region', 'unknown')
        }
    except Exception as e:
        logger.error(f"Error formatting simple bucket info: {str(e)}")
        return bucket  # Return original data if formatting fails

def format_acl_grants(acl: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format ACL grants into a more readable format.
    
    Args:
        acl: Raw ACL data from AWS
    
    Returns:
        List of formatted grant dictionaries
    """
    try:
        formatted_grants = []
        
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission')
            
            formatted_grant = {
                'permission': permission
            }
            
            # Handle different types of grantees
            if 'ID' in grantee:
                grantee_type = grantee.get('Type', '')
                
                if grantee_type == 'CanonicalUser':
                    formatted_grant['type'] = 'canonical_user'
                    formatted_grant['id'] = grantee.get('ID')
                    formatted_grant['display_name'] = grantee.get('DisplayName', 'Unknown')
                else:
                    formatted_grant['type'] = grantee_type.lower()
                    formatted_grant['id'] = grantee.get('ID')
            
            elif 'URI' in grantee:
                uri = grantee.get('URI', '')
                
                if 'AllUsers' in uri:
                    formatted_grant['type'] = 'public'
                    formatted_grant['group'] = 'all_users'
                elif 'AuthenticatedUsers' in uri:
                    formatted_grant['type'] = 'authenticated_users'
                    formatted_grant['group'] = 'authenticated_aws_users'
                elif 'LogDelivery' in uri:
                    formatted_grant['type'] = 'aws_service'
                    formatted_grant['group'] = 'log_delivery'
                else:
                    formatted_grant['type'] = 'unknown_group'
                    formatted_grant['uri'] = uri
            
            elif 'EmailAddress' in grantee:
                formatted_grant['type'] = 'email'
                formatted_grant['email'] = grantee.get('EmailAddress')
            
            else:
                formatted_grant['type'] = 'unknown'
            
            formatted_grants.append(formatted_grant)
        
        return formatted_grants
    
    except Exception as e:
        logger.error(f"Error formatting ACL grants: {str(e)}")
        return []  # Return empty list if formatting fails

def calculate_security_rating(bucket_details: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate a security rating for a bucket based on its configuration.
    
    Args:
        bucket_details: Comprehensive bucket details
    
    Returns:
        Dict containing security rating and breakdown
    """
    try:
        # Initialize score components
        score = 100
        issues = []
        
        # Check public access block settings
        account_block = bucket_details.get('account_public_access_block', {})
        bucket_block = bucket_details.get('PublicAccessBlock', {}).get('PublicAccessBlockConfiguration', {})
        
        # Check for missing public access block settings
        if not account_block and not bucket_block:
            score -= 20
            issues.append({
                'severity': 'high',
                'issue': 'No public access block settings configured at account or bucket level',
                'recommendation': 'Enable block public access at the account level or bucket level'
            })
        elif not bucket_block:
            score -= 10
            issues.append({
                'severity': 'medium',
                'issue': 'No bucket-level public access block settings',
                'recommendation': 'Enable block public access for this specific bucket'
            })
        
        # Check bucket ACL
        acl = bucket_details.get('ACL', {})
        has_public_acl = False
        
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            uri = grantee.get('URI', '')
            
            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                has_public_acl = True
                permission = grant.get('Permission', 'Unknown')
                score -= 20
                issues.append({
                    'severity': 'high',
                    'issue': f'Bucket ACL grants {permission} permission to {uri}',
                    'recommendation': 'Remove public ACL grants from the bucket'
                })
        
        # Check bucket policy
        policy = bucket_details.get('Policy', {})
        has_public_policy = False
        
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal')
            effect = statement.get('Effect')
            
            if effect == 'Allow' and (principal == '*' or principal == {'AWS': '*'}):
                has_public_policy = True
                score -= 20
                issues.append({
                    'severity': 'high',
                    'issue': 'Bucket policy allows public access',
                    'recommendation': 'Remove public access from bucket policy or add conditions'
                })
        
        # Check encryption
        encryption = bucket_details.get('Encryption')
        if not encryption:
            score -= 15
            issues.append({
                'severity': 'medium',
                'issue': 'Server-side encryption not enabled',
                'recommendation': 'Enable default encryption for the bucket'
            })
        
        # Check versioning
        versioning = bucket_details.get('Versioning', {})
        if versioning.get('Status') != 'Enabled':
            score -= 10
            issues.append({
                'severity': 'medium',
                'issue': 'Bucket versioning not enabled',
                'recommendation': 'Enable versioning to protect against accidental deletion'
            })
        
        # Check logging
        logging = bucket_details.get('Logging', {})
        if not logging.get('LoggingEnabled'):
            score -= 10
            issues.append({
                'severity': 'medium',
                'issue': 'Access logging not enabled',
                'recommendation': 'Enable access logging to track bucket activity'
            })
        
        # Calculate overall rating
        if score >= 90:
            rating = 'excellent'
        elif score >= 80:
            rating = 'good'
        elif score >= 60:
            rating = 'fair'
        elif score >= 40:
            rating = 'poor'
        else:
            rating = 'critical'
        
        # If public via ACL or policy, cannot be better than poor
        if has_public_acl or has_public_policy:
            if rating in ['excellent', 'good', 'fair']:
                rating = 'poor'
        
        return {
            'score': score,
            'rating': rating,
            'issues': issues
        }
    
    except Exception as e:
        logger.error(f"Error calculating security rating: {str(e)}")
        return {
            'score': 0,
            'rating': 'unknown',
            'issues': [{
                'severity': 'unknown',
                'issue': f'Error calculating security rating: {str(e)}',
                'recommendation': 'Check bucket configuration manually'
            }]
        }

def format_bucket_details(bucket_details: Dict[str, Any]) -> Dict[str, Any]:
    """Format detailed bucket information for better readability.
    
    Args:
        bucket_details: Raw bucket details from AWS
    
    Returns:
        Dict containing formatted bucket details
    """
    try:
        formatted = {
            'name': bucket_details.get('Name'),
            'region': bucket_details.get('Region', 'unknown')
        }
        
        # Format public access block
        public_access_block = bucket_details.get('PublicAccessBlock', {})
        if public_access_block:
            block_config = public_access_block.get('PublicAccessBlockConfiguration', {})
            formatted['public_access_block'] = {
                'block_public_acls': block_config.get('BlockPublicAcls', False),
                'ignore_public_acls': block_config.get('IgnorePublicAcls', False),
                'block_public_policy': block_config.get('BlockPublicPolicy', False),
                'restrict_public_buckets': block_config.get('RestrictPublicBuckets', False)
            }
        else:
            formatted['public_access_block'] = None
        
        # Format ACL
        acl = bucket_details.get('ACL', {})
        if acl:
            formatted['acl'] = {
                'owner': {
                    'id': acl.get('Owner', {}).get('ID'),
                    'display_name': acl.get('Owner', {}).get('DisplayName')
                },
                'grants': format_acl_grants(acl)
            }
        else:
            formatted['acl'] = None
        
        # Format policy
        policy = bucket_details.get('Policy')
        if policy:
            # Simplify policy representation if needed
            formatted['policy'] = {
                'has_policy': True,
                'statement_count': len(policy.get('Statement', [])),
                'version': policy.get('Version')
            }
        else:
            formatted['policy'] = {
                'has_policy': False
            }
        
        # Format encryption
        encryption = bucket_details.get('Encryption', {})
        if encryption:
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            encryption_methods = []
            
            for rule in rules:
                default_encryption = rule.get('ApplyServerSideEncryptionByDefault', {})
                if default_encryption:
                    encryption_methods.append({
                        'algorithm': default_encryption.get('SSEAlgorithm'),
                        'kms_key_id': default_encryption.get('KMSMasterKeyID')
                    })
            
            formatted['encryption'] = {
                'enabled': True,
                'methods': encryption_methods
            }
        else:
            formatted['encryption'] = {
                'enabled': False
            }
        
        # Format versioning
        versioning = bucket_details.get('Versioning', {})
        formatted['versioning'] = {
            'status': versioning.get('Status'),
            'mfa_delete': versioning.get('MFADelete')
        }
        
        # Format logging
        logging = bucket_details.get('Logging', {})
        logging_enabled = logging.get('LoggingEnabled', {})
        
        if logging_enabled:
            formatted['logging'] = {
                'enabled': True,
                'target_bucket': logging_enabled.get('TargetBucket'),
                'target_prefix': logging_enabled.get('TargetPrefix')
            }
        else:
            formatted['logging'] = {
                'enabled': False
            }
        
        # Add security rating
        formatted['security_rating'] = calculate_security_rating(bucket_details)
        
        return formatted
    
    except Exception as e:
        logger.error(f"Error formatting bucket details: {str(e)}")
        return bucket_details  # Return original data if formatting fails

def format_public_buckets_assessment(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Format public buckets assessment data for better readability.
    
    Args:
        assessment: Raw assessment data
    
    Returns:
        Dict containing formatted assessment data
    """
    try:
        # Extract key information
        total_buckets = assessment.get('total_buckets', 0)
        public_buckets_count = assessment.get('public_buckets_count', 0)
        public_buckets = assessment.get('public_buckets', [])
        account_block = assessment.get('account_public_access_block', {})
        bucket_assessments = assessment.get('bucket_assessments', {})
        
        # Format public buckets
        formatted_public_buckets = []
        for bucket in public_buckets:
            bucket_name = bucket.get('Name')
            bucket_assessment = bucket_assessments.get(bucket_name, {})
            
            formatted_bucket = {
                'name': bucket_name,
                'created': bucket.get('CreationDate', '').isoformat() if bucket.get('CreationDate') else None,
                'reasons': bucket_assessment.get('reasons', []),
                'details': bucket_assessment.get('details', {})
            }
            
            formatted_public_buckets.append(formatted_bucket)
        
        # Format account protection
        account_protection = None
        if account_block:
            block_config = account_block.get('PublicAccessBlockConfiguration', {})
            account_protection = {
                'block_public_acls': block_config.get('BlockPublicAcls', False),
                'ignore_public_acls': block_config.get('IgnorePublicAcls', False),
                'block_public_policy': block_config.get('BlockPublicPolicy', False),
                'restrict_public_buckets': block_config.get('RestrictPublicBuckets', False)
            }
        
        # Generate risk assessment
        risk_assessment = {}
        if public_buckets_count == 0:
            risk_assessment = {
                'level': 'low',
                'summary': 'No public S3 buckets detected in the account'
            }
        else:
            public_percentage = (public_buckets_count / total_buckets) * 100 if total_buckets > 0 else 0
            
            if public_percentage > 10 or public_buckets_count > 5:
                risk_level = 'critical'
                summary = f'High number of public buckets: {public_buckets_count} ({public_percentage:.1f}%)'
            elif public_buckets_count > 0:
                risk_level = 'high' 
                summary = f'Public buckets detected: {public_buckets_count} ({public_percentage:.1f}%)'
            
            risk_assessment = {
                'level': risk_level,
                'summary': summary
            }
        
        # Compile formatted assessment
        return {
            'summary': {
                'total_buckets': total_buckets,
                'public_buckets': public_buckets_count,
                'percentage_public': (public_buckets_count / total_buckets) * 100 if total_buckets > 0 else 0,
                'account_protected': account_protection is not None and all(account_protection.values()),
                'scan_timestamp': assessment.get('scan_timestamp')
            },
            'account_protection': account_protection,
            'public_buckets': formatted_public_buckets,
            'risk_assessment': risk_assessment
        }
    
    except Exception as e:
        logger.error(f"Error formatting public buckets assessment: {str(e)}")
        return assessment  # Return original data if formatting fails 