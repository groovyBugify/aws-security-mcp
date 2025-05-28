"""IAM service module for AWS Security MCP.

This module provides functions to interact with the AWS IAM service
for retrieving IAM roles, users, access keys and policies.
"""

import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_security_mcp.services.base import (
    get_client, 
    handle_aws_error, 
    format_pagination_response
)

# Configure logging
logger = logging.getLogger(__name__)

def list_roles(
    max_items: Optional[int] = None,
    marker: Optional[str] = None,
    path_prefix: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List IAM roles with optional filtering.
    
    Args:
        max_items: Maximum number of roles to return
        marker: Pagination token for subsequent requests
        path_prefix: Filter roles by path prefix
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing roles and pagination information
    """
    client = get_client('iam', session_context=session_context)
    
    try:
        # Prepare paginator configuration
        paginator = client.get_paginator('list_roles')
        pagination_config = {}
        
        if path_prefix:
            pagination_config['PathPrefix'] = path_prefix
        if marker:
            pagination_config['StartingToken'] = marker
        if max_items:
            # Set MaxItems to 500 max as requested
            pagination_config['MaxItems'] = min(max_items, 500)
        
        # Get only one page of results
        page_iterator = paginator.paginate(**pagination_config)
        response = None
        roles = []
        
        for page in page_iterator:
            response = page
            roles.extend(page.get('Roles', []))
            # We only want one page for proper pagination
            break
            
        # Get simplified role data
        simplified_roles = []
        for role in roles:
            simplified_roles.append({
                'RoleName': role.get('RoleName'),
                'RoleId': role.get('RoleId'),
                'Arn': role.get('Arn'),
                'Path': role.get('Path'),
                'CreateDate': role.get('CreateDate')
            })
            
        # Extract pagination information
        is_truncated = response.get('IsTruncated', False)
        next_marker = response.get('Marker') if is_truncated else None
            
        return format_pagination_response(
            items=simplified_roles,
            next_token=next_marker,
            is_truncated=is_truncated
        )
    
    except ClientError as e:
        logger.error(f"Error listing IAM roles: {str(e)}")
        raise

def get_role(role_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get detailed information about a specific IAM role.
    
    Args:
        role_name: The name of the IAM role
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing the role details
    """
    client = get_client('iam', session_context=session_context)
    
    try:
        # Get the role information
        role_response = client.get_role(RoleName=role_name)
        role_data = role_response.get('Role', {})
        
        # Get attached managed policies
        attached_policies = []
        paginator = client.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            attached_policies.extend(page.get('AttachedPolicies', []))
        
        # Get inline policies
        inline_policy_names = []
        paginator = client.get_paginator('list_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            inline_policy_names.extend(page.get('PolicyNames', []))
        
        # Get inline policy documents
        inline_policies = {}
        for policy_name in inline_policy_names:
            policy_response = client.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            inline_policies[policy_name] = policy_response.get('PolicyDocument', {})
        
        # Combine all data
        role_details = {
            "Role": role_data,
            "AttachedManagedPolicies": attached_policies,
            "InlinePolicyNames": inline_policy_names,
            "InlinePolicies": inline_policies
        }
        
        return role_details
    
    except ClientError as e:
        logger.error(f"Error getting IAM role '{role_name}': {str(e)}")
        raise

def list_users(
    max_items: Optional[int] = None,
    marker: Optional[str] = None,
    path_prefix: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List IAM users with optional filtering.
    
    Args:
        max_items: Maximum number of users to return
        marker: Pagination token for subsequent requests
        path_prefix: Filter users by path prefix
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing users and pagination information
    """
    client = get_client('iam', session_context=session_context)
    
    try:
        # Prepare paginator configuration
        paginator = client.get_paginator('list_users')
        pagination_config = {}
        
        if path_prefix:
            pagination_config['PathPrefix'] = path_prefix
        if marker:
            pagination_config['StartingToken'] = marker
        if max_items:
            # Set MaxItems to 500 max as requested
            pagination_config['MaxItems'] = min(max_items, 500)
        
        # Get only one page of results
        page_iterator = paginator.paginate(**pagination_config)
        response = None
        users = []
        
        for page in page_iterator:
            response = page
            users.extend(page.get('Users', []))
            # We only want one page for proper pagination
            break
            
        # Get simplified user data
        simplified_users = []
        for user in users:
            simplified_users.append({
                'UserName': user.get('UserName'),
                'UserId': user.get('UserId'),
                'Arn': user.get('Arn'),
                'Path': user.get('Path'),
                'CreateDate': user.get('CreateDate')
            })
            
        # Extract pagination information
        is_truncated = response.get('IsTruncated', False)
        next_marker = response.get('Marker') if is_truncated else None
            
        return format_pagination_response(
            items=simplified_users,
            next_token=next_marker,
            is_truncated=is_truncated
        )
    
    except ClientError as e:
        logger.error(f"Error listing IAM users: {str(e)}")
        raise

def get_user(user_name: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get detailed information about a specific IAM user.
    
    Args:
        user_name: The name of the IAM user
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing the user details
    """
    client = get_client('iam', session_context=session_context)
    
    try:
        # Get the user information
        user_response = client.get_user(UserName=user_name)
        user_data = user_response.get('User', {})
        
        # Get login profile (console access information)
        login_profile = None
        try:
            login_profile_response = client.get_login_profile(UserName=user_name)
            login_profile = login_profile_response.get('LoginProfile', {})
        except ClientError as e:
            # It's normal for users to not have console access
            if e.response['Error']['Code'] != 'NoSuchEntity':
                raise
        
        # Get access keys
        access_keys = []
        paginator = client.get_paginator('list_access_keys')
        for page in paginator.paginate(UserName=user_name):
            access_keys.extend(page.get('AccessKeyMetadata', []))
        
        # Get attached managed policies
        attached_policies = []
        paginator = client.get_paginator('list_attached_user_policies')
        for page in paginator.paginate(UserName=user_name):
            attached_policies.extend(page.get('AttachedPolicies', []))
        
        # Get inline policies
        inline_policy_names = []
        paginator = client.get_paginator('list_user_policies')
        for page in paginator.paginate(UserName=user_name):
            inline_policy_names.extend(page.get('PolicyNames', []))
        
        # Get inline policy documents
        inline_policies = {}
        for policy_name in inline_policy_names:
            policy_response = client.get_user_policy(
                UserName=user_name,
                PolicyName=policy_name
            )
            inline_policies[policy_name] = policy_response.get('PolicyDocument', {})
        
        # Get MFA devices
        mfa_devices = []
        paginator = client.get_paginator('list_mfa_devices')
        for page in paginator.paginate(UserName=user_name):
            mfa_devices.extend(page.get('MFADevices', []))
        
        # Get groups
        groups = []
        paginator = client.get_paginator('list_groups_for_user')
        for page in paginator.paginate(UserName=user_name):
            groups.extend(page.get('Groups', []))
        
        # Combine all data
        user_details = {
            "User": user_data,
            "LoginProfile": login_profile,
            "AccessKeys": access_keys,
            "MFADevices": mfa_devices,
            "Groups": groups,
            "AttachedManagedPolicies": attached_policies,
            "InlinePolicyNames": inline_policy_names,
            "InlinePolicies": inline_policies
        }
        
        return user_details
    
    except ClientError as e:
        logger.error(f"Error getting IAM user '{user_name}': {str(e)}")
        raise

def get_policy(
    policy_arn: str, 
    include_versions: bool = False,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get information about an IAM policy.
    
    Args:
        policy_arn: The ARN of the policy
        include_versions: Whether to include policy versions information
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing the policy details
    """
    client = get_client('iam', session_context=session_context)
    
    try:
        # Get the policy information
        policy_response = client.get_policy(PolicyArn=policy_arn)
        policy_data = policy_response.get('Policy', {})
        
        # Get the default (active) policy version document
        default_version_id = policy_data.get('DefaultVersionId')
        if default_version_id:
            version_response = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            policy_document = version_response.get('PolicyVersion', {}).get('Document', {})
            policy_data['PolicyDocument'] = policy_document
        
        # Get all policy versions if requested
        policy_versions = []
        if include_versions:
            paginator = client.get_paginator('list_policy_versions')
            for page in paginator.paginate(PolicyArn=policy_arn):
                policy_versions.extend(page.get('Versions', []))
                
            # Sort by CreateDate (newest first)
            policy_versions.sort(
                key=lambda x: x.get('CreateDate', ''), 
                reverse=True
            )
        
        # Combine all data
        policy_details = {
            "Policy": policy_data,
            "PolicyVersions": policy_versions if include_versions else []
        }
        
        return policy_details
    
    except ClientError as e:
        logger.error(f"Error getting IAM policy '{policy_arn}': {str(e)}")
        raise

def get_policy_batch(
    policy_arns: List[str], 
    include_versions: bool = False,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get information about multiple IAM policies in batch.
    
    Args:
        policy_arns: List of policy ARNs
        include_versions: Whether to include policy versions information
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict mapping policy ARNs to their details
    """
    results = {}
    errors = {}
    
    for policy_arn in policy_arns:
        try:
            policy_details = get_policy(
                policy_arn=policy_arn,
                include_versions=include_versions,
                session_context=session_context
            )
            results[policy_arn] = policy_details
        except Exception as e:
            errors[policy_arn] = str(e)
    
    return {
        "Policies": results,
        "Errors": errors,
        "SuccessCount": len(results),
        "ErrorCount": len(errors),
        "TotalCount": len(policy_arns)
    }

def find_access_key(access_key_id: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Find the IAM user associated with an access key and get key details.
    
    Args:
        access_key_id: The access key ID
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing the access key details and associated user
    """
    client = get_client('iam', session_context=session_context)
    
    try:
        # List all users
        paginator = client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get('Users', []):
                user_name = user.get('UserName')
                
                # List access keys for this user
                access_key_paginator = client.get_paginator('list_access_keys')
                for key_page in access_key_paginator.paginate(UserName=user_name):
                    for key in key_page.get('AccessKeyMetadata', []):
                        if key.get('AccessKeyId') == access_key_id:
                            # Get the last used info for this key
                            last_used_response = client.get_access_key_last_used(
                                AccessKeyId=access_key_id
                            )
                            
                            return {
                                "AccessKey": key,
                                "User": user,
                                "LastUsed": last_used_response.get('AccessKeyLastUsed', {})
                            }
        
        return {
            "AccessKey": None,
            "User": None,
            "LastUsed": None,
            "Error": f"Access key '{access_key_id}' not found in any user"
        }
    
    except ClientError as e:
        logger.error(f"Error finding access key '{access_key_id}': {str(e)}")
        raise 