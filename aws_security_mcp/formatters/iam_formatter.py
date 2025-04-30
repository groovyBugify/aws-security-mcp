"""IAM formatter module for AWS Security MCP.

This module formats IAM API responses to extract and standardize
security-related metadata for roles, users, policies and access keys.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)

def format_role(role: Dict[str, Any]) -> Dict[str, Any]:
    """Format IAM role data to extract security-relevant information.
    
    Args:
        role: Raw IAM role data from AWS API
        
    Returns:
        Dict with formatted role data
    """
    if not role:
        return {}
    
    role_name = role.get('RoleName', 'unknown')
    
    # Format the creation date
    create_date = role.get('CreateDate')
    if create_date and isinstance(create_date, datetime):
        create_date_str = create_date.isoformat()
    else:
        create_date_str = str(create_date) if create_date else None
    
    # Calculate role age in days if create date is available
    role_age_days = None
    if create_date and isinstance(create_date, datetime):
        role_age_days = (datetime.now().replace(tzinfo=None) - create_date.replace(tzinfo=None)).days
    
    # Extract trust policy (assume role policy)
    trust_policy = role.get('AssumeRolePolicyDocument', {})
    
    # Check for service roles and extract service principals
    service_principals = []
    if trust_policy and 'Statement' in trust_policy:
        statements = trust_policy['Statement']
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            principal = statement.get('Principal', {})
            if isinstance(principal, dict) and 'Service' in principal:
                services = principal['Service']
                if isinstance(services, list):
                    service_principals.extend(services)
                else:
                    service_principals.append(services)
    
    # Format max session duration
    max_session_duration = role.get('MaxSessionDuration', 3600)
    
    # Determine if this is a service role
    is_service_role = len(service_principals) > 0
    
    # Construct formatted response
    formatted_role = {
        'role_name': role_name,
        'role_id': role.get('RoleId'),
        'arn': role.get('Arn'),
        'path': role.get('Path'),
        'create_date': create_date_str,
        'role_age_days': role_age_days,
        'description': role.get('Description'),
        'max_session_duration': max_session_duration,
        'permissions_boundary': role.get('PermissionsBoundary'),
        'tags': role.get('Tags', []),
        'is_service_role': is_service_role,
        'service_principals': service_principals,
        'trust_policy': trust_policy
    }
    
    return formatted_role

def format_user(user: Dict[str, Any]) -> Dict[str, Any]:
    """Format IAM user data to extract security-relevant information.
    
    Args:
        user: Raw IAM user data from AWS API
        
    Returns:
        Dict with formatted user data
    """
    if not user:
        return {}
    
    user_name = user.get('UserName', 'unknown')
    
    # Format the creation date
    create_date = user.get('CreateDate')
    if create_date and isinstance(create_date, datetime):
        create_date_str = create_date.isoformat()
    else:
        create_date_str = str(create_date) if create_date else None
    
    # Calculate user age in days if create date is available
    user_age_days = None
    if create_date and isinstance(create_date, datetime):
        user_age_days = (datetime.now().replace(tzinfo=None) - create_date.replace(tzinfo=None)).days
    
    # Format password last used
    password_last_used = user.get('PasswordLastUsed')
    if password_last_used and isinstance(password_last_used, datetime):
        password_last_used_str = password_last_used.isoformat()
        
        # Calculate days since password was last used
        days_since_password_used = (datetime.now().replace(tzinfo=None) - password_last_used.replace(tzinfo=None)).days
    else:
        password_last_used_str = str(password_last_used) if password_last_used else None
        days_since_password_used = None
    
    # Construct formatted response
    formatted_user = {
        'user_name': user_name,
        'user_id': user.get('UserId'),
        'arn': user.get('Arn'),
        'path': user.get('Path'),
        'create_date': create_date_str,
        'user_age_days': user_age_days,
        'password_last_used': password_last_used_str,
        'days_since_password_used': days_since_password_used,
        'permissions_boundary': user.get('PermissionsBoundary'),
        'tags': user.get('Tags', [])
    }
    
    return formatted_user

def format_access_key(access_key: Dict[str, Any], last_used: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Format IAM access key data to extract security-relevant information.
    
    Args:
        access_key: Raw access key data from AWS API
        last_used: Information about when and where the key was last used
        
    Returns:
        Dict with formatted access key data
    """
    if not access_key:
        return {}
    
    # Format create date
    create_date = access_key.get('CreateDate')
    if create_date and isinstance(create_date, datetime):
        create_date_str = create_date.isoformat()
        
        # Calculate key age in days
        key_age_days = (datetime.now().replace(tzinfo=None) - create_date.replace(tzinfo=None)).days
    else:
        create_date_str = str(create_date) if create_date else None
        key_age_days = None
    
    # Format last used info
    last_used_date = None
    last_used_service = None
    last_used_region = None
    days_since_last_used = None
    
    if last_used:
        last_used_date = last_used.get('LastUsedDate')
        if last_used_date and isinstance(last_used_date, datetime):
            # Calculate days since key was last used
            days_since_last_used = (datetime.now().replace(tzinfo=None) - last_used_date.replace(tzinfo=None)).days
            last_used_date = last_used_date.isoformat()
        else:
            last_used_date = str(last_used_date) if last_used_date else None
        
        last_used_service = last_used.get('ServiceName')
        last_used_region = last_used.get('Region')
    
    # Construct formatted response
    formatted_key = {
        'access_key_id': access_key.get('AccessKeyId'),
        'user_name': access_key.get('UserName'),
        'status': access_key.get('Status'),
        'create_date': create_date_str,
        'key_age_days': key_age_days,
        'last_used_date': last_used_date,
        'days_since_last_used': days_since_last_used,
        'last_used_service': last_used_service,
        'last_used_region': last_used_region
    }
    
    return formatted_key

def format_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Format IAM policy data to extract security-relevant information.
    
    Args:
        policy: Raw IAM policy data from AWS API
        
    Returns:
        Dict with formatted policy data
    """
    if not policy:
        return {}
    
    # Format create date
    create_date = policy.get('CreateDate')
    if create_date and isinstance(create_date, datetime):
        create_date_str = create_date.isoformat()
        
        # Calculate policy age in days
        policy_age_days = (datetime.now().replace(tzinfo=None) - create_date.replace(tzinfo=None)).days
    else:
        create_date_str = str(create_date) if create_date else None
        policy_age_days = None
    
    # Format update date
    update_date = policy.get('UpdateDate')
    if update_date and isinstance(update_date, datetime):
        update_date_str = update_date.isoformat()
    else:
        update_date_str = str(update_date) if update_date else None
    
    # Extract policy document for security analysis
    policy_document = policy.get('PolicyDocument', {})
    
    # Identify if this is an AWS managed policy
    is_aws_managed = policy.get('Arn', '').startswith('arn:aws:iam::aws:')
    
    # Construct formatted response
    formatted_policy = {
        'policy_name': policy.get('PolicyName'),
        'policy_id': policy.get('PolicyId'),
        'arn': policy.get('Arn'),
        'path': policy.get('Path'),
        'default_version_id': policy.get('DefaultVersionId'),
        'attachment_count': policy.get('AttachmentCount'),
        'is_attachable': policy.get('IsAttachable'),
        'permissions_boundary_usage_count': policy.get('PermissionsBoundaryUsageCount'),
        'is_aws_managed': is_aws_managed,
        'create_date': create_date_str,
        'update_date': update_date_str,
        'policy_age_days': policy_age_days,
        'policy_document': policy_document,
        'tags': policy.get('Tags', [])
    }
    
    return formatted_policy

def format_role_details(role_details: Dict[str, Any]) -> Dict[str, Any]:
    """Format complete IAM role details including policies.
    
    Args:
        role_details: Complete role details from IAM service
        
    Returns:
        Dict with formatted role details
    """
    if not role_details:
        return {}
    
    # Format the basic role information
    role_data = role_details.get('Role', {})
    formatted_role = format_role(role_data)
    
    # Format the attached managed policies
    attached_policies = role_details.get('AttachedManagedPolicies', [])
    formatted_attached_policies = []
    
    for policy in attached_policies:
        formatted_attached_policies.append({
            'policy_name': policy.get('PolicyName'),
            'policy_arn': policy.get('PolicyArn')
        })
    
    # Format inline policies
    inline_policies = role_details.get('InlinePolicies', {})
    formatted_inline_policies = {}
    
    for policy_name, policy_doc in inline_policies.items():
        formatted_inline_policies[policy_name] = policy_doc
    
    # Combine into complete response
    formatted_role_details = {
        'role': formatted_role,
        'attached_managed_policies': formatted_attached_policies,
        'inline_policies': formatted_inline_policies
    }
    
    return formatted_role_details

def format_user_details(user_details: Dict[str, Any]) -> Dict[str, Any]:
    """Format complete IAM user details including access keys, policies, etc.
    
    Args:
        user_details: Complete user details from IAM service
        
    Returns:
        Dict with formatted user details
    """
    if not user_details:
        return {}
    
    # Format the basic user information
    user_data = user_details.get('User', {})
    formatted_user = format_user(user_data)
    
    # Format login profile (console access)
    login_profile = user_details.get('LoginProfile')
    has_console_access = login_profile is not None
    
    # Format access keys
    access_keys = user_details.get('AccessKeys', [])
    formatted_access_keys = []
    
    for key in access_keys:
        formatted_access_keys.append({
            'access_key_id': key.get('AccessKeyId'),
            'status': key.get('Status'),
            'create_date': key.get('CreateDate').isoformat() if isinstance(key.get('CreateDate'), datetime) else str(key.get('CreateDate')) if key.get('CreateDate') else None
        })
    
    # Format MFA devices
    mfa_devices = user_details.get('MFADevices', [])
    formatted_mfa_devices = []
    
    for device in mfa_devices:
        formatted_mfa_devices.append({
            'serial_number': device.get('SerialNumber'),
            'enable_date': device.get('EnableDate').isoformat() if isinstance(device.get('EnableDate'), datetime) else str(device.get('EnableDate')) if device.get('EnableDate') else None
        })
    
    # Format groups
    groups = user_details.get('Groups', [])
    formatted_groups = []
    
    for group in groups:
        formatted_groups.append({
            'group_name': group.get('GroupName'),
            'group_id': group.get('GroupId'),
            'arn': group.get('Arn'),
            'create_date': group.get('CreateDate').isoformat() if isinstance(group.get('CreateDate'), datetime) else str(group.get('CreateDate')) if group.get('CreateDate') else None
        })
    
    # Format attached managed policies
    attached_policies = user_details.get('AttachedManagedPolicies', [])
    formatted_attached_policies = []
    
    for policy in attached_policies:
        formatted_attached_policies.append({
            'policy_name': policy.get('PolicyName'),
            'policy_arn': policy.get('PolicyArn')
        })
    
    # Format inline policies
    inline_policies = user_details.get('InlinePolicies', {})
    formatted_inline_policies = {}
    
    for policy_name, policy_doc in inline_policies.items():
        formatted_inline_policies[policy_name] = policy_doc
    
    # Combine into complete response
    formatted_user_details = {
        'user': formatted_user,
        'has_console_access': has_console_access,
        'password_last_reset': login_profile.get('CreateDate').isoformat() if login_profile and isinstance(login_profile.get('CreateDate'), datetime) else str(login_profile.get('CreateDate')) if login_profile and login_profile.get('CreateDate') else None,
        'password_reset_required': login_profile.get('PasswordResetRequired') if login_profile else False,
        'access_keys': formatted_access_keys,
        'access_key_count': len(formatted_access_keys),
        'active_access_key_count': sum(1 for key in formatted_access_keys if key.get('status') == 'Active'),
        'mfa_devices': formatted_mfa_devices,
        'mfa_enabled': len(formatted_mfa_devices) > 0,
        'groups': formatted_groups,
        'group_count': len(formatted_groups),
        'attached_managed_policies': formatted_attached_policies,
        'inline_policies': formatted_inline_policies,
        'total_policy_count': len(formatted_attached_policies) + len(formatted_inline_policies)
    }
    
    return formatted_user_details 