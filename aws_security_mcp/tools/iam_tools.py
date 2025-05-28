"""IAM tools module for AWS Security MCP.

This module provides tools to interact with AWS IAM service for
analyzing roles, users, access keys and policies.
"""

import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.services import iam as iam_service
from aws_security_mcp.formatters import iam_formatter
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
async def find_iam_role(
    role_name: str,
    format_response: bool = True,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Find and get detailed information about a specific IAM role.
    
    Retrieves comprehensive information about an IAM role, including:
    - Basic role information and metadata
    - Trust relationships (AssumeRolePolicyDocument)
    - Attached managed policies
    - Inline policies
    
    Args:
        role_name: Name of the IAM role to find
        format_response: Whether to format the response for security analysis
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing complete role details
    """
    try:
        # Get the role details from the service
        role_details = iam_service.get_role(role_name=role_name, session_context=session_context)
        
        # Format the response if requested
        if format_response:
            return iam_formatter.format_role_details(role_details)
        
        return role_details
    
    except Exception as e:
        logger.error(f"Error finding IAM role '{role_name}': {str(e)}")
        return {
            "error": str(e),
            "role_name": role_name,
            "status": "error"
        }


@register_tool()
async def find_iam_user(
    user_name: str,
    format_response: bool = True,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Find and get detailed information about a specific IAM user.
    
    Retrieves comprehensive information about an IAM user, including:
    - Basic user information and metadata
    - Console login details
    - Access keys
    - MFA devices
    - Group memberships
    - Attached managed policies
    - Inline policies
    
    Args:
        user_name: Name of the IAM user to find
        format_response: Whether to format the response for security analysis
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing complete user details
    """
    try:
        # Get the user details from the service
        user_details = iam_service.get_user(user_name=user_name, session_context=session_context)
        
        # Format the response if requested
        if format_response:
            return iam_formatter.format_user_details(user_details)
        
        return user_details
    
    except Exception as e:
        logger.error(f"Error finding IAM user '{user_name}': {str(e)}")
        return {
            "error": str(e),
            "user_name": user_name,
            "status": "error"
        }


@register_tool()
async def list_iam_roles(
    max_items: Optional[int] = None,
    marker: Optional[str] = None,
    path_prefix: Optional[str] = None,
    format_response: bool = True,
    names_only: bool = False,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List IAM roles in the AWS account with optional filtering.
    
    Args:
        max_items: Maximum number of roles to return
        marker: Pagination token for subsequent requests
        path_prefix: Filter roles by path prefix
        format_response: Whether to format the response for security analysis
        names_only: If True, returns only a list of role names
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing roles and pagination information
    """
    try:
        # Get the roles from the service
        roles_response = iam_service.list_roles(
            max_items=max_items,
            marker=marker,
            path_prefix=path_prefix,
            session_context=session_context
        )
        
        # Handle names_only case (most minimal response)
        if names_only:
            role_names = [role.get('RoleName') for role in roles_response.get('items', [])]
            return {
                'items': role_names,
                'count': len(role_names),
                'next_token': roles_response.get('next_token'),
                'is_truncated': roles_response.get('is_truncated')
            }
        
        # Format the response if requested
        if format_response:
            roles = roles_response.get('items', [])
            formatted_roles = [iam_formatter.format_role(role) for role in roles]
            
            return {
                'items': formatted_roles,
                'count': len(formatted_roles),
                'next_token': roles_response.get('next_token'),
                'is_truncated': roles_response.get('is_truncated')
            }
        
        return roles_response
    
    except Exception as e:
        logger.error(f"Error listing IAM roles: {str(e)}")
        return {
            "error": str(e),
            "status": "error",
            "items": [],
            "count": 0
        }


@register_tool()
async def list_iam_users(
    max_items: Optional[int] = None,
    marker: Optional[str] = None,
    path_prefix: Optional[str] = None,
    format_response: bool = True,
    names_only: bool = False,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List IAM users in the AWS account with optional filtering.
    
    Args:
        max_items: Maximum number of users to return
        marker: Pagination token for subsequent requests
        path_prefix: Filter users by path prefix
        format_response: Whether to format the response for security analysis
        names_only: If True, returns only a list of user names
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing users and pagination information
    """
    try:
        # Get the users from the service
        users_response = iam_service.list_users(
            max_items=max_items,
            marker=marker,
            path_prefix=path_prefix,
            session_context=session_context
        )
        
        # Handle names_only case (most minimal response)
        if names_only:
            user_names = [user.get('UserName') for user in users_response.get('items', [])]
            return {
                'items': user_names,
                'count': len(user_names),
                'next_token': users_response.get('next_token'),
                'is_truncated': users_response.get('is_truncated')
            }
            
        # Format the response if requested
        if format_response:
            users = users_response.get('items', [])
            formatted_users = [iam_formatter.format_user(user) for user in users]
            
            return {
                'items': formatted_users,
                'count': len(formatted_users),
                'next_token': users_response.get('next_token'),
                'is_truncated': users_response.get('is_truncated')
            }
        
        return users_response
    
    except Exception as e:
        logger.error(f"Error listing IAM users: {str(e)}")
        return {
            "error": str(e),
            "status": "error",
            "items": [],
            "count": 0
        }


@register_tool()
async def find_access_key(
    access_key_id: str,
    format_response: bool = True,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Find details about an IAM access key including the associated user.
    
    Args:
        access_key_id: The access key ID to search for
        format_response: Whether to format the response for security analysis
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing access key details and associated user information
    """
    try:
        # Get the access key details from the service
        access_key_response = iam_service.find_access_key(access_key_id=access_key_id, session_context=session_context)
        
        # Format the response if requested
        if format_response:
            access_key = access_key_response.get('AccessKey')
            user = access_key_response.get('User')
            last_used = access_key_response.get('LastUsed')
            
            if access_key and user:
                formatted_key = iam_formatter.format_access_key(access_key, last_used)
                formatted_user = iam_formatter.format_user(user)
                
                return {
                    'access_key': formatted_key,
                    'user': formatted_user,
                    'status': 'found'
                }
            else:
                return {
                    'access_key_id': access_key_id,
                    'status': 'not_found',
                    'error': access_key_response.get('Error', 'Access key not found')
                }
        
        return access_key_response
    
    except Exception as e:
        logger.error(f"Error finding access key '{access_key_id}': {str(e)}")
        return {
            "error": str(e),
            "access_key_id": access_key_id,
            "status": "error"
        }


@register_tool()
async def get_iam_policy_details(
    policy_arn: str,
    include_versions: bool = False,
    format_response: bool = True,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get detailed information about a specific IAM policy.
    
    Args:
        policy_arn: The ARN of the policy to retrieve
        include_versions: Whether to include all policy versions information
        format_response: Whether to format the response for security analysis
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing the policy details
    """
    try:
        # Get the policy details from the service
        policy_response = iam_service.get_policy(
            policy_arn=policy_arn,
            include_versions=include_versions,
            session_context=session_context
        )
        
        # Format the response if requested
        if format_response:
            policy = policy_response.get('Policy', {})
            formatted_policy = iam_formatter.format_policy(policy)
            
            return {
                'policy': formatted_policy,
                'policy_versions': policy_response.get('PolicyVersions', []),
                'status': 'success'
            }
        
        return policy_response
    
    except Exception as e:
        logger.error(f"Error getting IAM policy '{policy_arn}': {str(e)}")
        return {
            "error": str(e),
            "policy_arn": policy_arn,
            "status": "error"
        }


@register_tool()
async def get_iam_policy_batch(
    policy_arns: List[str],
    include_versions: bool = False,
    format_response: bool = True,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get details about multiple IAM policies in batch.
    
    Args:
        policy_arns: List of policy ARNs to retrieve
        include_versions: Whether to include all policy versions information
        format_response: Whether to format the response for security analysis
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing details for each requested policy
    """
    try:
        # Get the policies in batch from the service
        batch_response = iam_service.get_policy_batch(
            policy_arns=policy_arns,
            include_versions=include_versions,
            session_context=session_context
        )
        
        # Format the response if requested
        if format_response:
            formatted_policies = {}
            
            for arn, policy_data in batch_response.get('Policies', {}).items():
                policy = policy_data.get('Policy', {})
                formatted_policy = iam_formatter.format_policy(policy)
                
                formatted_policies[arn] = {
                    'policy': formatted_policy,
                    'policy_versions': policy_data.get('PolicyVersions', [])
                }
            
            return {
                'policies': formatted_policies,
                'errors': batch_response.get('Errors', {}),
                'success_count': batch_response.get('SuccessCount', 0),
                'error_count': batch_response.get('ErrorCount', 0),
                'total_count': batch_response.get('TotalCount', 0)
            }
        
        return batch_response
    
    except Exception as e:
        logger.error(f"Error getting IAM policies in batch: {str(e)}")
        return {
            "error": str(e),
            "status": "error",
            "policies": {},
            "success_count": 0,
            "error_count": len(policy_arns),
            "total_count": len(policy_arns)
        } 