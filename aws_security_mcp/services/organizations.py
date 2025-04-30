"""Organizations service module for AWS Security MCP.

This module provides functions for interacting with AWS Organizations.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import asyncio

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from aws_security_mcp.services.base import get_client, handle_aws_error, format_pagination_response

# Configure logging
logger = logging.getLogger(__name__)

# Helper function for running sync code in an executor
async def run_in_executor(func, *args, **kwargs) -> Any:
    """Run a synchronous function in an executor to make it awaitable.
    
    Args:
        func: The synchronous function to call
        *args: Positional arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function
        
    Returns:
        The result of the function call
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: func(*args, **kwargs)
    )

def get_organization() -> Dict[str, Any]:
    """Get information about the AWS Organization.
    
    Returns:
        Dictionary containing information about the AWS Organization
    """
    try:
        # Organizations API must use us-east-1 as per AWS documentation
        client = get_client('organizations', region='us-east-1')
        response = client.describe_organization()
        return response
    except ClientError as e:
        logger.error(f"Error getting organization info: {str(e)}")
        return {}

def list_accounts() -> List[Dict[str, Any]]:
    """List all accounts in the AWS Organization.
    
    Returns:
        List of accounts in the organization
    """
    try:
        client = get_client('organizations', region='us-east-1')
        paginator = client.get_paginator('list_accounts')
        
        all_accounts = []
        for page in paginator.paginate():
            if 'Accounts' in page:
                all_accounts.extend(page['Accounts'])
        
        return all_accounts
    except ClientError as e:
        logger.error(f"Error listing organization accounts: {str(e)}")
        return []

def get_account_details(account_id: str) -> Dict[str, Any]:
    """Get details for a specific AWS account.
    
    Args:
        account_id: AWS account ID
    
    Returns:
        Dictionary with account details
    """
    try:
        client = get_client('organizations', region='us-east-1')
        response = client.describe_account(AccountId=account_id)
        return response.get('Account', {})
    except ClientError as e:
        logger.error(f"Error getting account details for {account_id}: {str(e)}")
        return {}

def list_policies(filter_type: str = 'SERVICE_CONTROL_POLICY') -> List[Dict[str, Any]]:
    """List all policies of a specific type in the AWS Organization.
    
    Args:
        filter_type: Type of policy to list (default: SERVICE_CONTROL_POLICY)
        
    Returns:
        List of policies
    """
    try:
        client = get_client('organizations', region='us-east-1')
        paginator = client.get_paginator('list_policies')
        
        all_policies = []
        for page in paginator.paginate(Filter=filter_type):
            if 'Policies' in page:
                all_policies.extend(page['Policies'])
        
        return all_policies
    except ClientError as e:
        logger.error(f"Error listing policies of type {filter_type}: {str(e)}")
        return []

def get_policy(policy_id: str) -> Dict[str, Any]:
    """Get details of a specific policy.
    
    Args:
        policy_id: ID of the policy
        
    Returns:
        Dictionary with policy details
    """
    try:
        client = get_client('organizations', region='us-east-1')
        response = client.describe_policy(PolicyId=policy_id)
        return response.get('Policy', {})
    except ClientError as e:
        logger.error(f"Error getting policy details for {policy_id}: {str(e)}")
        return {}

def list_targets_for_policy(policy_id: str) -> List[Dict[str, Any]]:
    """List all targets (accounts, OUs) that a policy is attached to.
    
    Args:
        policy_id: ID of the policy
        
    Returns:
        List of targets
    """
    try:
        client = get_client('organizations', region='us-east-1')
        paginator = client.get_paginator('list_targets_for_policy')
        
        all_targets = []
        for page in paginator.paginate(PolicyId=policy_id):
            if 'Targets' in page:
                all_targets.extend(page['Targets'])
        
        return all_targets
    except ClientError as e:
        logger.error(f"Error listing targets for policy {policy_id}: {str(e)}")
        return []

def list_policies_for_target(target_id: str, filter_type: str = 'SERVICE_CONTROL_POLICY') -> List[Dict[str, Any]]:
    """List all policies attached to a specific target (account, OU).
    
    Args:
        target_id: ID of the target (account ID or OU ID)
        filter_type: Type of policy to list (default: SERVICE_CONTROL_POLICY)
        
    Returns:
        List of policies
    """
    try:
        client = get_client('organizations', region='us-east-1')
        paginator = client.get_paginator('list_policies_for_target')
        
        all_policies = []
        for page in paginator.paginate(TargetId=target_id, Filter=filter_type):
            if 'Policies' in page:
                all_policies.extend(page['Policies'])
        
        return all_policies
    except ClientError as e:
        logger.error(f"Error listing policies for target {target_id}: {str(e)}")
        return []

def list_roots() -> List[Dict[str, Any]]:
    """List all roots in the AWS Organization.
    
    Returns:
        List of roots
    """
    try:
        client = get_client('organizations', region='us-east-1')
        paginator = client.get_paginator('list_roots')
        
        all_roots = []
        for page in paginator.paginate():
            if 'Roots' in page:
                all_roots.extend(page['Roots'])
        
        return all_roots
    except ClientError as e:
        logger.error(f"Error listing organization roots: {str(e)}")
        return []

def list_organizational_units_for_parent(parent_id: str) -> List[Dict[str, Any]]:
    """List all OUs under a specific parent.
    
    Args:
        parent_id: ID of the parent (root ID or OU ID)
        
    Returns:
        List of organizational units
    """
    try:
        client = get_client('organizations', region='us-east-1')
        paginator = client.get_paginator('list_organizational_units_for_parent')
        
        all_ous = []
        for page in paginator.paginate(ParentId=parent_id):
            if 'OrganizationalUnits' in page:
                all_ous.extend(page['OrganizationalUnits'])
        
        return all_ous
    except ClientError as e:
        logger.error(f"Error listing OUs for parent {parent_id}: {str(e)}")
        return []

def list_accounts_for_parent(parent_id: str) -> List[Dict[str, Any]]:
    """List all accounts under a specific parent.
    
    Args:
        parent_id: ID of the parent (root ID or OU ID)
        
    Returns:
        List of accounts
    """
    try:
        client = get_client('organizations', region='us-east-1')
        paginator = client.get_paginator('list_accounts_for_parent')
        
        all_accounts = []
        for page in paginator.paginate(ParentId=parent_id):
            if 'Accounts' in page:
                all_accounts.extend(page['Accounts'])
        
        return all_accounts
    except ClientError as e:
        logger.error(f"Error listing accounts for parent {parent_id}: {str(e)}")
        return []

def get_effective_policies_for_account(account_id: str) -> Dict[str, List[Dict[str, Any]]]:
    """Get all effective policies for a specific account.
    
    Args:
        account_id: AWS account ID
        
    Returns:
        Dictionary mapping policy types to lists of policies
    """
    policy_types = ['SERVICE_CONTROL_POLICY', 'TAG_POLICY', 'BACKUP_POLICY', 'AISERVICES_OPT_OUT_POLICY']
    effective_policies = {}
    
    for policy_type in policy_types:
        try:
            client = get_client('organizations', region='us-east-1')
            response = client.describe_effective_policy(
                TargetId=account_id,
                PolicyType=policy_type
            )
            
            if 'EffectivePolicy' in response:
                if policy_type not in effective_policies:
                    effective_policies[policy_type] = []
                effective_policies[policy_type].append(response['EffectivePolicy'])
        except ClientError as e:
            # Some policy types might not be enabled, which is expected
            error_code = e.response.get('Error', {}).get('Code')
            if error_code == 'PolicyTypeNotEnabledException':
                logger.info(f"Policy type {policy_type} not enabled for account {account_id}")
            else:
                logger.error(f"Error getting effective {policy_type} for account {account_id}: {str(e)}")
    
    return effective_policies

def get_organization_hierarchy() -> Dict[str, Any]:
    """Get the complete AWS Organization hierarchy.
    
    Returns:
        Dictionary representing the organization structure
    """
    try:
        # Get the root of the organization
        roots = list_roots()
        if not roots:
            logger.error("No roots found in the organization")
            return {}
        
        root = roots[0]  # There's typically only one root
        hierarchy = {
            'Id': root['Id'],
            'Name': root['Name'],
            'Type': 'ROOT',
            'OrganizationalUnits': [],
            'Accounts': []
        }
        
        # Get OUs under the root
        ous = list_organizational_units_for_parent(root['Id'])
        for ou in ous:
            ou_hierarchy = build_ou_hierarchy(ou['Id'], ou['Name'])
            hierarchy['OrganizationalUnits'].append(ou_hierarchy)
        
        # Get accounts directly under the root
        accounts = list_accounts_for_parent(root['Id'])
        hierarchy['Accounts'] = accounts
        
        return hierarchy
    except Exception as e:
        logger.error(f"Error building organization hierarchy: {str(e)}")
        return {}

def build_ou_hierarchy(ou_id: str, ou_name: str) -> Dict[str, Any]:
    """Recursively build the hierarchy for an organizational unit.
    
    Args:
        ou_id: ID of the organizational unit
        ou_name: Name of the organizational unit
        
    Returns:
        Dictionary representing the OU hierarchy
    """
    hierarchy = {
        'Id': ou_id,
        'Name': ou_name,
        'Type': 'ORGANIZATIONAL_UNIT',
        'OrganizationalUnits': [],
        'Accounts': []
    }
    
    # Get child OUs
    child_ous = list_organizational_units_for_parent(ou_id)
    for child_ou in child_ous:
        child_hierarchy = build_ou_hierarchy(child_ou['Id'], child_ou['Name'])
        hierarchy['OrganizationalUnits'].append(child_hierarchy)
    
    # Get accounts in this OU
    accounts = list_accounts_for_parent(ou_id)
    hierarchy['Accounts'] = accounts
    
    return hierarchy 