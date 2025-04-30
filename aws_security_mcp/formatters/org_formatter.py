"""Organizations formatter module for AWS Security MCP.

This module provides functions to format AWS Organizations information
for better readability and security assessment.
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

def format_organization_simple(org_info: Dict[str, Any]) -> Dict[str, Any]:
    """Format organization information into a simplified representation.
    
    Args:
        org_info: Raw organization data from AWS
    
    Returns:
        Dict containing simplified organization representation
    """
    try:
        return {
            'id': org_info.get('Organization', {}).get('Id'),
            'arn': org_info.get('Organization', {}).get('Arn'),
            'feature_set': org_info.get('Organization', {}).get('FeatureSet'),
            'master_account_id': org_info.get('Organization', {}).get('MasterAccountId'),
            'master_account_email': org_info.get('Organization', {}).get('MasterAccountEmail'),
            'available_policy_types': [
                {
                    'type': policy_type.get('Type'),
                    'status': policy_type.get('Status')
                }
                for policy_type in org_info.get('Organization', {}).get('AvailablePolicyTypes', [])
            ]
        }
    except Exception as e:
        logger.error(f"Error formatting organization info: {str(e)}")
        return org_info  # Return original data if formatting fails

def format_account_simple(account: Dict[str, Any]) -> Dict[str, Any]:
    """Format an account into a simplified representation.
    
    Args:
        account: Raw account data from AWS
    
    Returns:
        Dict containing simplified account representation
    """
    try:
        return {
            'id': account.get('Id'),
            'arn': account.get('Arn'),
            'name': account.get('Name'),
            'email': account.get('Email'),
            'status': account.get('Status'),
            'joined_method': account.get('JoinedMethod'),
            'joined_timestamp': account.get('JoinedTimestamp').isoformat() if account.get('JoinedTimestamp') else None
        }
    except Exception as e:
        logger.error(f"Error formatting account info: {str(e)}")
        return account  # Return original data if formatting fails

def format_policy_simple(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Format a policy into a simplified representation.
    
    Args:
        policy: Raw policy data from AWS
    
    Returns:
        Dict containing simplified policy representation
    """
    try:
        return {
            'id': policy.get('Id'),
            'arn': policy.get('Arn'),
            'name': policy.get('Name'),
            'description': policy.get('Description'),
            'type': policy.get('Type'),
            'aws_managed': policy.get('AwsManaged', False)
        }
    except Exception as e:
        logger.error(f"Error formatting policy info: {str(e)}")
        return policy  # Return original data if formatting fails

def format_policy_detail(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Format detailed policy information.
    
    Args:
        policy: Raw policy data from AWS
    
    Returns:
        Dict containing formatted policy details
    """
    try:
        formatted = format_policy_simple(policy)
        
        # Add content if available
        content = policy.get('Content')
        if content:
            try:
                # Content is stored as a JSON string
                import json
                formatted['content'] = json.loads(content)
            except Exception as e:
                logger.warning(f"Error parsing policy content as JSON: {str(e)}")
                formatted['content'] = content
        
        return formatted
    except Exception as e:
        logger.error(f"Error formatting policy details: {str(e)}")
        return policy  # Return original data if formatting fails

def format_policy_target(target: Dict[str, Any]) -> Dict[str, Any]:
    """Format a policy target into a simplified representation.
    
    Args:
        target: Raw target data from AWS
    
    Returns:
        Dict containing simplified target representation
    """
    try:
        return {
            'target_id': target.get('TargetId'),
            'arn': target.get('Arn'),
            'name': target.get('Name'),
            'type': target.get('Type')
        }
    except Exception as e:
        logger.error(f"Error formatting policy target: {str(e)}")
        return target  # Return original data if formatting fails

def format_policy_with_targets(policy: Dict[str, Any], targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format a policy with its targets.
    
    Args:
        policy: Raw policy data from AWS
        targets: List of targets the policy is attached to
    
    Returns:
        Dict containing policy with targets
    """
    try:
        formatted_policy = format_policy_detail(policy)
        formatted_policy['targets'] = [format_policy_target(target) for target in targets]
        return formatted_policy
    except Exception as e:
        logger.error(f"Error formatting policy with targets: {str(e)}")
        return policy  # Return original data if formatting fails

def format_org_hierarchy(hierarchy: Dict[str, Any]) -> Dict[str, Any]:
    """Format the organizational hierarchy for better readability.
    
    Args:
        hierarchy: Raw hierarchy data
    
    Returns:
        Dict containing formatted hierarchy
    """
    try:
        if not hierarchy:
            return {}
            
        formatted = {
            'id': hierarchy.get('Id'),
            'name': hierarchy.get('Name'),
            'type': hierarchy.get('Type'),
            'accounts': [format_account_simple(account) for account in hierarchy.get('Accounts', [])],
            'organizational_units': []
        }
        
        # Format child OUs recursively
        for ou in hierarchy.get('OrganizationalUnits', []):
            formatted_ou = format_org_hierarchy(ou)
            formatted['organizational_units'].append(formatted_ou)
        
        return formatted
    except Exception as e:
        logger.error(f"Error formatting organizational hierarchy: {str(e)}")
        return hierarchy  # Return original data if formatting fails

def format_effective_policies(effective_policies: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Format effective policies for better readability.
    
    Args:
        effective_policies: Raw effective policies data
    
    Returns:
        Dict containing formatted effective policies
    """
    try:
        formatted = {}
        
        for policy_type, policies in effective_policies.items():
            formatted_type = policy_type.replace('_', ' ').title()
            formatted[formatted_type] = []
            
            for policy in policies:
                formatted_policy = {
                    'id': policy.get('Id'),
                    'arn': policy.get('Arn'),
                    'name': policy.get('Name', 'Unknown')
                }
                
                # Parse policy content if available
                content = policy.get('Content')
                if content:
                    try:
                        import json
                        formatted_policy['content'] = json.loads(content)
                    except Exception as e:
                        logger.warning(f"Error parsing policy content as JSON: {str(e)}")
                        formatted_policy['content'] = content
                
                formatted[formatted_type].append(formatted_policy)
        
        return formatted
    except Exception as e:
        logger.error(f"Error formatting effective policies: {str(e)}")
        return effective_policies  # Return original data if formatting fails 