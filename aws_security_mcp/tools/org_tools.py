"""Organizations tools module for AWS Security MCP.

This module provides tools for retrieving and analyzing AWS Organizations information
for security assessment purposes.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from aws_security_mcp.services import organizations
from aws_security_mcp.formatters import org_formatter
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)

@register_tool()
async def fetch_aws_org() -> Dict[str, Any]:
    """Fetch information about the AWS Organization.

    Returns:
        Dict containing information about the AWS Organization
    """
    try:
        logger.info("Fetching AWS Organization information")
        
        # Get organization info from the service
        org_info = organizations.get_organization()
        
        # Format organization information
        formatted_org = org_formatter.format_organization_simple(org_info)
        
        # Get hierarchy information
        hierarchy = await get_org_hierarchy_async()
        
        return {
            "organization": formatted_org,
            "hierarchy": hierarchy,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error fetching AWS Organization: {str(e)}")
        return {
            "organization": {},
            "hierarchy": {},
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

async def get_org_hierarchy_async() -> Dict[str, Any]:
    """Async wrapper for get_organization_hierarchy.
    
    Returns:
        Dictionary representing the organization structure
    """
    try:
        # Run the synchronous function in an executor
        hierarchy = await organizations.run_in_executor(organizations.get_organization_hierarchy)
        
        # Format the hierarchy
        formatted_hierarchy = org_formatter.format_org_hierarchy(hierarchy)
        
        return formatted_hierarchy
    except Exception as e:
        logger.error(f"Error getting organization hierarchy: {str(e)}")
        return {}

@register_tool()
async def details_aws_account(account_id: Optional[str] = None, account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Fetch details about AWS accounts in the organization.

    Args:
        account_id: Optional single account ID to fetch details for
        account_ids: Optional list of account IDs to fetch details for

    Returns:
        Dict containing account details
    """
    try:
        logger.info(f"Fetching AWS account details")
        
        accounts_to_fetch = []
        
        # If both parameters are None, fetch all accounts
        if account_id is None and account_ids is None:
            logger.info("No account IDs specified, fetching all accounts")
            all_accounts = organizations.list_accounts()
            accounts_to_fetch = [account.get('Id') for account in all_accounts if account.get('Id')]
        
        # If single account_id is provided
        elif account_id is not None:
            accounts_to_fetch = [account_id]
        
        # If account_ids list is provided
        elif account_ids is not None:
            accounts_to_fetch = account_ids
        
        # Get details for each account
        account_details = {}
        policies_by_account = {}
        
        # Process accounts in parallel using asyncio
        async def get_account_with_policies(acc_id: str):
            try:
                # Get basic account details
                account_detail = await organizations.run_in_executor(organizations.get_account_details, acc_id)
                
                # Get effective policies
                policies = await organizations.run_in_executor(organizations.get_effective_policies_for_account, acc_id)
                
                return acc_id, account_detail, policies
            except Exception as e:
                logger.error(f"Error getting details for account {acc_id}: {str(e)}")
                return acc_id, {}, {}
        
        # Create tasks for all accounts
        tasks = [get_account_with_policies(acc_id) for acc_id in accounts_to_fetch]
        results = await asyncio.gather(*tasks)
        
        # Process results
        for acc_id, account_detail, policies in results:
            if account_detail:
                account_details[acc_id] = org_formatter.format_account_simple(account_detail)
                policies_by_account[acc_id] = org_formatter.format_effective_policies(policies)
        
        return {
            "accounts": account_details,
            "effective_policies": policies_by_account,
            "count": len(account_details),
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error fetching AWS account details: {str(e)}")
        return {
            "accounts": {},
            "effective_policies": {},
            "count": 0,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool()
async def fetch_aws_org_controls() -> Dict[str, Any]:
    """Fetch all AWS Organization-level security controls.

    Returns:
        Dict containing Organization-level controls (SCPs, etc.)
    """
    try:
        logger.info("Fetching AWS Organization controls")
        
        # Get all policy types
        policy_types = [
            'SERVICE_CONTROL_POLICY',
            'TAG_POLICY',
            'BACKUP_POLICY',
            'AISERVICES_OPT_OUT_POLICY'
        ]
        
        policies_by_type = {}
        
        # Get policies for each type
        for policy_type in policy_types:
            try:
                policies = await organizations.run_in_executor(organizations.list_policies, policy_type)
                
                if policies:
                    formatted_type = policy_type.replace('_', ' ').title()
                    policies_by_type[formatted_type] = [
                        org_formatter.format_policy_simple(policy) for policy in policies
                    ]
            except Exception as e:
                logger.warning(f"Error fetching policies of type {policy_type}: {str(e)}")
        
        # Get all roots for reference
        roots = await organizations.run_in_executor(organizations.list_roots)
        formatted_roots = []
        
        for root in roots:
            formatted_root = {
                'id': root.get('Id'),
                'name': root.get('Name'),
                'arn': root.get('Arn'),
                'policy_types': [
                    {
                        'type': pt.get('Type'),
                        'status': pt.get('Status')
                    }
                    for pt in root.get('PolicyTypes', [])
                ]
            }
            formatted_roots.append(formatted_root)
        
        return {
            "policies": policies_by_type,
            "roots": formatted_roots,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error fetching AWS Organization controls: {str(e)}")
        return {
            "policies": {},
            "roots": [],
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool()
async def fetch_scp_details(policy_id: str) -> Dict[str, Any]:
    """Fetch details of a specific SCP policy and its targets.

    Args:
        policy_id: ID of the SCP policy

    Returns:
        Dict containing SCP policy details and targets
    """
    try:
        logger.info(f"Fetching SCP policy details for {policy_id}")
        
        # Get policy details
        policy_details = await organizations.run_in_executor(organizations.get_policy, policy_id)
        
        if not policy_details:
            logger.warning(f"Policy {policy_id} not found")
            return {
                "policy": {},
                "targets": [],
                "scan_timestamp": datetime.utcnow().isoformat(),
                "error": f"Policy {policy_id} not found"
            }
        
        # Get targets for the policy
        targets = await organizations.run_in_executor(organizations.list_targets_for_policy, policy_id)
        
        # Format policy with targets
        formatted_policy = org_formatter.format_policy_with_targets(policy_details, targets)
        
        return {
            "policy": formatted_policy,
            "target_count": len(targets),
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error fetching SCP policy details: {str(e)}")
        return {
            "policy": {},
            "targets": [],
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        } 