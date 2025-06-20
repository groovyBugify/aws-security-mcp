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
async def details_aws_account(
    account_id: Optional[str] = None, 
    account_ids: Optional[List[str]] = None,
    include_policies: bool = False,
    status_filter: str = "ACTIVE"
) -> Dict[str, Any]:
    """Fetch details about AWS accounts in the organization.

    Args:
        account_id: Optional single account ID to fetch details for
        account_ids: Optional list of account IDs to fetch details for
        include_policies: Whether to include effective policies (expensive operation)
        status_filter: Account status to filter by (ACTIVE, SUSPENDED, ALL)

    Returns:
        Dict containing account details with counts and optionally policies
    """
    try:
        logger.info(f"Fetching AWS account details with status_filter={status_filter}, include_policies={include_policies}")
        
        # Get account counts first
        account_counts = await organizations.run_in_executor(organizations.get_account_counts)
        
        accounts_to_process = []
        
        # Determine which accounts to fetch
        if account_id is not None:
            # Single account - get its details directly
            account_detail = await organizations.run_in_executor(organizations.get_account_details, account_id)
            if account_detail and (status_filter == "ALL" or account_detail.get('Status') == status_filter):
                accounts_to_process = [account_detail]
        elif account_ids is not None:
            # Multiple specific accounts
            async def get_single_account(acc_id: str):
                try:
                    return await organizations.run_in_executor(organizations.get_account_details, acc_id)
                except Exception as e:
                    logger.error(f"Error getting account {acc_id}: {str(e)}")
                    return None
            
            tasks = [get_single_account(acc_id) for acc_id in account_ids]
            results = await asyncio.gather(*tasks)
            
            # Filter by status
            for account_detail in results:
                if account_detail and (status_filter == "ALL" or account_detail.get('Status') == status_filter):
                    accounts_to_process.append(account_detail)
        else:
            # No specific accounts - get all accounts with status filtering
            if status_filter == "ACTIVE":
                accounts_to_process = await organizations.run_in_executor(organizations.list_active_accounts)
            elif status_filter == "ALL":
                accounts_to_process = await organizations.run_in_executor(organizations.list_accounts)
            else:
                # Other status filters
                all_accounts = await organizations.run_in_executor(organizations.list_accounts)
                accounts_to_process = [acc for acc in all_accounts if acc.get('Status') == status_filter]
        
        # Format account details
        account_details = {}
        policies_by_account = {}
        
        # Process accounts efficiently
        for account in accounts_to_process:
            if not account:
                continue
                
            account_id = account.get('Id')
            if not account_id:
                continue
                
            # Always include basic account details
            account_details[account_id] = org_formatter.format_account_simple(account)
        
        # Only fetch policies if explicitly requested (expensive operation)
        if include_policies and account_details:
            logger.info(f"Fetching effective policies for {len(account_details)} accounts (this may take time)")
            
            async def get_account_policies(acc_id: str):
                try:
                    policies = await organizations.run_in_executor(organizations.get_effective_policies_for_account, acc_id)
                    return acc_id, policies
                except Exception as e:
                    logger.error(f"Error getting policies for account {acc_id}: {str(e)}")
                    return acc_id, {}
            
            # Process policies in parallel
            policy_tasks = [get_account_policies(acc_id) for acc_id in account_details.keys()]
            policy_results = await asyncio.gather(*policy_tasks)
            
            for acc_id, policies in policy_results:
                if policies:
                    policies_by_account[acc_id] = org_formatter.format_effective_policies(policies)
        
        # Build response
        response = {
            "accounts": account_details,
            "account_counts": account_counts,
            "filtered_count": len(account_details),
            "status_filter": status_filter,
            "policies_included": include_policies,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        # Only include policies section if requested
        if include_policies:
            response["effective_policies"] = policies_by_account
        
        logger.info(f"Successfully fetched details for {len(account_details)} accounts")
        return response
    
    except Exception as e:
        logger.error(f"Error fetching AWS account details: {str(e)}")
        return {
            "accounts": {},
            "account_counts": {},
            "filtered_count": 0,
            "status_filter": status_filter,
            "policies_included": include_policies,
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