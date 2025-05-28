"""Shield service module for AWS Security MCP."""

import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from aws_security_mcp.services.base import get_client, handle_aws_error, handle_pagination

# Configure logging
logger = logging.getLogger(__name__)

def get_shield_client(session_context: Optional[str] = None, **kwargs: Any) -> Any:
    """Get AWS Shield client.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        **kwargs: Additional arguments to pass to the boto3 client constructor
        
    Returns:
        boto3.client: An initialized Shield client
    """
    # Shield API is only available in us-east-1
    return get_client('shield', region='us-east-1', session_context=session_context, **kwargs)

async def get_subscription_state(session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get the Shield Advanced subscription state.
    
    Args:
        session_context: Optional session key for cross-account access
        
    Returns:
        Dictionary containing subscription information
    """
    client = get_shield_client(session_context=session_context)
    
    try:
        response = client.describe_subscription()
        return response.get('Subscription', {})
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ResourceNotFoundException':
            # No Shield Advanced subscription
            return {}
        logger.error(f"Error getting Shield subscription state: {e}")
        raise

async def list_protected_resources(
    max_items: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List resources protected by Shield Advanced.

    Args:
        max_items: Maximum number of protected resources to return
        next_token: Token for pagination
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing protected resources and pagination information
    """
    client = get_shield_client(session_context=session_context)
    
    try:
        params = {}
        
        if next_token:
            params['NextToken'] = next_token
            
        response = client.list_protected_resources(**params)
        
        return {
            'protected_resources': response.get('ProtectedResources', []),
            'next_token': response.get('NextToken'),
            'has_more': bool(response.get('NextToken'))
        }
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ResourceNotFoundException':
            # No Shield Advanced subscription
            return {
                'protected_resources': [],
                'next_token': None,
                'has_more': False
            }
        logger.error(f"Error listing Shield protected resources: {e}")
        raise

async def get_protection_details(resource_arn: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get protection details for a specific resource.

    Args:
        resource_arn: ARN of the resource to get protection details for
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing protection information
    """
    client = get_shield_client(session_context=session_context)
    
    try:
        response = client.describe_protection(ResourceArn=resource_arn)
        return response.get('Protection', {})
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ResourceNotFoundException':
            # Resource not protected by Shield Advanced
            return {}
        logger.error(f"Error getting Shield protection details for {resource_arn}: {e}")
        raise

async def list_protections(
    max_items: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List all protections in Shield Advanced.

    Args:
        max_items: Maximum number of protections to return
        next_token: Token for pagination
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing protections and pagination information
    """
    client = get_shield_client(session_context=session_context)
    
    try:
        params = {}
        
        if next_token:
            params['NextToken'] = next_token
            
        response = client.list_protections(**params)
        
        return {
            'protections': response.get('Protections', []),
            'next_token': response.get('NextToken'),
            'has_more': bool(response.get('NextToken'))
        }
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ResourceNotFoundException':
            # No Shield Advanced subscription
            return {
                'protections': [],
                'next_token': None,
                'has_more': False
            }
        logger.error(f"Error listing Shield protections: {e}")
        raise

async def list_attacks(
    start_time: Optional[Dict[str, Any]] = None,
    end_time: Optional[Dict[str, Any]] = None,
    max_items: int = 100,
    next_token: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """List detected DDoS attacks.

    Args:
        start_time: Start time for attack listing (format: {'FromInclusive': datetime, 'ToExclusive': datetime})
        end_time: End time for attack listing (format: {'FromInclusive': datetime, 'ToExclusive': datetime})
        max_items: Maximum number of attacks to return
        next_token: Token for pagination
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing attacks and pagination information
    """
    client = get_shield_client(session_context=session_context)
    
    try:
        params = {
            'MaxResults': min(max_items, 100)  # API maximum is 100
        }
        
        if start_time:
            params['StartTime'] = start_time
            
        if end_time:
            params['EndTime'] = end_time
            
        if next_token:
            params['NextToken'] = next_token
            
        response = client.list_attacks(**params)
        
        return {
            'attacks': response.get('AttackSummaries', []),
            'next_token': response.get('NextToken'),
            'has_more': bool(response.get('NextToken'))
        }
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ResourceNotFoundException':
            # No Shield Advanced subscription
            return {
                'attacks': [],
                'next_token': None,
                'has_more': False
            }
        logger.error(f"Error listing Shield attacks: {e}")
        raise

async def get_attack_details(attack_id: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get details of a specific DDoS attack.

    Args:
        attack_id: ID of the attack to get details for
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing detailed attack information
    """
    client = get_shield_client(session_context=session_context)
    
    try:
        response = client.describe_attack(AttackId=attack_id)
        return response.get('Attack', {})
    except ClientError as e:
        logger.error(f"Error getting Shield attack details for {attack_id}: {e}")
        raise

async def get_drt_access(session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get DDoS Response Team (DRT) access status.

    Args:
        session_context: Optional session key for cross-account access

    Returns:
        Dictionary containing DRT access information
    """
    client = get_shield_client(session_context=session_context)
    
    try:
        response = client.describe_drt_access()
        return {
            'role_arn': response.get('RoleArn'),
            'log_bucket_list': response.get('LogBucketList', [])
        }
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ResourceNotFoundException':
            # No Shield Advanced subscription or DRT access not configured
            return {
                'role_arn': None,
                'log_bucket_list': []
            }
        logger.error(f"Error getting Shield DRT access: {e}")
        raise

async def describe_emergency_contact_list(session_context: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get the emergency contact list for AWS Shield.

    Args:
        session_context: Optional session key for cross-account access

    Returns:
        List of emergency contacts
    """
    client = get_shield_client(session_context=session_context)
    
    try:
        response = client.describe_emergency_contact_settings()
        return response.get('EmergencyContactList', [])
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ResourceNotFoundException':
            # No Shield Advanced subscription or no emergency contacts
            return []
        logger.error(f"Error getting Shield emergency contacts: {e}")
        raise

# Backward compatibility: Keep the ShieldService class for existing code
class ShieldService:
    """Service class for AWS Shield operations.
    
    DEPRECATED: Use the standalone functions above instead.
    This class is kept for backward compatibility only.
    """

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None, session_context: Optional[str] = None):
        """Initialize the Shield service.

        Args:
            region: AWS region name (overrides config)
            profile: AWS profile name (overrides config) 
            session_context: Optional session key for cross-account access
        """
        self.region = region
        self.profile = profile
        self.session_context = session_context
        self._client = None

    @property
    def client(self):
        """Get the Shield client, creating it if necessary.

        Returns:
            boto3.client: The Shield client
        """
        if self._client is None:
            self._client = get_shield_client(session_context=self.session_context)
        return self._client

    async def get_subscription_state(self) -> Dict[str, Any]:
        """Get the Shield Advanced subscription state."""
        return await get_subscription_state(session_context=self.session_context)

    async def list_protected_resources(self, max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
        """List resources protected by Shield Advanced."""
        return await list_protected_resources(max_items=max_items, next_token=next_token, session_context=self.session_context)

    async def get_protection_details(self, resource_arn: str) -> Dict[str, Any]:
        """Get protection details for a specific resource."""
        return await get_protection_details(resource_arn=resource_arn, session_context=self.session_context)

    async def list_protections(self, max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
        """List all protections in Shield Advanced."""
        return await list_protections(max_items=max_items, next_token=next_token, session_context=self.session_context)

    async def list_attacks(
        self,
        start_time: Optional[Dict[str, Any]] = None,
        end_time: Optional[Dict[str, Any]] = None,
        max_items: int = 100,
        next_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """List detected DDoS attacks."""
        return await list_attacks(
            start_time=start_time,
            end_time=end_time,
            max_items=max_items,
            next_token=next_token,
            session_context=self.session_context
        )

    async def get_attack_details(self, attack_id: str) -> Dict[str, Any]:
        """Get details of a specific DDoS attack."""
        return await get_attack_details(attack_id=attack_id, session_context=self.session_context)

    async def get_drt_access(self) -> Dict[str, Any]:
        """Get DDoS Response Team (DRT) access status."""
        return await get_drt_access(session_context=self.session_context)

    async def describe_emergency_contact_list(self) -> List[Dict[str, Any]]:
        """Get the emergency contact list for AWS Shield."""
        return await describe_emergency_contact_list(session_context=self.session_context) 