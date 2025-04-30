"""Shield service module for AWS Security MCP."""

import logging
from typing import Any, Dict, List, Optional, Union

from botocore.exceptions import ClientError

from aws_security_mcp.services.base import get_client, handle_aws_error, handle_pagination

# Configure logging
logger = logging.getLogger(__name__)

class ShieldService:
    """Service class for AWS Shield operations."""

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize the Shield service.

        Args:
            region: AWS region name (overrides config)
            profile: AWS profile name (overrides config)
        """
        self.region = region
        self.profile = profile
        self._client = None

    @property
    def client(self):
        """Get the Shield client, creating it if necessary.

        Returns:
            boto3.client: The Shield client
        """
        if self._client is None:
            # Shield API is only available in us-east-1
            self._client = get_client('shield', 'us-east-1', self.profile)
        return self._client

    async def get_subscription_state(self) -> Dict[str, Any]:
        """Get the Shield Advanced subscription state.

        Returns:
            Dictionary containing subscription information
        """
        try:
            response = self.client.describe_subscription()
            return response.get('Subscription', {})
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'ResourceNotFoundException':
                # No Shield Advanced subscription
                return {}
            logger.error(f"Error getting Shield subscription state: {e}")
            raise

    async def list_protected_resources(self, max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
        """List resources protected by Shield Advanced.

        Args:
            max_items: Maximum number of protected resources to return
            next_token: Token for pagination

        Returns:
            Dictionary containing protected resources and pagination information
        """
        try:
            params = {}
            
            if next_token:
                params['NextToken'] = next_token
                
            response = self.client.list_protected_resources(**params)
            
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

    async def get_protection_details(self, resource_arn: str) -> Dict[str, Any]:
        """Get protection details for a specific resource.

        Args:
            resource_arn: ARN of the resource to get protection details for

        Returns:
            Dictionary containing protection information
        """
        try:
            response = self.client.describe_protection(
                ResourceArn=resource_arn
            )
            return response.get('Protection', {})
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'ResourceNotFoundException':
                # Resource not protected by Shield Advanced
                return {}
            logger.error(f"Error getting Shield protection details for {resource_arn}: {e}")
            raise

    async def list_protections(self, max_items: int = 100, next_token: Optional[str] = None) -> Dict[str, Any]:
        """List all protections in Shield Advanced.

        Args:
            max_items: Maximum number of protections to return
            next_token: Token for pagination

        Returns:
            Dictionary containing protections and pagination information
        """
        try:
            params = {}
            
            if next_token:
                params['NextToken'] = next_token
                
            response = self.client.list_protections(**params)
            
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
        self,
        start_time: Optional[Dict[str, Any]] = None,
        end_time: Optional[Dict[str, Any]] = None,
        max_items: int = 100,
        next_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """List detected DDoS attacks.

        Args:
            start_time: Start time for attack listing (format: {'FromInclusive': datetime, 'ToExclusive': datetime})
            end_time: End time for attack listing (format: {'FromInclusive': datetime, 'ToExclusive': datetime})
            max_items: Maximum number of attacks to return
            next_token: Token for pagination

        Returns:
            Dictionary containing attacks and pagination information
        """
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
                
            response = self.client.list_attacks(**params)
            
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

    async def get_attack_details(self, attack_id: str) -> Dict[str, Any]:
        """Get details of a specific DDoS attack.

        Args:
            attack_id: ID of the attack to get details for

        Returns:
            Dictionary containing detailed attack information
        """
        try:
            response = self.client.describe_attack(
                AttackId=attack_id
            )
            return response.get('Attack', {})
        except ClientError as e:
            logger.error(f"Error getting Shield attack details for {attack_id}: {e}")
            raise

    async def get_drt_access(self) -> Dict[str, Any]:
        """Get DDoS Response Team (DRT) access status.

        Returns:
            Dictionary containing DRT access information
        """
        try:
            response = self.client.describe_drt_access()
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

    async def describe_emergency_contact_list(self) -> List[Dict[str, Any]]:
        """Get the emergency contact list for AWS Shield.

        Returns:
            List of emergency contacts
        """
        try:
            response = self.client.describe_emergency_contact_settings()
            return response.get('EmergencyContactList', [])
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'ResourceNotFoundException':
                # No Shield Advanced subscription or no emergency contacts
                return []
            logger.error(f"Error getting Shield emergency contacts: {e}")
            raise 