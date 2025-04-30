"""WAF service module for AWS Security MCP."""

import logging
from typing import Any, Dict, List, Optional, Union

from botocore.exceptions import ClientError

from aws_security_mcp.services.base import get_client, handle_aws_error, handle_pagination

# Configure logging
logger = logging.getLogger(__name__)

class WAFService:
    """Service class for AWS WAF operations."""

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize the WAF service.

        Args:
            region: AWS region name (overrides config)
            profile: AWS profile name (overrides config)
        """
        self.region = region
        self.profile = profile
        self._waf_client = None  # Classic WAF
        self._wafv2_client = None  # WAFv2

    @property
    def waf_client(self):
        """Get the Classic WAF client, creating it if necessary.

        Returns:
            boto3.client: The WAF client
        """
        if self._waf_client is None:
            self._waf_client = get_client('waf', self.region, self.profile)
        return self._waf_client

    @property
    def wafv2_client(self):
        """Get the WAFv2 client, creating it if necessary.

        Returns:
            boto3.client: The WAFv2 client
        """
        if self._wafv2_client is None:
            self._wafv2_client = get_client('wafv2', self.region, self.profile)
        return self._wafv2_client

    async def list_web_acls(self, scope: str = 'REGIONAL', max_items: int = 100, next_marker: Optional[str] = None) -> Dict[str, Any]:
        """List WAFv2 Web ACLs.

        Args:
            scope: The scope of the Web ACL. Valid values are 'REGIONAL' or 'CLOUDFRONT'
            max_items: Maximum number of Web ACLs to return
            next_marker: Token for pagination

        Returns:
            Dictionary containing Web ACLs and pagination information
        """
        try:
            params = {
                'Scope': scope,
                'Limit': min(max_items, 100)  # API maximum is 100
            }
            
            if next_marker:
                params['NextMarker'] = next_marker
                
            response = self.wafv2_client.list_web_acls(**params)
            
            return {
                'web_acls': response.get('WebACLs', []),
                'next_marker': response.get('NextMarker'),
                'has_more': bool(response.get('NextMarker'))
            }
        except ClientError as e:
            logger.error(f"Error listing WAFv2 Web ACLs: {e}")
            raise

    async def list_ip_sets(self, scope: str = 'REGIONAL', max_items: int = 100, next_marker: Optional[str] = None) -> Dict[str, Any]:
        """List WAFv2 IP sets.

        Args:
            scope: The scope of the IP set. Valid values are 'REGIONAL' or 'CLOUDFRONT'
            max_items: Maximum number of IP sets to return
            next_marker: Token for pagination

        Returns:
            Dictionary containing IP sets and pagination information
        """
        try:
            params = {
                'Scope': scope,
                'Limit': min(max_items, 100)  # API maximum is 100
            }
            
            if next_marker:
                params['NextMarker'] = next_marker
                
            response = self.wafv2_client.list_ip_sets(**params)
            
            return {
                'ip_sets': response.get('IPSets', []),
                'next_marker': response.get('NextMarker'),
                'has_more': bool(response.get('NextMarker'))
            }
        except ClientError as e:
            logger.error(f"Error listing WAFv2 IP sets: {e}")
            raise

    async def list_rule_groups(self, scope: str = 'REGIONAL', max_items: int = 100, next_marker: Optional[str] = None) -> Dict[str, Any]:
        """List WAFv2 rule groups.

        Args:
            scope: The scope of the rule group. Valid values are 'REGIONAL' or 'CLOUDFRONT'
            max_items: Maximum number of rule groups to return
            next_marker: Token for pagination

        Returns:
            Dictionary containing rule groups and pagination information
        """
        try:
            params = {
                'Scope': scope,
                'Limit': min(max_items, 100)  # API maximum is 100
            }
            
            if next_marker:
                params['NextMarker'] = next_marker
                
            response = self.wafv2_client.list_rule_groups(**params)
            
            return {
                'rule_groups': response.get('RuleGroups', []),
                'next_marker': response.get('NextMarker'),
                'has_more': bool(response.get('NextMarker'))
            }
        except ClientError as e:
            logger.error(f"Error listing WAFv2 rule groups: {e}")
            raise

    async def get_web_acl(self, web_acl_id: str, web_acl_name: str, scope: str = 'REGIONAL') -> Dict[str, Any]:
        """Get details of a specific WAFv2 Web ACL.

        Args:
            web_acl_id: The ID of the Web ACL
            web_acl_name: The name of the Web ACL
            scope: The scope of the Web ACL. Valid values are 'REGIONAL' or 'CLOUDFRONT'

        Returns:
            Dictionary containing detailed Web ACL information
        """
        try:
            response = self.wafv2_client.get_web_acl(
                Name=web_acl_name,
                Id=web_acl_id,
                Scope=scope
            )
            return response.get('WebACL', {})
        except ClientError as e:
            logger.error(f"Error getting WAFv2 Web ACL {web_acl_name}: {e}")
            raise

    async def get_ip_set(self, ip_set_id: str, ip_set_name: str, scope: str = 'REGIONAL') -> Dict[str, Any]:
        """Get details of a specific WAFv2 IP set.

        Args:
            ip_set_id: The ID of the IP set
            ip_set_name: The name of the IP set
            scope: The scope of the IP set. Valid values are 'REGIONAL' or 'CLOUDFRONT'

        Returns:
            Dictionary containing detailed IP set information
        """
        try:
            response = self.wafv2_client.get_ip_set(
                Name=ip_set_name,
                Id=ip_set_id,
                Scope=scope
            )
            return response.get('IPSet', {})
        except ClientError as e:
            logger.error(f"Error getting WAFv2 IP set {ip_set_name}: {e}")
            raise

    async def get_rule_group(self, rule_group_id: str, rule_group_name: str, scope: str = 'REGIONAL') -> Dict[str, Any]:
        """Get details of a specific WAFv2 rule group.

        Args:
            rule_group_id: The ID of the rule group
            rule_group_name: The name of the rule group
            scope: The scope of the rule group. Valid values are 'REGIONAL' or 'CLOUDFRONT'

        Returns:
            Dictionary containing detailed rule group information
        """
        try:
            response = self.wafv2_client.get_rule_group(
                Name=rule_group_name,
                Id=rule_group_id,
                Scope=scope
            )
            return response.get('RuleGroup', {})
        except ClientError as e:
            logger.error(f"Error getting WAFv2 rule group {rule_group_name}: {e}")
            raise

    async def list_resources_for_web_acl(self, web_acl_arn: str, resource_type: str = 'APPLICATION_LOAD_BALANCER') -> List[str]:
        """List resources protected by a WAFv2 Web ACL.

        Args:
            web_acl_arn: The ARN of the Web ACL
            resource_type: The type of resource. Valid values include 'APPLICATION_LOAD_BALANCER', 'API_GATEWAY', 'APPSYNC', etc.

        Returns:
            List of resource ARNs associated with the Web ACL
        """
        try:
            response = self.wafv2_client.list_resources_for_web_acl(
                WebACLArn=web_acl_arn,
                ResourceType=resource_type
            )
            return response.get('ResourceArns', [])
        except ClientError as e:
            logger.error(f"Error listing resources for WAFv2 Web ACL {web_acl_arn}: {e}")
            raise

    # Classic WAF methods - these are kept for backward compatibility but are deprecated

    async def list_classic_web_acls(self, max_items: int = 100, next_marker: Optional[str] = None) -> Dict[str, Any]:
        """List Classic WAF Web ACLs.

        Note: This is a deprecated API. Use WAFv2 methods whenever possible.

        Args:
            max_items: Maximum number of Web ACLs to return
            next_marker: Token for pagination

        Returns:
            Dictionary containing Web ACLs and pagination information
        """
        try:
            params = {
                'Limit': min(max_items, 100)  # API maximum is 100
            }
            
            if next_marker:
                params['NextMarker'] = next_marker
                
            response = self.waf_client.list_web_acls(**params)
            
            return {
                'web_acls': response.get('WebACLs', []),
                'next_marker': response.get('NextMarker'),
                'has_more': bool(response.get('NextMarker'))
            }
        except ClientError as e:
            logger.error(f"Error listing Classic WAF Web ACLs: {e}")
            raise

    async def get_classic_web_acl(self, web_acl_id: str) -> Dict[str, Any]:
        """Get details of a specific Classic WAF Web ACL.

        Note: This is a deprecated API. Use WAFv2 methods whenever possible.

        Args:
            web_acl_id: The ID of the Web ACL

        Returns:
            Dictionary containing detailed Web ACL information
        """
        try:
            response = self.waf_client.get_web_acl(
                WebACLId=web_acl_id
            )
            return response.get('WebACL', {})
        except ClientError as e:
            logger.error(f"Error getting Classic WAF Web ACL {web_acl_id}: {e}")
            raise 