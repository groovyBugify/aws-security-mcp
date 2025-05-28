"""AWS service clients for security-related operations."""

from typing import Any, Dict, Optional, Union

# Export common utilities
from aws_security_mcp.services.base import get_aws_session, get_client

# Type alias for AWS responses
AWSResponse = Dict[str, Any]

# Import service modules for easy access
from aws_security_mcp.services import (
    access_analyzer,
    base,
    cloudfront,
    credentials,
    ec2,
    ecs,
    ecr,
    guardduty,
    iam,
    lambda_service,
    load_balancer,
    organizations,
    resource_tagging,
    route53,
    s3,
    securityhub,
    shield,
    trusted_advisor,
    waf,
)

# For backward compatibility, keep the class imports where they exist
try:
    from aws_security_mcp.services.shield import ShieldService
except ImportError:
    pass
    
try:
    from aws_security_mcp.services.resource_tagging import ResourceTaggingService
except ImportError:
    pass 