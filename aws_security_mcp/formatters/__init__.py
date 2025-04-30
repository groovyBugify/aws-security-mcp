"""Formatters for AWS resources in the AWS Security MCP."""

from typing import Any, Dict, List, Optional, Union

# Common text formatting utilities
def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to a maximum length with ellipsis if needed.
    
    Args:
        text: Text to truncate
        max_length: Maximum length before truncation
        
    Returns:
        Truncated text with ellipsis if needed
    """
    if not text or len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

def format_key_value(key: str, value: Any, indent: int = 0) -> str:
    """Format a key-value pair for display.
    
    Args:
        key: The label or key
        value: The value to display
        indent: Number of spaces to indent
        
    Returns:
        Formatted key-value string
    """
    indent_str = " " * indent
    return f"{indent_str}{key}: {value}"

def format_list(items: List[Any], indent: int = 0) -> str:
    """Format a list of items with bullet points.
    
    Args:
        items: List of items to format
        indent: Number of spaces to indent
        
    Returns:
        Formatted list as a string
    """
    if not items:
        return ""
        
    indent_str = " " * indent
    return "\n".join(f"{indent_str}- {item}" for item in items)

# Export formatters for easier imports
# Removed IAM formatters - to be rebuilt
# from aws_security_mcp.formatters.iam import (
#     format_iam_role_json,
#     format_iam_policy_json,
#     format_iam_user_json,
#     format_iam_access_key_json,
#     format_iam_permission_set_json,
#     format_iam_group_json,
#     format_iam_policy_document_json,
#     format_iam_mfa_device_json,
#     format_iam_user_detail_json,
#     format_iam_role_detail_json,
#     format_iam_summary_json,
#     format_iam_credential_report_json,
#     format_iam_permissions_boundary_json,
# )

from aws_security_mcp.formatters.s3_formatter import (
    format_bucket_simple,
    format_bucket_details,
    format_public_buckets_assessment,
    calculate_security_rating,
    format_acl_grants
)

from aws_security_mcp.formatters.org_formatter import (
    format_organization_simple,
    format_account_simple,
    format_policy_simple,
    format_policy_detail,
    format_policy_target,
    format_policy_with_targets,
    format_org_hierarchy,
    format_effective_policies
)

# EC2 formatters removed as they're now replaced with direct JSON formatting in the tools

from aws_security_mcp.formatters.guardduty import (
    format_guardduty_detector_json,
    format_guardduty_finding_json,
    format_guardduty_findings_statistics_json,
    format_guardduty_ip_set_json,
    format_guardduty_threat_intel_set_json,
    format_guardduty_filter_json,
    format_guardduty_detectors_summary_json,
)

from aws_security_mcp.formatters.lambda_formatter import (
    format_lambda_function_json,
    format_lambda_layer_json,
    format_lambda_functions_summary_json,
    format_lambda_alias_json,
    format_lambda_event_source_mapping_json,
)

# Legacy formatters - will be migrated in future updates
from aws_security_mcp.formatters.load_balancer import (
    format_load_balancer,
    format_target_group,
    format_listener,
)

from aws_security_mcp.formatters.cloudfront import (
    format_distribution,
    format_cache_policy,
    format_origin_request_policy,
)

from aws_security_mcp.formatters.route53 import (
    format_hosted_zone,
    format_record_set,
    format_health_check,
)

from aws_security_mcp.formatters.securityhub import (
    format_finding,
    format_securityhub_finding,
    format_finding_resources,
    format_finding_summary,
    format_insight,
    format_standard,
    format_control,
) 