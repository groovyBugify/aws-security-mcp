"""SecurityHub tools for AWS Security MCP."""

import logging
import json
from typing import Any, Dict, List, Optional, Union

from aws_security_mcp.services import securityhub
from aws_security_mcp.tools import register_tool
from aws_security_mcp.formatters.securityhub import (
    format_finding_json,
    format_securityhub_finding_json,
    format_finding_summary_json,
    format_standard_json,
    format_control_json
)
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
async def get_securityhub_findings(limit: int = 10, severity: str = "ALL", search_term: str = "") -> str:
    """Get findings from AWS SecurityHub.
    
    Args:
        limit: Maximum number of findings to return
        severity: Severity level to filter by (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, or ALL)
        search_term: Optional search term to filter findings
        
    Returns:
        JSON formatted string with SecurityHub findings
    """
    logger.info(f"Getting SecurityHub findings (limit={limit}, severity={severity}, search_term='{search_term}')")
    
    try:
        # Create filters
        filters = {}
        
        # Add severity filter if provided
        if severity != "ALL":
            severity_filter = securityhub.create_severity_filter(severity)
            filters.update(severity_filter)
        
        # For search terms, we'll use Title filter and then post-process for additional fields
        if search_term:
            search_filter = securityhub.create_search_term_filter(search_term)
            filters.update(search_filter)
        
        # Get findings
        findings = securityhub.get_all_findings(filters=filters, max_items=limit * 2)  # Get extra to account for post-filtering
        
        # Apply additional search term filtering if needed (post-processing for multi-field search)
        if search_term:
            findings = securityhub.filter_findings_by_text(findings, search_term)
        
        # Limit to requested number
        findings = findings[:limit]
        
        if not findings:
            return json.dumps({
                "count": 0,
                "findings": [],
                "severity": severity,
                "search_term": search_term if search_term else None,
                "message": f"No SecurityHub findings found{' with severity ' + severity if severity != 'ALL' else ''}{' matching ' + search_term if search_term else ''}."
            })
        
        # Format findings
        formatted_findings = []
        for finding in findings:
            formatted_findings.append(format_finding_json(finding))
        
        result = {
            "count": len(findings),
            "findings": formatted_findings,
            "severity": severity,
            "search_term": search_term if search_term else None,
            "is_truncated": len(findings) == limit
        }
        
        return json.dumps(result, default=lambda o: str(o))
    except Exception as e:
        logger.error(f"Error getting SecurityHub findings: {e}")
        return json.dumps({
            "error": {
                "message": f"Error retrieving SecurityHub findings: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def list_failed_security_standards(limit: int = 20) -> str:
    """List failed security standards from SecurityHub.
    
    Args:
        limit: Maximum number of failed standards to return
        
    Returns:
        JSON formatted string with failed security standards
    """
    logger.info(f"Listing failed security standards (limit={limit})")
    
    try:
        # Get SecurityHub client
        client = securityhub.get_securityhub_client()
        
        # Check if SecurityHub is enabled
        try:
            hub_response = client.describe_hub()
            if not hub_response:
                return json.dumps({
                    "count": 0,
                    "controls": [],
                    "message": "SecurityHub is not enabled in this region"
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAccessException':
                return json.dumps({
                    "count": 0,
                    "controls": [],
                    "message": "SecurityHub is not enabled or insufficient permissions"
                })
            raise
        
        # Get all enabled standards (subscriptions)
        enabled_standards_response = client.get_enabled_standards()
        enabled_standards = enabled_standards_response.get('StandardsSubscriptions', [])
        
        if not enabled_standards:
            return json.dumps({
                "count": 0,
                "controls": [],
                "message": "No security standards are enabled in SecurityHub"
            })
        
        # Get failed controls for each enabled standard
        failed_controls = []
        
        for standard in enabled_standards:
            standard_subscription_arn = standard.get('StandardsSubscriptionArn')
            standard_name = standard.get('StandardsArn', '').split('/')[-1] if standard.get('StandardsArn') else 'Unknown'
            
            if not standard_subscription_arn:
                logger.warning(f"Missing StandardsSubscriptionArn for standard: {standard}")
                continue
            
            # Get controls for this standard subscription
            try:
                controls_response = client.describe_standards_controls(
                    StandardsSubscriptionArn=standard_subscription_arn
                )
                
                controls = controls_response.get('Controls', [])
                
                # Filter failed controls
                for control in controls:
                    if control.get('ControlStatus') == 'FAILED':
                        control['StandardName'] = standard_name
                        failed_controls.append(control)
            except ClientError as e:
                logger.warning(f"Error getting controls for standard {standard_subscription_arn}: {e}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error getting controls for standard {standard_subscription_arn}: {e}")
                continue
        
        # Limit results
        failed_controls = failed_controls[:limit]
        
        if not failed_controls:
            return json.dumps({
                "count": 0,
                "controls": [],
                "message": "No failed security standards found"
            })
        
        # Format the results
        formatted_controls = []
        for control in failed_controls:
            formatted_controls.append({
                "control_id": control.get('ControlId', 'Unknown'),
                "standard": control.get('StandardName', 'Unknown'),
                "title": control.get('Title', 'Unknown'),
                "severity": control.get('SeverityRating', 'Unknown'),
                "description": control.get('Description', 'No description available'),
                "related_requirements": control.get('RelatedRequirements', [])
            })
        
        result = {
            "count": len(failed_controls),
            "controls": formatted_controls,
            "is_truncated": len(failed_controls) == limit
        }
        
        return json.dumps(result, default=lambda o: str(o))
    except Exception as e:
        logger.error(f"Error listing failed security standards: {e}")
        return json.dumps({
            "error": {
                "message": f"Error retrieving failed security standards: {str(e)}",
                "type": type(e).__name__
            }
        })


@register_tool()
async def get_account_security_score() -> str:
    """Get the overall security score for the AWS account.
    
    Returns:
        JSON formatted string with account security score
    """
    logger.info("Getting account security score")
    
    try:
        # Get SecurityHub client
        client = securityhub.get_securityhub_client()
        
        # Check if SecurityHub is enabled
        try:
            hub_response = client.describe_hub()
            if not hub_response:
                return json.dumps({
                    "message": "SecurityHub is not enabled in this region",
                    "standards_enabled": 0,
                    "score": None
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAccessException':
                return json.dumps({
                    "message": "SecurityHub is not enabled or insufficient permissions",
                    "standards_enabled": 0,
                    "score": None
                })
            raise
        
        # Get enabled standards
        standards_response = client.get_enabled_standards()
        standards = standards_response.get('StandardsSubscriptions', [])
        
        if not standards:
            return json.dumps({
                "message": "No security standards are enabled in SecurityHub",
                "standards_enabled": 0,
                "score": None
            })
        
        # Get findings to calculate score
        filters = {
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
            'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
        }
        
        findings = securityhub.get_all_findings(filters=filters, max_items=1000)
        
        # Calculate scores
        total_findings = len(findings)
        
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0
        }
        
        # Count findings by severity, with fallback for missing severity
        for finding in findings:
            severity = finding.get('Severity', {}).get('Label', 'INFORMATIONAL')
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                # Handle unexpected severity values
                logger.warning(f"Unknown severity level: {severity}")
                severity_counts['INFORMATIONAL'] += 1
        
        # Calculate weighted score
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 5,
            'MEDIUM': 3,
            'LOW': 1,
            'INFORMATIONAL': 0
        }
        
        total_weight = sum(
            severity_counts[severity] * severity_weights[severity]
            for severity in severity_counts
        )
        
        # Calculate maximum possible weight (if all findings were CRITICAL)
        max_possible_weight = total_findings * severity_weights['CRITICAL'] if total_findings > 0 else 1
        
        # Calculate score (higher is worse)
        raw_score = (total_weight / max_possible_weight) * 100 if max_possible_weight > 0 else 0
        
        # Invert score (higher is better) and ensure it's between 0-100
        security_score = max(0, min(100, 100 - raw_score))
        
        # Calculate additional metrics
        high_priority_findings = severity_counts['CRITICAL'] + severity_counts['HIGH']
        low_priority_findings = severity_counts['MEDIUM'] + severity_counts['LOW'] + severity_counts['INFORMATIONAL']
        
        # Format the results
        result = {
            "security_score": round(security_score, 1),
            "severity_distribution": severity_counts,
            "total_findings": total_findings,
            "high_priority_findings": high_priority_findings,
            "low_priority_findings": low_priority_findings,
            "standards_enabled": len(standards),
            "calculation_method": "Weighted severity score (CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1, INFO=0)",
            "standards": [{
                "name": standard.get('StandardsArn', '').split('/')[-1] if standard.get('StandardsArn') else 'Unknown',
                "status": standard.get('StandardsStatus', 'Unknown'),
                "subscription_arn": standard.get('StandardsSubscriptionArn', 'Unknown')[:50] + '...' if standard.get('StandardsSubscriptionArn') else 'Unknown'  # Truncate for readability
            } for standard in standards]
        }
        
        return json.dumps(result, default=lambda o: str(o))
    except Exception as e:
        logger.error(f"Error getting account security score: {e}")
        return json.dumps({
            "error": {
                "message": f"Error retrieving account security score: {str(e)}",
                "type": type(e).__name__
            }
        }) 