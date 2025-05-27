"""Access Analyzer Service Wrapper for AWS Security MCP.

This wrapper consolidates all Access Analyzer operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing Access Analyzer functions to reuse them
from aws_security_mcp.tools.access_analyzer_tools import (
    list_analyzers as _list_analyzers,
    get_analyzer as _get_analyzer,
    list_findings as _list_findings,
    get_finding as _get_finding,
    list_findings_by_category as _list_findings_by_category
)

logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects."""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def safe_json_dumps(data: Any, **kwargs) -> str:
    """Safely serialize data to JSON, handling datetime objects."""
    return json.dumps(data, cls=DateTimeEncoder, **kwargs)

@register_tool()
async def access_analyzer_security_operations(operation: str, **params) -> str:
    """Access Analyzer Security Operations Hub - Comprehensive external access analysis and security monitoring.
    
    🔍 ANALYZER MANAGEMENT:
    - list_analyzers: List all IAM Access Analyzers in the account
    - get_analyzer: Get detailed information about a specific Access Analyzer
    
    🔎 FINDINGS ANALYSIS:
    - list_findings: List findings from a specific IAM Access Analyzer with filtering
    - get_finding: Get detailed information about a specific Access Analyzer finding
    - list_findings_by_category: Get findings filtered by resource type category
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🔍 List all analyzers:
    operation="list_analyzers"
    
    🔍 Get analyzer details:
    operation="get_analyzer", analyzer_name="MyAnalyzer"
    
    🔎 List all findings:
    operation="list_findings", analyzerArn="arn:aws:access-analyzer:us-east-1:123456789012:analyzer/MyAnalyzer"
    
    🔎 List active findings:
    operation="list_findings", analyzerArn="MyAnalyzer", status="ACTIVE"
    
    🔎 List findings with pagination:
    operation="list_findings", analyzerArn="MyAnalyzer", status="ACTIVE", limit=50, next_token="token"
    
    🔎 Get specific finding:
    operation="get_finding", analyzerArn="MyAnalyzer", finding_id="12345678-1234-1234-1234-123456789012"
    
    🔎 List S3 bucket findings:
    operation="list_findings_by_category", analyzerArn="MyAnalyzer", resource_type="AWS::S3::Bucket"
    
    🔎 List IAM role findings:
    operation="list_findings_by_category", analyzerArn="MyAnalyzer", resource_type="AWS::IAM::Role", status="ACTIVE"
    
    🔎 List Lambda function findings:
    operation="list_findings_by_category", analyzerArn="MyAnalyzer", resource_type="AWS::Lambda::Function", limit=25
    
    Args:
        operation: The Access Analyzer operation to perform (see descriptions above)
        
        # Analyzer identification parameters:
        analyzer_name: Name of the Access Analyzer (required for get_analyzer)
        analyzerArn: ARN or name of the Access Analyzer (required for finding operations)
        
        # Finding identification parameters:
        finding_id: ID of the specific finding (required for get_finding)
        
        # Filtering parameters:
        status: Finding status filter (ACTIVE, ARCHIVED, RESOLVED)
        resource_type: Resource type to filter by (e.g., AWS::S3::Bucket, AWS::IAM::Role)
        
        # Pagination parameters:
        next_token: Pagination token for fetching the next set of results
        limit: Maximum number of findings to return (default: 100)
        
    Returns:
        JSON formatted response with operation results and Access Analyzer security insights
    """
    
    logger.info(f"Access Analyzer operation requested: {operation}")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_analyzers":
            result = await _list_analyzers()
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        elif operation == "get_analyzer":
            analyzer_name = params.get("analyzer_name")
            if not analyzer_name:
                return safe_json_dumps({
                    "error": "analyzer_name parameter is required for get_analyzer",
                    "usage": "operation='get_analyzer', analyzer_name='MyAnalyzer'"
                })
            
            result = await _get_analyzer(analyzer_name=analyzer_name)
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        elif operation == "list_findings":
            analyzerArn = params.get("analyzerArn")
            if not analyzerArn:
                return safe_json_dumps({
                    "error": "analyzerArn parameter is required for list_findings",
                    "usage": "operation='list_findings', analyzerArn='MyAnalyzer'"
                })
            
            status = params.get("status")
            next_token = params.get("next_token")
            limit = params.get("limit", 100)
            
            result = await _list_findings(
                analyzerArn=analyzerArn,
                status=status,
                next_token=next_token,
                limit=limit
            )
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        elif operation == "get_finding":
            analyzerArn = params.get("analyzerArn")
            finding_id = params.get("finding_id")
            
            if not analyzerArn:
                return safe_json_dumps({
                    "error": "analyzerArn parameter is required for get_finding",
                    "usage": "operation='get_finding', analyzerArn='MyAnalyzer', finding_id='12345678-1234-1234-1234-123456789012'"
                })
            
            if not finding_id:
                return safe_json_dumps({
                    "error": "finding_id parameter is required for get_finding",
                    "usage": "operation='get_finding', analyzerArn='MyAnalyzer', finding_id='12345678-1234-1234-1234-123456789012'"
                })
            
            result = await _get_finding(
                analyzerArn=analyzerArn,
                finding_id=finding_id
            )
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        elif operation == "list_findings_by_category":
            analyzerArn = params.get("analyzerArn")
            resource_type = params.get("resource_type")
            
            if not analyzerArn:
                return safe_json_dumps({
                    "error": "analyzerArn parameter is required for list_findings_by_category",
                    "usage": "operation='list_findings_by_category', analyzerArn='MyAnalyzer', resource_type='AWS::S3::Bucket'"
                })
            
            if not resource_type:
                return safe_json_dumps({
                    "error": "resource_type parameter is required for list_findings_by_category",
                    "usage": "operation='list_findings_by_category', analyzerArn='MyAnalyzer', resource_type='AWS::S3::Bucket'",
                    "valid_resource_types": [
                        "AWS::S3::Bucket", "AWS::IAM::Role", "AWS::SQS::Queue", 
                        "AWS::Lambda::Function", "AWS::KMS::Key", "AWS::SecretsManager::Secret",
                        "AWS::EFS::FileSystem", "AWS::EC2::Snapshot", "AWS::ECR::Repository",
                        "AWS::RDS::DBSnapshot", "AWS::SNS::Topic", "AWS::DynamoDB::Table"
                    ]
                })
            
            status = params.get("status", "ACTIVE")
            next_token = params.get("next_token")
            limit = params.get("limit", 100)
            
            result = await _list_findings_by_category(
                analyzerArn=analyzerArn,
                resource_type=resource_type,
                status=status,
                next_token=next_token,
                limit=limit
            )
            
            # Parse the JSON string result and return as safe JSON
            return safe_json_dumps(json.loads(result))
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_analyzers", "get_analyzer", "list_findings",
                "get_finding", "list_findings_by_category"
            ]
            
            return safe_json_dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_analyzers": "operation='list_analyzers'",
                    "get_analyzer": "operation='get_analyzer', analyzer_name='MyAnalyzer'",
                    "list_findings": "operation='list_findings', analyzerArn='MyAnalyzer'",
                    "get_finding": "operation='get_finding', analyzerArn='MyAnalyzer', finding_id='12345678-1234-1234-1234-123456789012'",
                    "list_findings_by_category": "operation='list_findings_by_category', analyzerArn='MyAnalyzer', resource_type='AWS::S3::Bucket'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in Access Analyzer operation '{operation}': {e}")
        return safe_json_dumps({
            "error": {
                "message": f"Error executing Access Analyzer operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_access_analyzer_operations() -> str:
    """Discover all available Access Analyzer operations with detailed usage examples.
    
    This tool provides comprehensive documentation of Access Analyzer operations available
    through the access_analyzer_security_operations tool, including parameter requirements
    and practical usage examples for external access analysis and security monitoring.
    
    Returns:
        Detailed catalog of Access Analyzer operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS IAM Access Analyzer",
        "description": "External access analysis and security monitoring for AWS resources",
        "wrapper_tool": "access_analyzer_security_operations",
        "supported_features": {
            "analyzer_management": "Manage and configure Access Analyzers for security monitoring",
            "findings_analysis": "Analyze and investigate external access findings",
            "resource_monitoring": "Monitor specific resource types for external access",
            "compliance_tracking": "Track compliance with least privilege access principles",
            "policy_validation": "Validate resource policies for unintended external access",
            "security_assessment": "Comprehensive security assessment of resource access patterns"
        },
        "operation_categories": {
            "analyzer_management": {
                "list_analyzers": {
                    "description": "List all IAM Access Analyzers in the account",
                    "parameters": {},
                    "examples": [
                        "access_analyzer_security_operations(operation='list_analyzers')"
                    ]
                },
                "get_analyzer": {
                    "description": "Get detailed information about a specific Access Analyzer",
                    "parameters": {
                        "analyzer_name": {"type": "str", "required": True, "description": "Name of the Access Analyzer"}
                    },
                    "examples": [
                        "access_analyzer_security_operations(operation='get_analyzer', analyzer_name='MyAnalyzer')",
                        "access_analyzer_security_operations(operation='get_analyzer', analyzer_name='OrganizationAnalyzer')"
                    ]
                }
            },
            "findings_analysis": {
                "list_findings": {
                    "description": "List findings from a specific IAM Access Analyzer with filtering",
                    "parameters": {
                        "analyzerArn": {"type": "str", "required": True, "description": "ARN or name of the Access Analyzer"},
                        "status": {"type": "str", "description": "Finding status filter (ACTIVE, ARCHIVED, RESOLVED)"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching the next set of results"},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of findings to return"}
                    },
                    "examples": [
                        "access_analyzer_security_operations(operation='list_findings', analyzerArn='MyAnalyzer')",
                        "access_analyzer_security_operations(operation='list_findings', analyzerArn='arn:aws:access-analyzer:us-east-1:123456789012:analyzer/MyAnalyzer', status='ACTIVE')",
                        "access_analyzer_security_operations(operation='list_findings', analyzerArn='MyAnalyzer', status='ACTIVE', limit=50)",
                        "access_analyzer_security_operations(operation='list_findings', analyzerArn='MyAnalyzer', next_token='pagination_token')"
                    ]
                },
                "get_finding": {
                    "description": "Get detailed information about a specific Access Analyzer finding",
                    "parameters": {
                        "analyzerArn": {"type": "str", "required": True, "description": "ARN or name of the Access Analyzer"},
                        "finding_id": {"type": "str", "required": True, "description": "ID of the specific finding"}
                    },
                    "examples": [
                        "access_analyzer_security_operations(operation='get_finding', analyzerArn='MyAnalyzer', finding_id='12345678-1234-1234-1234-123456789012')",
                        "access_analyzer_security_operations(operation='get_finding', analyzerArn='arn:aws:access-analyzer:us-east-1:123456789012:analyzer/MyAnalyzer', finding_id='abcdef12-3456-7890-abcd-ef1234567890')"
                    ]
                },
                "list_findings_by_category": {
                    "description": "Get findings filtered by resource type category",
                    "parameters": {
                        "analyzerArn": {"type": "str", "required": True, "description": "ARN or name of the Access Analyzer"},
                        "resource_type": {"type": "str", "required": True, "description": "Resource type to filter by"},
                        "status": {"type": "str", "default": "ACTIVE", "description": "Finding status filter (ACTIVE, ARCHIVED, RESOLVED)"},
                        "next_token": {"type": "str", "description": "Pagination token for fetching the next set of results"},
                        "limit": {"type": "int", "default": 100, "description": "Maximum number of findings to return"}
                    },
                    "examples": [
                        "access_analyzer_security_operations(operation='list_findings_by_category', analyzerArn='MyAnalyzer', resource_type='AWS::S3::Bucket')",
                        "access_analyzer_security_operations(operation='list_findings_by_category', analyzerArn='MyAnalyzer', resource_type='AWS::IAM::Role', status='ACTIVE')",
                        "access_analyzer_security_operations(operation='list_findings_by_category', analyzerArn='MyAnalyzer', resource_type='AWS::Lambda::Function', limit=25)",
                        "access_analyzer_security_operations(operation='list_findings_by_category', analyzerArn='MyAnalyzer', resource_type='AWS::SQS::Queue', status='ARCHIVED')"
                    ]
                }
            }
        },
        "supported_resource_types": [
            "AWS::S3::Bucket",
            "AWS::IAM::Role", 
            "AWS::SQS::Queue",
            "AWS::Lambda::Function",
            "AWS::Lambda::LayerVersion",
            "AWS::KMS::Key",
            "AWS::SecretsManager::Secret",
            "AWS::EFS::FileSystem",
            "AWS::EC2::Snapshot",
            "AWS::ECR::Repository",
            "AWS::RDS::DBSnapshot",
            "AWS::RDS::DBClusterSnapshot",
            "AWS::SNS::Topic",
            "AWS::S3Express::DirectoryBucket",
            "AWS::DynamoDB::Table",
            "AWS::DynamoDB::Stream",
            "AWS::IAM::User"
        ],
        "access_analyzer_security_insights": {
            "common_operations": [
                "List all analyzers: operation='list_analyzers'",
                "Get analyzer details: operation='get_analyzer', analyzer_name='MyAnalyzer'",
                "List active findings: operation='list_findings', analyzerArn='MyAnalyzer', status='ACTIVE'",
                "Get S3 bucket findings: operation='list_findings_by_category', analyzerArn='MyAnalyzer', resource_type='AWS::S3::Bucket'"
            ],
            "security_monitoring_patterns": [
                "Monitor for unintended external access to S3 buckets",
                "Track IAM roles accessible from outside the organization",
                "Identify Lambda functions with external invoke permissions",
                "Monitor KMS keys with external access grants",
                "Review SQS queues accessible from external accounts",
                "Check Secrets Manager secrets with cross-account access",
                "Monitor EFS file systems with external mount permissions",
                "Track EC2 snapshots shared with external accounts",
                "Review ECR repositories with external push/pull access"
            ],
            "security_best_practices": [
                "Regularly review and remediate ACTIVE findings",
                "Use organization-level analyzers for comprehensive coverage",
                "Set up automated alerts for new external access findings",
                "Implement least privilege access principles for all resources",
                "Archive resolved findings after proper validation",
                "Monitor findings by resource type for targeted security reviews",
                "Use Access Analyzer for continuous compliance monitoring",
                "Integrate findings into security incident response workflows",
                "Regularly audit analyzer configurations and coverage",
                "Document legitimate external access patterns for reference"
            ],
            "compliance_considerations": [
                "Ensure all external access is documented and justified",
                "Regularly audit findings for regulatory compliance",
                "Implement approval processes for external access grants",
                "Maintain audit logs of all finding remediation actions",
                "Use findings data for compliance reporting and metrics",
                "Monitor for changes in external access patterns",
                "Ensure proper segregation of duties in access management",
                "Implement break-glass procedures with proper monitoring"
            ],
            "finding_prioritization": [
                "Prioritize ACTIVE findings over ARCHIVED or RESOLVED",
                "Focus on high-risk resource types (S3, IAM roles, KMS keys)",
                "Review findings with broad external access first",
                "Investigate unexpected or unauthorized external access",
                "Monitor for patterns indicating potential security incidents",
                "Prioritize findings affecting production resources",
                "Review findings with elevated permissions or sensitive data access",
                "Focus on recently created findings for timely remediation"
            ],
            "integration_opportunities": [
                "Integrate with AWS Config for automated remediation",
                "Connect to SIEM systems for security monitoring",
                "Use with AWS Security Hub for centralized findings management",
                "Integrate with ticketing systems for finding remediation tracking",
                "Connect to notification services for real-time alerts",
                "Use with AWS Lambda for automated finding processing",
                "Integrate with compliance management tools",
                "Connect to infrastructure-as-code pipelines for preventive controls"
            ],
            "performance_optimization": [
                "Use pagination for large finding sets",
                "Filter by status to focus on actionable findings",
                "Use resource type filters for targeted analysis",
                "Implement caching for frequently accessed analyzer data",
                "Monitor API rate limits and implement backoff strategies",
                "Use batch operations where possible for efficiency"
            ]
        }
    }
    
    return safe_json_dumps(operations_catalog, indent=2) 