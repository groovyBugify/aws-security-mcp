"""Access Analyzer tools for AWS Security MCP."""

import json
import logging
from typing import Dict, List, Optional, Any

from aws_security_mcp.services import access_analyzer
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)


@register_tool()
async def list_analyzers(session_context: Optional[str] = None) -> str:
    """List all IAM Access Analyzers in the account.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
    
    Returns:
        JSON string with Access Analyzers
        
    Examples:
        # Single account (default)
        list_analyzers()
        
        # Cross-account access
        list_analyzers(session_context="123456789012_aws_dev")
    """
    logger.info(f"Listing Access Analyzers (session_context={session_context})")
    
    try:
        analyzers = access_analyzer.list_analyzers(session_context=session_context)
        
        response = {
            "status": "success",
            "count": len(analyzers),
            "analyzers": analyzers
        }
        
        return json.dumps(response, default=str)
    except Exception as e:
        logger.error(f"Error listing Access Analyzers: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        })


@register_tool()
async def get_analyzer(analyzer_name: str, session_context: Optional[str] = None) -> str:
    """Get detailed information about a specific Access Analyzer.
    
    Args:
        analyzer_name: Name of the Access Analyzer
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with analyzer details
        
    Examples:
        # Single account (default)
        get_analyzer("MyAnalyzer")
        
        # Cross-account access
        get_analyzer("MyAnalyzer", session_context="123456789012_aws_dev")
    """
    logger.info(f"Getting analyzer details for {analyzer_name} (session_context={session_context})")
    
    try:
        analyzer = access_analyzer.get_analyzer(analyzer_name, session_context=session_context)
        
        response = {
            "status": "success",
            "analyzer": analyzer
        }
        
        return json.dumps(response, default=str)
    except Exception as e:
        logger.error(f"Error getting analyzer details: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        })


def _get_analyzer_arn(analyzer_name: str, session_context: Optional[str] = None) -> Optional[str]:
    """Helper function to get analyzer ARN from name.
    
    Args:
        analyzer_name: Name of the analyzer
        session_context: Optional session key for cross-account access
        
    Returns:
        Optional[str]: ARN of the analyzer if found, None otherwise
    """
    try:
        # First try to get the specific analyzer
        analyzer = access_analyzer.get_analyzer(analyzer_name, session_context=session_context)
        if analyzer and 'arn' in analyzer:
            return analyzer['arn']
        
        # If not found by direct lookup, try listing all analyzers
        analyzers = access_analyzer.list_analyzers(session_context=session_context)
        for analyzer in analyzers:
            if analyzer.get('name') == analyzer_name:
                return analyzer.get('arn')
                
        return None
    except Exception as e:
        logger.error(f"Error getting analyzer ARN: {e}")
        return None


@register_tool()
async def list_findings(analyzerArn: str, status: Optional[str] = None, next_token: Optional[str] = None, limit: int = 100, session_context: Optional[str] = None) -> str:
    """List findings from a specific IAM Access Analyzer.
    
    Args:
        analyzerArn: ARN of the Access Analyzer
        status: Optional filter for finding status (ACTIVE, ARCHIVED, RESOLVED)
        next_token: Pagination token for fetching the next set of results
        limit: Maximum number of findings to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with findings
        
    Examples:
        # Single account (default)
        list_findings("MyAnalyzer")
        
        # Cross-account access
        list_findings("MyAnalyzer", session_context="123456789012_aws_dev")
    """
    logger.info(f"Listing findings for analyzer {analyzerArn} (status={status}, next_token={next_token}, limit={limit}, session_context={session_context})")
    
    valid_statuses = ['ACTIVE', 'ARCHIVED', 'RESOLVED']
    
    if status and status not in valid_statuses:
        return json.dumps({
            "status": "error",
            "message": f"Invalid status. Valid statuses are: {', '.join(valid_statuses)}"
        })
    
    try:
        # If the input looks like a name rather than an ARN, try to resolve it
        if not analyzerArn.startswith('arn:aws:access-analyzer:'):
            resolved_arn = _get_analyzer_arn(analyzerArn, session_context)
            if resolved_arn:
                analyzerArn = resolved_arn
            else:
                return json.dumps({
                    "status": "error",
                    "message": f"Analyzer with name '{analyzerArn}' not found"
                })
        
        findings, response_next_token = access_analyzer.list_findings(
            analyzer_arn=analyzerArn, 
            status=status, 
            max_results=limit, 
            next_token=next_token,
            session_context=session_context
        )
        
        response = {
            "status": "success",
            "count": len(findings),
            "findings": findings,
            "pagination": {
                "next_token": response_next_token,
                "is_truncated": response_next_token is not None
            }
        }
        
        return json.dumps(response, default=str)
    except Exception as e:
        logger.error(f"Error listing findings: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Error listing findings for analyzer '{analyzerArn}': {str(e)}"
        })


@register_tool()
async def get_finding(analyzerArn: str, finding_id: str, session_context: Optional[str] = None) -> str:
    """Get detailed information about a specific Access Analyzer finding.
    
    Args:
        analyzerArn: ARN of the Access Analyzer
        finding_id: ID of the finding
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with finding details
        
    Examples:
        # Single account (default)
        get_finding("MyAnalyzer", "12345678-1234-1234-1234-123456789012")
        
        # Cross-account access
        get_finding("MyAnalyzer", "12345678-1234-1234-1234-123456789012", session_context="123456789012_aws_dev")
    """
    logger.info(f"Getting finding details for analyzer {analyzerArn}, finding {finding_id} (session_context={session_context})")
    
    try:
        # If the input looks like a name rather than an ARN, try to resolve it
        if not analyzerArn.startswith('arn:aws:access-analyzer:'):
            resolved_arn = _get_analyzer_arn(analyzerArn, session_context)
            if resolved_arn:
                analyzerArn = resolved_arn
            else:
                return json.dumps({
                    "status": "error",
                    "message": f"Analyzer with name '{analyzerArn}' not found"
                })
            
        finding = access_analyzer.get_finding(analyzerArn, finding_id, session_context=session_context)
        
        response = {
            "status": "success",
            "finding": finding
        }
        
        return json.dumps(response, default=str)
    except Exception as e:
        logger.error(f"Error getting finding details: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Error getting details for finding '{finding_id}': {str(e)}"
        })


@register_tool()
async def list_findings_by_category(
    analyzerArn: str, 
    resource_type: str,
    status: str = "ACTIVE",
    next_token: Optional[str] = None,
    limit: int = 100,
    session_context: Optional[str] = None
) -> str:
    """Get findings filtered by resource type category.
    
    Args:
        analyzerArn: ARN of the Access Analyzer
        resource_type: Resource type to filter by (e.g., AWS::S3::Bucket, AWS::SQS::Queue)
        status: Finding status filter (ACTIVE, ARCHIVED, RESOLVED)
        next_token: Pagination token for fetching the next set of results
        limit: Maximum number of findings to return
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        JSON string with findings for the specified category
        
    Examples:
        # Single account (default)
        list_findings_by_category("MyAnalyzer", "AWS::S3::Bucket")
        
        # Cross-account access
        list_findings_by_category("MyAnalyzer", "AWS::S3::Bucket", session_context="123456789012_aws_dev")
    """
    logger.info(f"Getting findings by category for analyzer {analyzerArn}, resource type {resource_type}, status {status}, next_token {next_token}, limit {limit} (session_context={session_context})")
    
    valid_statuses = ['ACTIVE', 'ARCHIVED', 'RESOLVED']
    
    if status and status not in valid_statuses:
        return json.dumps({
            "status": "error",
            "message": f"Invalid status. Valid statuses are: {', '.join(valid_statuses)}"
        })
    
    valid_resource_types = [
        'AWS::S3::Bucket',
        'AWS::IAM::Role',
        'AWS::SQS::Queue',
        'AWS::Lambda::Function',
        'AWS::Lambda::LayerVersion',
        'AWS::KMS::Key',
        'AWS::SecretsManager::Secret',
        'AWS::EFS::FileSystem',
        'AWS::EC2::Snapshot',
        'AWS::ECR::Repository',
        'AWS::RDS::DBSnapshot',
        'AWS::RDS::DBClusterSnapshot',
        'AWS::SNS::Topic',
        'AWS::S3Express::DirectoryBucket',
        'AWS::DynamoDB::Table',
        'AWS::DynamoDB::Stream',
        'AWS::IAM::User'
    ]
    
    if resource_type not in valid_resource_types:
        return json.dumps({
            "status": "error",
            "message": f"Invalid resource type. Valid types include: AWS::S3::Bucket, AWS::SQS::Queue, etc."
        })
    
    try:
        # If the input looks like a name rather than an ARN, try to resolve it
        if not analyzerArn.startswith('arn:aws:access-analyzer:'):
            resolved_arn = _get_analyzer_arn(analyzerArn, session_context)
            if resolved_arn:
                analyzerArn = resolved_arn
            else:
                return json.dumps({
                    "status": "error",
                    "message": f"Analyzer with name '{analyzerArn}' not found"
                })
            
        findings, response_next_token = access_analyzer.list_findings_by_category(
            analyzer_arn=analyzerArn,
            resource_type=resource_type,
            status=status,
            max_results=limit,
            next_token=next_token,
            session_context=session_context
        )
        
        response = {
            "status": "success",
            "count": len(findings),
            "resource_type": resource_type,
            "findings": findings,
            "pagination": {
                "next_token": response_next_token,
                "is_truncated": response_next_token is not None
            }
        }
        
        return json.dumps(response, default=str)
    except Exception as e:
        logger.error(f"Error getting findings by category: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Error getting findings for resource type '{resource_type}': {str(e)}"
        }) 