"""Athena Service Wrapper for AWS Security MCP.

This wrapper consolidates all AWS Athena operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing Athena functions to reuse them
from aws_security_mcp.tools.athena_tools import (
    list_athena_catalogs as _list_athena_catalogs,
    list_athena_databases as _list_athena_databases,
    get_athena_table_schema as _get_athena_table_schema,
    execute_athena_query as _execute_athena_query,
    get_athena_query_status as _get_athena_query_status,
    get_athena_query_results as _get_athena_query_results,
    check_athena_query_complete as _check_athena_query_complete
)

logger = logging.getLogger(__name__)

@register_tool()
async def athena_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """Athena Security Operations Hub - Comprehensive AWS Athena query engine for CloudTrail and VPC Flow Logs analysis.
    
    🗂️ CATALOG & DATABASE DISCOVERY:
    - list_catalogs: List all available data catalogs (essential for finding CloudTrail data)
    - list_databases: List all databases in a specific catalog
    - get_table_schema: Get detailed schema information for a specific table
    
    🚀 ASYNC QUERY EXECUTION:
    - execute_query: Submit SQL query and get execution ID immediately (proper MCP pattern)
    - get_query_status: Check status of a running or completed query
    - check_query_complete: Quick check if query is done and ready for results
    - get_query_results: Retrieve results from a completed query with pagination
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🗂️ List catalogs:
    operation="list_catalogs"
    
    🔍 List databases:
    operation="list_databases", catalog_name="AwsDataCatalog"
    
    📊 Get table schema:
    operation="get_table_schema", database_name="cloudtrail_logs", table_name="cloudtrail_events"
    
    🚀 Execute query (returns execution ID immediately):
    operation="execute_query", 
    query_string="SELECT eventname, sourceipaddress, eventtime FROM cloudtrail_events WHERE year='2024' AND month='01' AND day='15' LIMIT 100",
    database="cloudtrail_logs",
    output_location="s3://my-athena-results/queries/"
    
    🔄 Check if query is complete:
    operation="check_query_complete", query_execution_id="12345678-1234-1234-1234-123456789012"
    
    📋 Check query status:
    operation="get_query_status", query_execution_id="12345678-1234-1234-1234-123456789012"
    
    📈 Get query results:
    operation="get_query_results", query_execution_id="12345678-1234-1234-1234-123456789012", max_items=100
    
    Args:
        operation: The Athena operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access
        
        # Database discovery parameters:
        catalog_name: Data catalog name (default: AwsDataCatalog)
        database_name: Database name (required for table operations)
        table_name: Table name (required for schema operations)
        
        # Query execution parameters:
        query_string: SQL query to execute (required for query operations)
        database: Database to run query against (required for query operations)
        output_location: S3 location for results (required for query operations, format: s3://bucket/path/)
        workgroup: Athena workgroup (default: primary)
        description: Optional query description
        
        # Query status/results parameters:
        query_execution_id: Query execution ID (required for status/results operations)
        
        # Pagination parameters:
        max_items: Maximum items to return
        next_token: Pagination token for next page
        
    Returns:
        JSON formatted response with operation results and Athena insights
    """
    
    logger.info(f"Athena operation requested: {operation} (cross-account: {session_context is not None})")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_catalogs":
            max_items = params.get("max_items")
            next_token = params.get("next_token")
            
            result = await _list_athena_catalogs(
                session_context=session_context,
                max_items=max_items,
                next_token=next_token
            )
            return json.dumps(result)
            
        elif operation == "list_databases":
            catalog_name = params.get("catalog_name", "AwsDataCatalog")
            max_items = params.get("max_items")
            next_token = params.get("next_token")
            
            result = await _list_athena_databases(
                catalog_name=catalog_name,
                session_context=session_context,
                max_items=max_items,
                next_token=next_token
            )
            return json.dumps(result)
            
        elif operation == "get_table_schema":
            database_name = params.get("database_name")
            table_name = params.get("table_name")
            catalog_name = params.get("catalog_name", "AwsDataCatalog")
            
            if not database_name:
                return json.dumps({
                    "error": "database_name parameter is required for get_table_schema",
                    "usage": "operation='get_table_schema', database_name='my_database', table_name='my_table'"
                })
            
            if not table_name:
                return json.dumps({
                    "error": "table_name parameter is required for get_table_schema",
                    "usage": "operation='get_table_schema', database_name='my_database', table_name='my_table'"
                })
            
            result = await _get_athena_table_schema(
                database_name=database_name,
                table_name=table_name,
                catalog_name=catalog_name,
                session_context=session_context
            )
            return json.dumps(result)
            
        elif operation == "execute_query":
            query_string = params.get("query_string")
            database = params.get("database")
            output_location = params.get("output_location")
            catalog_name = params.get("catalog_name")
            workgroup = params.get("workgroup", "primary")
            description = params.get("description")
            
            if not query_string:
                return json.dumps({
                    "error": "query_string parameter is required for execute_query",
                    "usage": "operation='execute_query', query_string='SELECT ...', database='my_db', output_location='s3://bucket/path/'"
                })
            
            if not database:
                return json.dumps({
                    "error": "database parameter is required for execute_query",
                    "usage": "operation='execute_query', query_string='SELECT ...', database='my_db', output_location='s3://bucket/path/'"
                })
            
            if not output_location:
                return json.dumps({
                    "error": "output_location parameter is required for execute_query (format: s3://bucket/path/)",
                    "usage": "operation='execute_query', query_string='SELECT ...', database='my_db', output_location='s3://bucket/path/'"
                })
            
            result = await _execute_athena_query(
                query_string=query_string,
                database=database,
                output_location=output_location,
                catalog_name=catalog_name,
                workgroup=workgroup,
                description=description,
                session_context=session_context
            )
            return json.dumps(result)
            
        elif operation == "check_query_complete":
            query_execution_id = params.get("query_execution_id")
            
            if not query_execution_id:
                return json.dumps({
                    "error": "query_execution_id parameter is required for check_query_complete",
                    "usage": "operation='check_query_complete', query_execution_id='12345678-1234-1234-1234-123456789012'"
                })
            
            result = await _check_athena_query_complete(
                query_execution_id=query_execution_id,
                session_context=session_context
            )
            return json.dumps(result)
            
        elif operation == "get_query_status":
            query_execution_id = params.get("query_execution_id")
            
            if not query_execution_id:
                return json.dumps({
                    "error": "query_execution_id parameter is required for get_query_status",
                    "usage": "operation='get_query_status', query_execution_id='12345678-1234-1234-1234-123456789012'"
                })
            
            result = await _get_athena_query_status(
                query_execution_id=query_execution_id,
                session_context=session_context
            )
            return json.dumps(result)
            
        elif operation == "get_query_results":
            query_execution_id = params.get("query_execution_id")
            max_items = params.get("max_items")
            next_token = params.get("next_token")
            
            if not query_execution_id:
                return json.dumps({
                    "error": "query_execution_id parameter is required for get_query_results",
                    "usage": "operation='get_query_results', query_execution_id='12345678-1234-1234-1234-123456789012'"
                })
            
            result = await _get_athena_query_results(
                query_execution_id=query_execution_id,
                session_context=session_context,
                max_items=max_items,
                next_token=next_token
            )
            return json.dumps(result)
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_catalogs", "list_databases", "get_table_schema", "execute_query", 
                "check_query_complete", "get_query_status", "get_query_results"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_catalogs": "operation='list_catalogs'",
                    "list_databases": "operation='list_databases'",
                    "get_table_schema": "operation='get_table_schema', database_name='my_db', table_name='my_table'",
                    "execute_query": "operation='execute_query', query_string='SELECT ...', database='my_db', output_location='s3://bucket/path/'",
                    "check_query_complete": "operation='check_query_complete', query_execution_id='12345678-1234-1234-1234-123456789012'",
                    "get_query_status": "operation='get_query_status', query_execution_id='12345678-1234-1234-1234-123456789012'",
                    "get_query_results": "operation='get_query_results', query_execution_id='12345678-1234-1234-1234-123456789012'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in Athena operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing Athena operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params,
                "session_context_provided": session_context is not None
            }
        })

@register_tool()
async def discover_athena_operations(session_context: Optional[str] = None) -> str:
    """Discover all available AWS Athena operations with detailed usage examples.
    
    This tool provides comprehensive documentation of Athena operations available
    through the athena_security_operations tool, including parameter requirements
    and practical usage examples for CloudTrail and VPC Flow Logs analysis.
    
    Returns:
        Detailed catalog of Athena operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS Athena",
        "description": "Interactive query service for analyzing CloudTrail logs, VPC Flow Logs, and security datasets using SQL",
        "wrapper_tool": "athena_security_operations",
        "supported_features": {
            "database_discovery": "Discover available databases and table schemas in the data catalog",
            "query_execution": "Execute SQL queries on security datasets with built-in optimizations",
            "result_management": "Manage query results with pagination and status monitoring",
            "security_analysis": "Built-in query validation and security recommendations"
        },
        "operation_categories": {
            "database_discovery": {
                "list_databases": {
                    "description": "List all available databases in the Athena data catalog",
                    "parameters": {
                        "catalog_name": {"type": "str", "required": False, "default": "AwsDataCatalog", "description": "Data catalog name"},
                        "max_items": {"type": "int", "required": False, "description": "Maximum number of databases to return"},
                        "next_token": {"type": "str", "required": False, "description": "Pagination token for next page"}
                    },
                    "examples": [
                        "athena_security_operations(operation='list_databases')",
                        "athena_security_operations(operation='list_databases', catalog_name='AwsDataCatalog', max_items=50)"
                    ],
                    "returns": [
                        "Complete list of all databases in the catalog",
                        "Database names, descriptions, and parameters",
                        "Pagination information for large result sets"
                    ]
                },
                "get_table_schema": {
                    "description": "Get detailed schema information for a specific table including columns and partitions",
                    "parameters": {
                        "database_name": {"type": "str", "required": True, "description": "Database containing the table"},
                        "table_name": {"type": "str", "required": True, "description": "Table name to get schema for"},
                        "catalog_name": {"type": "str", "required": False, "default": "AwsDataCatalog", "description": "Data catalog name"}
                    },
                    "examples": [
                        "athena_security_operations(operation='get_table_schema', database_name='cloudtrail_logs', table_name='cloudtrail_events')",
                        "athena_security_operations(operation='get_table_schema', database_name='vpc_flow_logs', table_name='vpc_flow_logs_table')"
                    ],
                    "returns": [
                        "Complete table schema with column names, types, and comments",
                        "Partition key information for optimized querying",
                        "Storage format and location details",
                        "Table creation and access timestamps"
                    ]
                }
            },
            "query_execution": {
                "execute_query": {
                    "description": "Execute SQL query and wait for completion, returning results immediately",
                    "parameters": {
                        "query_string": {"type": "str", "required": True, "description": "SQL query to execute"},
                        "database": {"type": "str", "required": True, "description": "Database to run query against"},
                        "output_location": {"type": "str", "required": True, "description": "S3 location for results (s3://bucket/path/)"},
                        "catalog_name": {"type": "str", "required": False, "default": "AwsDataCatalog", "description": "Data catalog name"},
                        "workgroup": {"type": "str", "required": False, "default": "primary", "description": "Athena workgroup"},
                        "description": {"type": "str", "required": False, "description": "Optional query description"},
                        "max_wait_time": {"type": "int", "required": False, "default": 300, "description": "Maximum wait time in seconds"}
                    },
                    "examples": [
                        "athena_security_operations(operation='execute_query', query_string=\"SELECT eventname, sourceipaddress, eventtime FROM cloudtrail_events WHERE year='2024' AND month='01' AND day='15' LIMIT 100\", database='cloudtrail_logs', output_location='s3://my-results/queries/')",
                        "athena_security_operations(operation='execute_query', query_string=\"SELECT srcaddr, dstaddr, srcport, dstport FROM vpc_flow_logs WHERE year='2024' AND month='01' LIMIT 50\", database='vpc_logs', output_location='s3://my-results/queries/')"
                    ],
                    "returns": [
                        "Complete query execution results with formatted data",
                        "Query execution statistics (execution time, data scanned)",
                        "Query validation and performance recommendations",
                        "Error details if query fails"
                    ]
                },
                "start_query": {
                    "description": "Start SQL query execution without waiting for completion (for long-running queries)",
                    "parameters": {
                        "query_string": {"type": "str", "required": True, "description": "SQL query to execute"},
                        "database": {"type": "str", "required": True, "description": "Database to run query against"},
                        "output_location": {"type": "str", "required": True, "description": "S3 location for results (s3://bucket/path/)"},
                        "catalog_name": {"type": "str", "required": False, "default": "AwsDataCatalog", "description": "Data catalog name"},
                        "workgroup": {"type": "str", "required": False, "default": "primary", "description": "Athena workgroup"},
                        "description": {"type": "str", "required": False, "description": "Optional query description"}
                    },
                    "examples": [
                        "athena_security_operations(operation='start_query', query_string=\"SELECT * FROM cloudtrail_events WHERE year='2024' AND month='01'\", database='cloudtrail_logs', output_location='s3://my-results/queries/')",
                        "athena_security_operations(operation='start_query', query_string=\"SELECT * FROM vpc_flow_logs WHERE year='2024' LIMIT 10000\", database='vpc_logs', output_location='s3://my-results/queries/')"
                    ],
                    "returns": [
                        "Query execution ID for status monitoring",
                        "Initial query status (QUEUED)",
                        "Query validation results and recommendations",
                        "Success/failure status"
                    ]
                }
            },
            "result_management": {
                "get_query_status": {
                    "description": "Check the status and details of a running or completed query",
                    "parameters": {
                        "query_execution_id": {"type": "str", "required": True, "description": "Query execution ID to check status for"}
                    },
                    "examples": [
                        "athena_security_operations(operation='get_query_status', query_execution_id='12345678-1234-1234-1234-123456789012')"
                    ],
                    "returns": [
                        "Current query status (QUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED)",
                        "Query execution details and timestamps",
                        "Execution statistics (time, data processed/scanned)",
                        "Error details if query failed"
                    ]
                },
                "get_query_results": {
                    "description": "Retrieve results from a completed query with pagination support",
                    "parameters": {
                        "query_execution_id": {"type": "str", "required": True, "description": "Query execution ID to get results for"},
                        "max_items": {"type": "int", "required": False, "description": "Maximum number of result rows to return"},
                        "next_token": {"type": "str", "required": False, "description": "Pagination token for next page of results"}
                    },
                    "examples": [
                        "athena_security_operations(operation='get_query_results', query_execution_id='12345678-1234-1234-1234-123456789012')",
                        "athena_security_operations(operation='get_query_results', query_execution_id='12345678-1234-1234-1234-123456789012', max_items=100)"
                    ],
                    "returns": [
                        "Formatted query results with column names and data types",
                        "Structured data rows with proper column mapping",
                        "Pagination information for large result sets",
                        "Result metadata and statistics"
                    ]
                }
            }
        },
        "security_analysis_patterns": {
            "cloudtrail_analysis": [
                "Analyze API calls by user: SELECT useridentity.type, useridentity.principalid, eventname, COUNT(*) FROM cloudtrail_events WHERE year='2024' AND month='01' GROUP BY useridentity.type, useridentity.principalid, eventname ORDER BY COUNT(*) DESC LIMIT 100",
                "Find failed login attempts: SELECT sourceipaddress, useridentity.principalid, eventtime FROM cloudtrail_events WHERE eventname='ConsoleLogin' AND errorcode IS NOT NULL AND year='2024' AND month='01' LIMIT 100",
                "Monitor privilege escalation: SELECT useridentity.principalid, eventname, resources FROM cloudtrail_events WHERE eventname IN ('AttachUserPolicy', 'PutUserPolicy', 'CreateRole', 'AttachRolePolicy') AND year='2024' AND month='01' LIMIT 100",
                "Track resource creation: SELECT eventname, awsregion, resources, eventtime FROM cloudtrail_events WHERE eventname LIKE '%Create%' AND year='2024' AND month='01' AND day='15' LIMIT 100"
            ],
            "vpc_flow_logs_analysis": [
                "Analyze network traffic by protocol: SELECT protocol, COUNT(*) as connection_count, SUM(bytes) as total_bytes FROM vpc_flow_logs WHERE year='2024' AND month='01' GROUP BY protocol ORDER BY connection_count DESC LIMIT 50",
                "Find rejected connections: SELECT srcaddr, dstaddr, srcport, dstport, protocol FROM vpc_flow_logs WHERE action='REJECT' AND year='2024' AND month='01' AND day='15' LIMIT 100",
                "Monitor suspicious ports: SELECT srcaddr, dstaddr, dstport, COUNT(*) FROM vpc_flow_logs WHERE dstport IN (22, 3389, 1433, 3306) AND year='2024' AND month='01' GROUP BY srcaddr, dstaddr, dstport LIMIT 100",
                "Analyze traffic patterns: SELECT srcaddr, dstaddr, SUM(bytes) as total_bytes, COUNT(*) as connection_count FROM vpc_flow_logs WHERE year='2024' AND month='01' GROUP BY srcaddr, dstaddr ORDER BY total_bytes DESC LIMIT 50"
            ],
            "performance_optimization": [
                "Always include partition filters (year, month, day) in WHERE clauses",
                "Use LIMIT clauses to control result set size",
                "Select only required columns instead of SELECT *",
                "Use appropriate date/time ranges to minimize data scanned",
                "Consider using approximate functions (approx_distinct, approx_percentile) for large datasets"
            ],
            "query_best_practices": [
                "Include time-based filters for CloudTrail and VPC Flow Logs queries",
                "Use partition pruning with year/month/day columns",
                "Avoid SELECT * on large tables",
                "Use LIMIT to control result size",
                "Consider using CTEs (Common Table Expressions) for complex queries",
                "Use appropriate JOIN conditions to avoid cartesian products"
            ]
        },
        "common_use_cases": {
            "security_monitoring": [
                "Monitor API usage patterns and anomalies",
                "Analyze authentication and authorization events",
                "Track resource access and modifications",
                "Identify suspicious network traffic patterns",
                "Investigate security incidents and breaches"
            ],
            "compliance_reporting": [
                "Generate audit reports for API activities",
                "Monitor data access patterns for compliance",
                "Track administrative actions and changes",
                "Analyze network traffic for security compliance",
                "Generate evidence for security audits"
            ],
            "threat_detection": [
                "Detect unusual login patterns or locations",
                "Identify privilege escalation attempts",
                "Monitor for data exfiltration patterns",
                "Analyze network traffic for malicious activity",
                "Correlate events across multiple data sources"
            ]
        },
        "integration_patterns": {
            "with_other_aws_services": [
                "Combine with GuardDuty findings for enhanced threat detection",
                "Integrate with SecurityHub for centralized security monitoring",
                "Use with Config for compliance rule evaluation",
                "Correlate with IAM Access Analyzer findings",
                "Combine with AWS Organizations for multi-account analysis"
            ],
            "data_sources": [
                "CloudTrail logs for API activity analysis",
                "VPC Flow Logs for network traffic analysis",
                "AWS Config snapshots for resource configuration analysis",
                "ELB access logs for application traffic analysis",
                "S3 access logs for data access patterns"
            ]
        },
        "cost_optimization": {
            "query_optimization": [
                "Use partition pruning to reduce data scanned",
                "Select only required columns to minimize data transfer",
                "Use appropriate compression and file formats",
                "Implement query result caching where appropriate",
                "Monitor query costs and optimize expensive queries"
            ],
            "data_management": [
                "Implement lifecycle policies for old data",
                "Use appropriate storage classes for infrequently accessed data",
                "Optimize table partitioning strategies",
                "Consider data compression and columnar formats",
                "Monitor storage costs and optimize data retention"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 