"""Athena tools module for AWS Security MCP.

This module provides tools for querying and analyzing CloudTrail logs, VPC Flow Logs,
and other security-related datasets using AWS Athena.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from aws_security_mcp.services import athena
from aws_security_mcp.formatters import athena as athena_formatter
from aws_security_mcp.tools import register_tool

# Configure logging
logger = logging.getLogger(__name__)

@register_tool("list_athena_catalogs")
async def list_athena_catalogs(
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List all available data catalogs in AWS Athena.

    This is essential for discovering CloudTrail and other security datasets
    that might be in different catalogs (not just AwsDataCatalog).

    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        max_items: Maximum number of catalogs to return
        next_token: Pagination token for next page of results

    Returns:
        Dict containing list of data catalogs with pagination info
    """
    try:
        logger.info("Listing Athena data catalogs")
        
        # Get catalogs from the service
        catalogs_response = athena.list_data_catalogs(
            session_context=session_context,
            max_items=max_items,
            next_token=next_token
        )
        
        catalogs = catalogs_response.get('items', [])
        
        # Format catalogs
        formatted_summary = athena_formatter.format_catalog_summary(catalogs)
        
        return {
            "catalogs": formatted_summary,
            "pagination": {
                "next_token": catalogs_response.get('next_token'),
                "is_truncated": catalogs_response.get('is_truncated', False),
                "count": catalogs_response.get('count', 0)
            },
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error listing Athena data catalogs: {str(e)}")
        return {
            "catalogs": {"total_catalogs": 0, "catalogs": []},
            "pagination": {"next_token": None, "is_truncated": False, "count": 0},
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool("list_athena_databases")
async def list_athena_databases(
    catalog_name: Optional[str] = None,
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List all databases in the specified AWS Athena data catalog.

    Args:
        catalog_name: Name of the data catalog (if None, defaults to AwsDataCatalog)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        max_items: Maximum number of databases to return
        next_token: Pagination token for next page of results

    Returns:
        Dict containing list of databases with pagination info
    """
    try:
        if catalog_name is None:
            catalog_name = 'AwsDataCatalog'
            
        logger.info(f"Listing Athena databases in catalog: {catalog_name}")
        
        # Get databases from the service
        databases_response = athena.list_databases(
            catalog_name=catalog_name,
            session_context=session_context,
            max_items=max_items,
            next_token=next_token
        )
        
        databases = databases_response.get('items', [])
        
        # Format databases
        formatted_summary = athena_formatter.format_database_summary(databases, catalog_name)
        
        return {
            "databases": formatted_summary,
            "pagination": {
                "next_token": databases_response.get('next_token'),
                "is_truncated": databases_response.get('is_truncated', False),
                "count": databases_response.get('count', 0)
            },
            "catalog_name": catalog_name,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error listing Athena databases in catalog {catalog_name}: {str(e)}")
        return {
            "databases": {"total_databases": 0, "databases": [], "catalog_name": catalog_name},
            "pagination": {"next_token": None, "is_truncated": False, "count": 0},
            "catalog_name": catalog_name,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool("get_athena_table_schema")
async def get_athena_table_schema(
    database_name: str,
    table_name: str,
    catalog_name: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get detailed schema information for a specific Athena table.

    Args:
        database_name: Name of the database containing the table
        table_name: Name of the table to get schema for
        catalog_name: Name of the data catalog (if None, defaults to AwsDataCatalog)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

    Returns:
        Dict containing detailed table schema information
    """
    try:
        if catalog_name is None:
            catalog_name = 'AwsDataCatalog'
            
        logger.info(f"Getting schema for table: {catalog_name}.{database_name}.{table_name}")
        
        # Get table metadata from the service
        table_metadata = athena.get_table_metadata(
            database_name=database_name,
            table_name=table_name,
            catalog_name=catalog_name,
            session_context=session_context
        )
        
        if not table_metadata:
            return {
                "table_schema": None,
                "database_name": database_name,
                "table_name": table_name,
                "catalog_name": catalog_name,
                "scan_timestamp": datetime.utcnow().isoformat(),
                "error": "Table not found or access denied"
            }
        
        # Format table metadata
        formatted_schema = athena_formatter.format_table_metadata(table_metadata)
        
        return {
            "table_schema": formatted_schema,
            "database_name": database_name,
            "table_name": table_name,
            "catalog_name": catalog_name,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting table schema for {catalog_name}.{database_name}.{table_name}: {str(e)}")
        return {
            "table_schema": None,
            "database_name": database_name,
            "table_name": table_name,
            "catalog_name": catalog_name,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool("execute_athena_query")
async def execute_athena_query(
    query_string: str,
    database: str,
    output_location: Optional[str] = None,
    catalog_name: Optional[str] = None,
    workgroup: Optional[str] = None,
    description: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Execute an Athena SQL query asynchronously and return execution ID immediately.

    This follows the proper MCP pattern - the query is submitted and you get back
    a query_execution_id. Use get_athena_query_status and get_athena_query_results
    to check progress and retrieve results.

    Args:
        query_string: The SQL query string to execute
        database: Database to run the query against
        output_location: S3 location for query results (if None, uses default from config)
        catalog_name: Name of the data catalog (if None, uses default from config)
        workgroup: Athena workgroup to use (if None, uses default from config)
        description: Optional description for the query
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

    Returns:
        Dict containing query execution ID and initial status (use for polling)
    """
    try:
        logger.info(f"Executing Athena query in {database}")
        
        # Import config here to avoid circular imports
        from aws_security_mcp.config import config
        
        # Use config defaults if not specified (for validation)
        if output_location is None:
            output_location = config.athena.default_output_location
        if catalog_name is None:
            catalog_name = config.athena.default_catalog
        if workgroup is None:
            workgroup = config.athena.default_workgroup
        
        # Validate query parameters
        is_valid, error_message = athena.validate_query_parameters(
            query_string=query_string,
            database=database,
            output_location=output_location
        )
        
        if not is_valid:
            return {
                "success": False,
                "error": f"Query validation failed: {error_message}",
                "query_execution_id": None,
                "status": "VALIDATION_FAILED",
                "query_string": query_string,
                "database": database,
                "catalog_name": catalog_name,
                "recommendations": athena_formatter.generate_query_recommendations(query_string, database),
                "scan_timestamp": datetime.utcnow().isoformat()
            }
        
        # Execute query asynchronously
        execution_result = athena.execute_query_async(
            query_string=query_string,
            database=database,
            output_location=output_location,
            catalog_name=catalog_name,
            workgroup=workgroup,
            description=description,
            session_context=session_context
        )
        
        # Generate query recommendations
        recommendations = athena_formatter.generate_query_recommendations(query_string, database)
        
        # Return the execution result with additional context
        return {
            "success": execution_result.get("success", False),
            "query_execution_id": execution_result.get("query_execution_id"),
            "status": execution_result.get("status", "UNKNOWN"),
            "message": execution_result.get("message", ""),
            "error": execution_result.get("error"),
            "query_string": query_string,
            "database": database,
            "catalog_name": catalog_name,
            "output_location": output_location,
            "workgroup": workgroup,
            "recommendations": recommendations,
            "next_steps": [
                f"Use get_athena_query_status with query_execution_id='{execution_result.get('query_execution_id')}' to check progress",
                f"Once status is SUCCEEDED, use get_athena_query_results to retrieve data"
            ],
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error executing Athena query: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "query_execution_id": None,
            "status": "ERROR",
            "query_string": query_string,
            "database": database,
            "catalog_name": catalog_name or 'AwsDataCatalog',
            "recommendations": [],
            "scan_timestamp": datetime.utcnow().isoformat()
        }

@register_tool("get_athena_query_status")
async def get_athena_query_status(
    query_execution_id: str,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Get the status and details of an Athena query execution.

    Args:
        query_execution_id: The query execution ID to check status for
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

    Returns:
        Dict containing query execution status and details
    """
    try:
        logger.info(f"Getting status for Athena query: {query_execution_id}")
        
        # Get query execution from the service
        query_execution = athena.get_query_execution(
            query_execution_id=query_execution_id,
            session_context=session_context
        )
        
        if not query_execution:
            return {
                "query_status": None,
                "query_execution_id": query_execution_id,
                "scan_timestamp": datetime.utcnow().isoformat(),
                "error": "Query execution not found"
            }
        
        # Format query execution details
        formatted_execution = athena_formatter.format_query_execution(query_execution)
        
        return {
            "query_status": formatted_execution,
            "query_execution_id": query_execution_id,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting query status for {query_execution_id}: {str(e)}")
        return {
            "query_status": None,
            "query_execution_id": query_execution_id,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool("get_athena_query_results")
async def get_athena_query_results(
    query_execution_id: str,
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None,
    query_result_type: Optional[str] = None
) -> Dict[str, Any]:
    """Get the results of a completed Athena query execution.

    Args:
        query_execution_id: The query execution ID to get results for
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        max_items: Maximum number of result rows to return
        next_token: Pagination token for next page of results
        query_result_type: Type of result ('DATA_ROWS' or 'DATA_MANIFEST') - optional, defaults to 'DATA_ROWS'

    Returns:
        Dict containing query results with pagination info
    """
    try:
        logger.info(f"Getting results for Athena query: {query_execution_id} (type: {query_result_type})")
        
        # Check if query is complete first
        is_complete, status, error_msg = athena.is_query_complete(query_execution_id, session_context)
        
        if not is_complete:
            return {
                "query_results": None,
                "query_execution_id": query_execution_id,
                "status": status,
                "message": f"Query is not yet complete. Current status: {status}",
                "pagination": {"next_token": None, "is_truncated": False, "count": 0},
                "scan_timestamp": datetime.utcnow().isoformat()
            }
        
        if status != 'SUCCEEDED':
            return {
                "query_results": None,
                "query_execution_id": query_execution_id,
                "status": status,
                "error": error_msg or f"Query {status.lower()}",
                "pagination": {"next_token": None, "is_truncated": False, "count": 0},
                "scan_timestamp": datetime.utcnow().isoformat()
            }
        
        # Get query results from the service
        results_response = athena.get_query_results(
            query_execution_id=query_execution_id,
            session_context=session_context,
            max_items=max_items,
            next_token=next_token,
            query_result_type=query_result_type or 'DATA_ROWS'  # Will fallback gracefully if not supported
        )
        
        # Format query results
        formatted_results = athena_formatter.format_query_results(results_response)
        
        return {
            "query_results": formatted_results,
            "query_execution_id": query_execution_id,
            "status": status,
            "query_result_type": query_result_type or 'DATA_ROWS',
            "pagination": {
                "next_token": results_response.get('next_token'),
                "is_truncated": results_response.get('is_truncated', False),
                "count": results_response.get('count', 0)
            },
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting query results for {query_execution_id}: {str(e)}")
        return {
            "query_results": {
                "count": 0,
                "is_truncated": False,
                "next_token": None,
                "rows": [],
                "data_row_count": 0
            },
            "query_execution_id": query_execution_id,
            "status": "ERROR",
            "pagination": {"next_token": None, "is_truncated": False, "count": 0},
            "scan_timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@register_tool("check_athena_query_complete")
async def check_athena_query_complete(
    query_execution_id: str,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Check if an Athena query is complete and ready for results.

    This is a convenience function that tells you if a query is done
    and whether it succeeded or failed.

    Args:
        query_execution_id: The query execution ID to check
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")

    Returns:
        Dict indicating if query is complete and status
    """
    try:
        logger.info(f"Checking if Athena query is complete: {query_execution_id}")
        
        is_complete, status, error_msg = athena.is_query_complete(
            query_execution_id=query_execution_id,
            session_context=session_context
        )
        
        result = {
            "query_execution_id": query_execution_id,
            "is_complete": is_complete,
            "status": status,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        if error_msg:
            result["error"] = error_msg
        
        if is_complete and status == 'SUCCEEDED':
            result["message"] = "Query completed successfully. Results are ready to retrieve."
            result["next_steps"] = [
                f"Use get_athena_query_results with query_execution_id='{query_execution_id}' to get data"
            ]
        elif is_complete and status in ['FAILED', 'CANCELLED']:
            result["message"] = f"Query {status.lower()}. No results available."
        else:
            result["message"] = f"Query is still {status.lower()}. Please wait and check again."
        
        return result
    
    except Exception as e:
        logger.error(f"Error checking query completion for {query_execution_id}: {str(e)}")
        return {
            "query_execution_id": query_execution_id,
            "is_complete": False,
            "status": "ERROR",
            "error": str(e),
            "scan_timestamp": datetime.utcnow().isoformat()
        } 