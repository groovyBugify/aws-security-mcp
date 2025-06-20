"""Athena service module for AWS Security MCP.

This module provides functions for interacting with AWS Athena for running SQL queries
on CloudTrail logs, VPC Flow Logs, and other security-related datasets.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
import time
import json

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from aws_security_mcp.services.base import get_client, handle_aws_error, format_pagination_response

# Configure logging
logger = logging.getLogger(__name__)

# Athena query execution states
QUERY_STATES = {
    'QUEUED': 'queued',
    'RUNNING': 'running', 
    'SUCCEEDED': 'succeeded',
    'FAILED': 'failed',
    'CANCELLED': 'cancelled'
}

def serialize_datetime_objects(obj: Any) -> Any:
    """Recursively convert datetime objects to ISO format strings for JSON serialization.
    
    Args:
        obj: Object that may contain datetime objects
        
    Returns:
        Object with datetime objects converted to strings
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {key: serialize_datetime_objects(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [serialize_datetime_objects(item) for item in obj]
    else:
        return obj

def list_data_catalogs(
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List all available data catalogs.

    Args:
        session_context: Optional session key for cross-account access
        max_items: Maximum number of catalogs to return
        next_token: Pagination token for next page of results

    Returns:
        Dict containing list of data catalogs with pagination info
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        params = {}
        
        if max_items:
            params['MaxResults'] = max_items
        if next_token:
            params['NextToken'] = next_token
            
        response = client.list_data_catalogs(**params)
        
        catalogs = response.get('DataCatalogsSummary', [])
        next_token = response.get('NextToken')
        
        # Convert datetime objects to strings for JSON serialization
        catalogs = serialize_datetime_objects(catalogs)
        
        return format_pagination_response(
            items=catalogs,
            next_token=next_token
        )
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error listing Athena data catalogs: {str(e)}")
        return format_pagination_response(items=[], next_token=None)

def list_databases(
    catalog_name: Optional[str] = None,
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List all databases in the specified data catalog.

    Args:
        catalog_name: Name of the data catalog (if None, defaults to AwsDataCatalog)
        session_context: Optional session key for cross-account access
        max_items: Maximum number of databases to return
        next_token: Pagination token for next page of results

    Returns:
        Dict containing list of databases with pagination info
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        # Default to AwsDataCatalog if not specified, but allow override
        if catalog_name is None:
            catalog_name = 'AwsDataCatalog'
        
        params = {
            'CatalogName': catalog_name
        }
        
        if max_items:
            params['MaxResults'] = max_items
        if next_token:
            params['NextToken'] = next_token
            
        response = client.list_databases(**params)
        
        databases = response.get('DatabaseList', [])
        next_token = response.get('NextToken')
        
        # Convert datetime objects to strings for JSON serialization
        databases = serialize_datetime_objects(databases)
        
        return format_pagination_response(
            items=databases,
            next_token=next_token
        )
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error listing Athena databases in catalog {catalog_name}: {str(e)}")
        return format_pagination_response(items=[], next_token=None)

def list_table_metadata(
    database_name: str,
    catalog_name: Optional[str] = None,
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None,
    expression: Optional[str] = None
) -> Dict[str, Any]:
    """List table metadata for tables in the specified database.

    Args:
        database_name: Name of the database
        catalog_name: Name of the data catalog (if None, defaults to AwsDataCatalog)
        session_context: Optional session key for cross-account access
        max_items: Maximum number of tables to return
        next_token: Pagination token for next page of results
        expression: Optional regex expression to filter table names

    Returns:
        Dict containing list of table metadata with pagination info
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        # Default to AwsDataCatalog if not specified, but allow override
        if catalog_name is None:
            catalog_name = 'AwsDataCatalog'
        
        params = {
            'CatalogName': catalog_name,
            'DatabaseName': database_name
        }
        
        if max_items:
            params['MaxResults'] = max_items
        if next_token:
            params['NextToken'] = next_token
        if expression:
            params['Expression'] = expression
            
        response = client.list_table_metadata(**params)
        
        tables = response.get('TableMetadataList', [])
        next_token = response.get('NextToken')
        
        # Convert datetime objects to strings for JSON serialization
        tables = serialize_datetime_objects(tables)
        
        return format_pagination_response(
            items=tables,
            next_token=next_token
        )
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error listing table metadata for database {database_name} in catalog {catalog_name}: {str(e)}")
        return format_pagination_response(items=[], next_token=None)

def get_table_metadata(
    database_name: str,
    table_name: str,
    catalog_name: Optional[str] = None,
    session_context: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Get detailed metadata for a specific table.

    Args:
        database_name: Name of the database
        table_name: Name of the table
        catalog_name: Name of the data catalog (if None, defaults to AwsDataCatalog)
        session_context: Optional session key for cross-account access

    Returns:
        Dict containing detailed table metadata or None if error
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        # Default to AwsDataCatalog if not specified, but allow override
        if catalog_name is None:
            catalog_name = 'AwsDataCatalog'
        
        response = client.get_table_metadata(
            CatalogName=catalog_name,
            DatabaseName=database_name,
            TableName=table_name
        )
        
        table_metadata = response.get('TableMetadata')
        
        # Convert datetime objects to strings for JSON serialization
        if table_metadata:
            table_metadata = serialize_datetime_objects(table_metadata)
        
        return table_metadata
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error getting table metadata for {catalog_name}.{database_name}.{table_name}: {str(e)}")
        return None

def start_query_execution(
    query_string: str,
    database: str,
    output_location: str,
    catalog_name: Optional[str] = None,
    workgroup: str = 'primary',
    description: Optional[str] = None,
    session_context: Optional[str] = None
) -> Optional[str]:
    """Start execution of an Athena SQL query.

    Args:
        query_string: The SQL query string to execute
        database: Database to run the query against
        output_location: S3 location for query results (s3://bucket/path/)
        catalog_name: Name of the data catalog (if None, defaults to AwsDataCatalog)
        workgroup: Athena workgroup to use (default: primary)
        description: Optional description for the query
        session_context: Optional session key for cross-account access

    Returns:
        Query execution ID if successful, None if error
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        # Default to AwsDataCatalog if not specified, but allow override
        if catalog_name is None:
            catalog_name = 'AwsDataCatalog'
        
        query_context = {
            'Database': database,
            'Catalog': catalog_name
        }
        
        result_configuration = {
            'OutputLocation': output_location
        }
        
        params = {
            'QueryString': query_string,
            'QueryExecutionContext': query_context,
            'ResultConfiguration': result_configuration,
            'WorkGroup': workgroup
        }
        
        if description:
            params['Description'] = description
            
        response = client.start_query_execution(**params)
        
        query_execution_id = response.get('QueryExecutionId')
        logger.info(f"Started Athena query execution: {query_execution_id} in catalog {catalog_name}")
        
        return query_execution_id
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error starting Athena query execution: {str(e)}")
        return None

def get_query_execution(
    query_execution_id: str,
    session_context: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Get the status and details of a query execution.

    Args:
        query_execution_id: The query execution ID
        session_context: Optional session key for cross-account access

    Returns:
        Dict containing query execution details or None if error
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        response = client.get_query_execution(
            QueryExecutionId=query_execution_id
        )
        
        query_execution = response.get('QueryExecution')
        
        # Convert datetime objects to strings for JSON serialization
        if query_execution:
            query_execution = serialize_datetime_objects(query_execution)
        
        return query_execution
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error getting query execution {query_execution_id}: {str(e)}")
        return None

def wait_for_query_completion(
    query_execution_id: str,
    max_wait_time: int = 300,
    poll_interval: int = 2,
    session_context: Optional[str] = None
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Wait for a query to complete execution.

    Args:
        query_execution_id: The query execution ID
        max_wait_time: Maximum time to wait in seconds (default: 300)
        poll_interval: Polling interval in seconds (default: 2)
        session_context: Optional session key for cross-account access

    Returns:
        Tuple of (final_status, query_execution_details)
    """
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        query_execution = get_query_execution(query_execution_id, session_context)
        
        if not query_execution:
            return 'ERROR', None
            
        status = query_execution.get('Status', {})
        state = status.get('State')
        
        if state in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
            logger.info(f"Query {query_execution_id} completed with status: {state}")
            return state, query_execution
            
        logger.debug(f"Query {query_execution_id} still {state}, waiting...")
        time.sleep(poll_interval)
    
    logger.warning(f"Query {query_execution_id} timed out after {max_wait_time} seconds")
    return 'TIMEOUT', get_query_execution(query_execution_id, session_context)

def get_query_results(
    query_execution_id: str,
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None,
    query_result_type: str = 'DATA_ROWS'
) -> Dict[str, Any]:
    """Get the results of a completed query execution.

    Args:
        query_execution_id: The query execution ID
        session_context: Optional session key for cross-account access
        max_items: Maximum number of result rows to return
        next_token: Pagination token for next page of results
        query_result_type: Type of result to return ('DATA_ROWS' or 'DATA_MANIFEST') - ignored if not supported

    Returns:
        Dict containing query results with pagination info
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        params = {
            'QueryExecutionId': query_execution_id
        }
        
        if max_items:
            params['MaxResults'] = max_items
        if next_token:
            params['NextToken'] = next_token
            
        # Try with QueryResultType first (newer boto3 versions)
        try:
            params['QueryResultType'] = query_result_type
            response = client.get_query_results(**params)
        except Exception as e:
            # Fall back to basic call if QueryResultType not supported
            if 'QueryResultType' in str(e):
                logger.warning(f"QueryResultType parameter not supported in this boto3 version, falling back to basic call")
                params.pop('QueryResultType', None)
                response = client.get_query_results(**params)
            else:
                raise e
        
        result_set = response.get('ResultSet', {})
        rows = result_set.get('Rows', [])
        next_token = response.get('NextToken')
        update_count = response.get('UpdateCount', 0)
        
        # Extract metadata about columns
        metadata = result_set.get('ResultSetMetadata', {})
        column_info = metadata.get('ColumnInfo', [])
        
        return {
            'items': rows,
            'next_token': next_token,
            'is_truncated': next_token is not None,
            'count': len(rows),
            'column_info': column_info,
            'metadata': metadata,
            'update_count': update_count,
            'query_result_type': query_result_type  # Note: May fallback to 'DATA_ROWS' if not supported
        }
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error getting query results for {query_execution_id} (type: {query_result_type}): {str(e)}")
        return format_pagination_response(items=[], next_token=None)

def get_query_results_paginated(
    query_execution_id: str,
    session_context: Optional[str] = None,
    query_result_type: str = 'DATA_ROWS'
) -> Dict[str, Any]:
    """Get all results from a query execution using AWS paginator.

    Args:
        query_execution_id: The query execution ID
        session_context: Optional session key for cross-account access
        query_result_type: Type of result to return ('DATA_ROWS' or 'DATA_MANIFEST') - ignored if not supported

    Returns:
        Dict containing all query results (unpaginated)
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        # Use AWS official paginator
        paginator = client.get_paginator('get_query_results')
        
        # Try with QueryResultType first (newer boto3 versions)
        try:
            page_iterator = paginator.paginate(
                QueryExecutionId=query_execution_id,
                QueryResultType=query_result_type
            )
        except Exception as e:
            # Fall back to basic call if QueryResultType not supported
            if 'QueryResultType' in str(e):
                logger.warning(f"QueryResultType parameter not supported in paginator, falling back to basic call")
                page_iterator = paginator.paginate(
                    QueryExecutionId=query_execution_id
                )
            else:
                raise e
        
        all_rows = []
        column_info = []
        metadata = {}
        update_count = 0
        
        for page in page_iterator:
            result_set = page.get('ResultSet', {})
            rows = result_set.get('Rows', [])
            all_rows.extend(rows)
            
            # Get metadata from first page
            if not column_info:
                metadata = result_set.get('ResultSetMetadata', {})
                column_info = metadata.get('ColumnInfo', [])
            
            # Get update count if available
            if page.get('UpdateCount'):
                update_count = page.get('UpdateCount', 0)
        
        return {
            'items': all_rows,
            'next_token': None,
            'is_truncated': False,
            'count': len(all_rows),
            'column_info': column_info,
            'metadata': metadata,
            'update_count': update_count,
            'query_result_type': query_result_type  # Note: May fallback to 'DATA_ROWS' if not supported
        }
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error getting paginated query results for {query_execution_id} (type: {query_result_type}): {str(e)}")
        return format_pagination_response(items=[], next_token=None)

def list_query_executions(
    workgroup: str = 'primary',
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List query executions in the specified workgroup.

    Args:
        workgroup: Athena workgroup name (default: primary)
        session_context: Optional session key for cross-account access
        max_items: Maximum number of executions to return
        next_token: Pagination token for next page of results

    Returns:
        Dict containing list of query executions with pagination info
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        params = {
            'WorkGroup': workgroup
        }
        
        if max_items:
            params['MaxResults'] = max_items
        if next_token:
            params['NextToken'] = next_token
            
        response = client.list_query_executions(**params)
        
        query_execution_ids = response.get('QueryExecutionIds', [])
        next_token = response.get('NextToken')
        
        return format_pagination_response(
            items=query_execution_ids,
            next_token=next_token
        )
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error listing query executions: {str(e)}")
        return format_pagination_response(items=[], next_token=None)

def execute_query_async(
    query_string: str,
    database: str,
    output_location: str,
    catalog_name: Optional[str] = None,
    workgroup: str = 'primary',
    description: Optional[str] = None,
    session_context: Optional[str] = None
) -> Dict[str, Any]:
    """Execute a query asynchronously and return execution ID immediately.

    This is the proper MCP approach - return the query execution ID immediately
    and let the client poll for status and results separately.

    Args:
        query_string: The SQL query string to execute
        database: Database to run the query against
        output_location: S3 location for query results
        catalog_name: Name of the data catalog (if None, defaults to AwsDataCatalog)
        workgroup: Athena workgroup to use (default: primary)
        description: Optional description for the query
        session_context: Optional session key for cross-account access

    Returns:
        Dict containing query execution ID and initial status
    """
    try:
        # Start query execution
        query_execution_id = start_query_execution(
            query_string=query_string,
            database=database,
            output_location=output_location,
            catalog_name=catalog_name,
            workgroup=workgroup,
            description=description,
            session_context=session_context
        )
        
        if not query_execution_id:
            return {
                'success': False,
                'error': 'Failed to start query execution',
                'query_execution_id': None,
                'status': 'FAILED'
            }
        
        # Get initial status
        query_execution = get_query_execution(query_execution_id, session_context)
        initial_status = 'QUEUED'
        
        if query_execution:
            status = query_execution.get('Status', {})
            initial_status = status.get('State', 'QUEUED')
        
        return {
            'success': True,
            'query_execution_id': query_execution_id,
            'status': initial_status,
            'message': f'Query submitted successfully. Use query_execution_id to check status and get results.'
        }
        
    except Exception as e:
        logger.error(f"Error executing query asynchronously: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'query_execution_id': None,
            'status': 'FAILED'
        }

def is_query_complete(
    query_execution_id: str,
    session_context: Optional[str] = None
) -> Tuple[bool, str, Optional[str]]:
    """Check if a query execution is complete and ready for results.

    Args:
        query_execution_id: The query execution ID
        session_context: Optional session key for cross-account access

    Returns:
        Tuple of (is_complete, status, error_message)
    """
    try:
        query_execution = get_query_execution(query_execution_id, session_context)
        
        if not query_execution:
            return False, 'ERROR', 'Query execution not found'
            
        status = query_execution.get('Status', {})
        state = status.get('State', 'UNKNOWN')
        
        if state in ['SUCCEEDED']:
            return True, state, None
        elif state in ['FAILED', 'CANCELLED']:
            error_msg = status.get('StateChangeReason', f'Query {state.lower()}')
            return True, state, error_msg
        else:
            # QUEUED, RUNNING
            return False, state, None
            
    except Exception as e:
        logger.error(f"Error checking query completion for {query_execution_id}: {str(e)}")
        return False, 'ERROR', str(e)

def stop_query_execution(
    query_execution_id: str,
    session_context: Optional[str] = None
) -> bool:
    """Stop a running query execution.

    Args:
        query_execution_id: The query execution ID to stop
        session_context: Optional session key for cross-account access

    Returns:
        True if successful, False otherwise
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        client.stop_query_execution(
            QueryExecutionId=query_execution_id
        )
        
        logger.info(f"Stopped query execution: {query_execution_id}")
        return True
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error stopping query execution {query_execution_id}: {str(e)}")
        return False

def list_workgroups(
    session_context: Optional[str] = None,
    max_items: Optional[int] = None,
    next_token: Optional[str] = None
) -> Dict[str, Any]:
    """List all Athena workgroups.

    Args:
        session_context: Optional session key for cross-account access
        max_items: Maximum number of workgroups to return
        next_token: Pagination token for next page of results

    Returns:
        Dict containing list of workgroups with pagination info
    """
    try:
        client = get_client('athena', session_context=session_context)
        
        params = {}
        
        if max_items:
            params['MaxResults'] = max_items
        if next_token:
            params['NextToken'] = next_token
            
        response = client.list_work_groups(**params)
        
        workgroups = response.get('WorkGroups', [])
        next_token = response.get('NextToken')
        
        # Convert datetime objects to strings for JSON serialization
        workgroups = serialize_datetime_objects(workgroups)
        
        return format_pagination_response(
            items=workgroups,
            next_token=next_token
        )
        
    except (ClientError, NoCredentialsError) as e:
        logger.error(f"Error listing Athena workgroups: {str(e)}")
        return format_pagination_response(items=[], next_token=None)

def validate_s3_output_location(output_location: str) -> Tuple[bool, Optional[str]]:
    """Validate S3 output location for Athena queries.

    Args:
        output_location: S3 output location to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not output_location:
        return False, "Output location cannot be empty"
    
    if not output_location.startswith('s3://'):
        return False, "Output location must be a valid S3 URI starting with 's3://' (e.g., s3://my-bucket/athena-results/)"
    
    # Basic S3 URI structure validation
    if output_location == 's3://':
        return False, "Output location must include bucket name (e.g., s3://my-bucket/athena-results/)"
    
    # Extract bucket and path
    s3_parts = output_location[5:].split('/', 1)  # Remove 's3://' prefix
    bucket_name = s3_parts[0]
    
    if not bucket_name:
        return False, "S3 bucket name cannot be empty in output location"
    
    # Validate bucket naming rules (basic check)
    if len(bucket_name) < 3 or len(bucket_name) > 63:
        return False, "S3 bucket name must be between 3 and 63 characters long"
    
    # Should end with / for directory-like structure
    if not output_location.endswith('/'):
        return False, "Output location should end with '/' to specify a directory (e.g., s3://my-bucket/athena-results/)"
    
    return True, None

def validate_query_parameters(
    query_string: str,
    database: str,
    output_location: str
) -> Tuple[bool, Optional[str]]:
    """Validate query parameters before execution.

    Allows safe read-only operations: SELECT, SHOW, DESCRIBE, EXPLAIN.
    Blocks potentially dangerous operations: DROP, DELETE, TRUNCATE, ALTER, CREATE, INSERT, UPDATE.

    Args:
        query_string: The SQL query string to validate
        database: Database name to validate
        output_location: S3 output location to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Basic validation
    if not query_string or not query_string.strip():
        return False, "Query string cannot be empty"
    
    if not database or not database.strip():
        return False, "Database name cannot be empty"
    
    # Validate S3 output location
    s3_valid, s3_error = validate_s3_output_location(output_location)
    if not s3_valid:
        return False, s3_error
    
    # Check for dangerous operations (basic safety)
    dangerous_keywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE', 'INSERT', 'UPDATE']
    query_upper = query_string.upper().strip()
    
    # Allow safe read-only operations for database exploration
    # SHOW: SHOW TABLES, SHOW DATABASES, SHOW COLUMNS FROM table, etc.
    # DESCRIBE/DESC: DESCRIBE table_name, DESC table_name
    # EXPLAIN: EXPLAIN SELECT ... (query planning)
    safe_read_operations = ['SHOW', 'DESCRIBE', 'DESC', 'EXPLAIN']
    
    # Check if query starts with a safe read operation
    is_safe_read_operation = any(query_upper.startswith(op) for op in safe_read_operations)
    
    # If it's not a safe read operation, check for dangerous keywords
    if not is_safe_read_operation:
        for keyword in dangerous_keywords:
            if keyword in query_upper:
                return False, f"Query contains potentially dangerous keyword: {keyword}. Only SELECT, SHOW, DESCRIBE, and EXPLAIN queries are allowed for security."
    
    # Recommend date/time filtering for CloudTrail and VPC Flow Logs
    if any(table in query_upper for table in ['CLOUDTRAIL', 'VPC_FLOW_LOGS', 'VPCFLOWLOGS']):
        if not any(date_filter in query_upper for date_filter in ['WHERE', 'LIMIT', 'DATE', 'TIMESTAMP']):
            return False, "Queries on CloudTrail/VPC Flow Logs should include date/time filters (WHERE year='2024' AND month='01') to limit result size and control costs"
    
    # Recommend LIMIT clause for large result sets
    if 'LIMIT' not in query_upper and not any(agg in query_upper for agg in ['COUNT(', 'SUM(', 'AVG(', 'GROUP BY']):
        logger.warning("Consider adding a LIMIT clause to prevent unexpectedly large result sets")
    
    return True, None 