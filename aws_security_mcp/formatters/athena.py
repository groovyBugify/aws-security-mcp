"""Athena formatter module for AWS Security MCP.

This module provides functions to format Athena query results and metadata
for better readability and security analysis.
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

def format_data_catalog_simple(catalog: Dict[str, Any]) -> Dict[str, Any]:
    """Format a data catalog into a simplified representation.
    
    Args:
        catalog: Raw data catalog data from AWS Athena
    
    Returns:
        Dict containing simplified catalog representation
    """
    try:
        return {
            'name': catalog.get('Name'),
            'type': catalog.get('Type'),
            'description': catalog.get('Description'),
            'parameters': catalog.get('Parameters', {})
        }
    except Exception as e:
        logger.error(f"Error formatting simple catalog info: {str(e)}")
        return catalog  # Return original data if formatting fails

def format_database_simple(database: Dict[str, Any]) -> Dict[str, Any]:
    """Format a database into a simplified representation.
    
    Args:
        database: Raw database data from AWS Athena
    
    Returns:
        Dict containing simplified database representation
    """
    try:
        return {
            'name': database.get('Name'),
            'description': database.get('Description'),
            'parameters': database.get('Parameters', {})
        }
    except Exception as e:
        logger.error(f"Error formatting simple database info: {str(e)}")
        return database  # Return original data if formatting fails

def format_table_metadata(table_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Format table metadata into a more readable format.
    
    Args:
        table_metadata: Raw table metadata from AWS Athena
    
    Returns:
        Dict containing formatted table metadata
    """
    try:
        formatted = {
            'name': table_metadata.get('Name'),
            'database_name': table_metadata.get('DatabaseName'),
            'owner': table_metadata.get('Owner'),
            'create_time': table_metadata.get('CreateTime'),
            'last_access_time': table_metadata.get('LastAccessTime'),
            'table_type': table_metadata.get('TableType'),
            'parameters': table_metadata.get('Parameters', {})
        }
        
        # Format storage descriptor
        storage_descriptor = table_metadata.get('StorageDescriptor', {})
        if storage_descriptor:
            formatted['storage'] = {
                'location': storage_descriptor.get('Location'),
                'input_format': storage_descriptor.get('InputFormat'),
                'output_format': storage_descriptor.get('OutputFormat'),
                'serde_info': storage_descriptor.get('SerdeInfo', {}),
                'compressed': storage_descriptor.get('Compressed', False),
                'number_of_buckets': storage_descriptor.get('NumberOfBuckets'),
                'bucket_columns': storage_descriptor.get('BucketColumns', []),
                'sort_columns': storage_descriptor.get('SortColumns', [])
            }
        
        # Format columns
        columns = storage_descriptor.get('Columns', [])
        if columns:
            formatted['columns'] = [
                {
                    'name': col.get('Name'),
                    'type': col.get('Type'),
                    'comment': col.get('Comment')
                }
                for col in columns
            ]
        
        # Format partition keys
        partition_keys = table_metadata.get('PartitionKeys', [])
        if partition_keys:
            formatted['partition_keys'] = [
                {
                    'name': pk.get('Name'),
                    'type': pk.get('Type'),
                    'comment': pk.get('Comment')
                }
                for pk in partition_keys
            ]
        
        return formatted
    
    except Exception as e:
        logger.error(f"Error formatting table metadata: {str(e)}")
        return table_metadata  # Return original data if formatting fails

def format_query_execution(query_execution: Dict[str, Any]) -> Dict[str, Any]:
    """Format query execution details into a more readable format.
    
    Args:
        query_execution: Raw query execution data from AWS Athena
    
    Returns:
        Dict containing formatted query execution details
    """
    try:
        formatted = {
            'query_execution_id': query_execution.get('QueryExecutionId'),
            'query_string': query_execution.get('Query'),
            'statement_type': query_execution.get('StatementType'),
            'workgroup': query_execution.get('WorkGroup')
        }
        
        # Format query execution context
        context = query_execution.get('QueryExecutionContext', {})
        if context:
            formatted['context'] = {
                'database': context.get('Database'),
                'catalog': context.get('Catalog')
            }
        
        # Format result configuration
        result_config = query_execution.get('ResultConfiguration', {})
        if result_config:
            formatted['result_configuration'] = {
                'output_location': result_config.get('OutputLocation'),
                'encryption_configuration': result_config.get('EncryptionConfiguration', {})
            }
        
        # Format status
        status = query_execution.get('Status', {})
        if status:
            formatted['status'] = {
                'state': status.get('State'),
                'state_change_reason': status.get('StateChangeReason'),
                'submission_datetime': status.get('SubmissionDateTime'),
                'completion_datetime': status.get('CompletionDateTime')
            }
            
            # Calculate execution time if available
            if status.get('SubmissionDateTime') and status.get('CompletionDateTime'):
                submission_time = status.get('SubmissionDateTime')
                completion_time = status.get('CompletionDateTime')
                
                if isinstance(submission_time, datetime) and isinstance(completion_time, datetime):
                    execution_time = (completion_time - submission_time).total_seconds()
                    formatted['status']['execution_time_seconds'] = execution_time
        
        # Format statistics
        statistics = query_execution.get('Statistics', {})
        if statistics:
            formatted['statistics'] = {
                'engine_execution_time_ms': statistics.get('EngineExecutionTimeInMillis'),
                'data_processed_bytes': statistics.get('DataProcessedInBytes'),
                'data_scanned_bytes': statistics.get('DataScannedInBytes'),
                'query_queue_time_ms': statistics.get('QueryQueueTimeInMillis'),
                'query_planning_time_ms': statistics.get('QueryPlanningTimeInMillis'),
                'service_processing_time_ms': statistics.get('ServiceProcessingTimeInMillis'),
                'total_execution_time_ms': statistics.get('TotalExecutionTimeInMillis')
            }
        
        return formatted
    
    except Exception as e:
        logger.error(f"Error formatting query execution: {str(e)}")
        return query_execution  # Return original data if formatting fails

def format_query_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """Format query results into a more readable format.
    
    Args:
        results: Raw query results from AWS Athena
    
    Returns:
        Dict containing formatted query results
    """
    try:
        formatted = {
            'count': results.get('count', 0),
            'is_truncated': results.get('is_truncated', False),
            'next_token': results.get('next_token')
        }
        
        # Format column information
        column_info = results.get('column_info', [])
        if column_info:
            formatted['columns'] = [
                {
                    'name': col.get('Name'),
                    'type': col.get('Type'),
                    'label': col.get('Label'),
                    'schema_name': col.get('SchemaName'),
                    'table_name': col.get('TableName'),
                    'nullable': col.get('Nullable'),
                    'case_sensitive': col.get('CaseSensitive')
                }
                for col in column_info
            ]
        
        # Format rows
        rows = results.get('items', [])
        if rows and column_info:
            # First row is usually headers, skip it
            data_rows = rows[1:] if len(rows) > 1 else []
            
            formatted_rows = []
            for row in data_rows:
                row_data = row.get('Data', [])
                formatted_row = {}
                
                for i, col in enumerate(column_info):
                    col_name = col.get('Name', f'column_{i}')
                    col_value = row_data[i].get('VarCharValue') if i < len(row_data) else None
                    formatted_row[col_name] = col_value
                
                formatted_rows.append(formatted_row)
            
            formatted['rows'] = formatted_rows
            formatted['data_row_count'] = len(formatted_rows)
        else:
            formatted['rows'] = []
            formatted['data_row_count'] = 0
        
        return formatted
    
    except Exception as e:
        logger.error(f"Error formatting query results: {str(e)}")
        return results  # Return original data if formatting fails

def format_workgroup(workgroup: Dict[str, Any]) -> Dict[str, Any]:
    """Format a workgroup into a simplified representation.
    
    Args:
        workgroup: Raw workgroup data from AWS Athena
    
    Returns:
        Dict containing simplified workgroup representation
    """
    try:
        return {
            'name': workgroup.get('Name'),
            'description': workgroup.get('Description'),
            'state': workgroup.get('State'),
            'creation_time': workgroup.get('CreationTime')
        }
    except Exception as e:
        logger.error(f"Error formatting simple workgroup info: {str(e)}")
        return workgroup  # Return original data if formatting fails

def format_query_execution_summary(query_executions: List[str]) -> Dict[str, Any]:
    """Format a list of query execution IDs into a summary.
    
    Args:
        query_executions: List of query execution IDs
    
    Returns:
        Dict containing summary of query executions
    """
    try:
        return {
            'total_executions': len(query_executions),
            'execution_ids': query_executions
        }
    except Exception as e:
        logger.error(f"Error formatting query execution summary: {str(e)}")
        return {
            'total_executions': 0,
            'execution_ids': [],
            'error': str(e)
        }

def format_table_schema_summary(tables: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format a list of table metadata into a schema summary.
    
    Args:
        tables: List of table metadata dictionaries
    
    Returns:
        Dict containing database schema summary
    """
    try:
        formatted_tables = []
        
        for table in tables:
            formatted_table = {
                'name': table.get('Name'),
                'table_type': table.get('TableType'),
                'owner': table.get('Owner'),
                'create_time': table.get('CreateTime'),
                'column_count': 0,
                'partition_count': 0
            }
            
            # Count columns
            storage_descriptor = table.get('StorageDescriptor', {})
            columns = storage_descriptor.get('Columns', [])
            formatted_table['column_count'] = len(columns)
            
            # Count partition keys
            partition_keys = table.get('PartitionKeys', [])
            formatted_table['partition_count'] = len(partition_keys)
            
            # Add storage location if available
            if storage_descriptor.get('Location'):
                formatted_table['location'] = storage_descriptor.get('Location')
            
            formatted_tables.append(formatted_table)
        
        return {
            'total_tables': len(formatted_tables),
            'tables': formatted_tables
        }
    
    except Exception as e:
        logger.error(f"Error formatting table schema summary: {str(e)}")
        return {
            'total_tables': 0,
            'tables': [],
            'error': str(e)
        }

def format_data_catalog_simple(catalog: Dict[str, Any]) -> Dict[str, Any]:
    """Format a data catalog into a simplified representation.
    
    Args:
        catalog: Raw data catalog data from AWS Athena
    
    Returns:
        Dict containing simplified data catalog representation
    """
    try:
        return {
            'name': catalog.get('CatalogName'),
            'type': catalog.get('Type'),
            'description': catalog.get('Description'),
            'parameters': catalog.get('Parameters', {})
        }
    except Exception as e:
        logger.error(f"Error formatting simple data catalog info: {str(e)}")
        return catalog  # Return original data if formatting fails

def format_catalog_summary(catalogs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format a list of data catalogs into a summary.
    
    Args:
        catalogs: List of data catalog dictionaries
    
    Returns:
        Dict containing catalogs summary
    """
    try:
        formatted_catalogs = [format_data_catalog_simple(catalog) for catalog in catalogs]
        
        return {
            'total_catalogs': len(formatted_catalogs),
            'catalogs': formatted_catalogs
        }
    
    except Exception as e:
        logger.error(f"Error formatting catalog summary: {str(e)}")
        return {
            'total_catalogs': 0,
            'catalogs': [],
            'error': str(e)
        }

def format_database_summary(databases: List[Dict[str, Any]], catalog_name: Optional[str] = None) -> Dict[str, Any]:
    """Format a list of databases into a summary.
    
    Args:
        databases: List of database dictionaries
        catalog_name: Name of the catalog these databases belong to
    
    Returns:
        Dict containing databases summary
    """
    try:
        formatted_databases = [format_database_simple(db) for db in databases]
        
        result = {
            'total_databases': len(formatted_databases),
            'databases': formatted_databases
        }
        
        if catalog_name:
            result['catalog_name'] = catalog_name
        
        return result
    
    except Exception as e:
        logger.error(f"Error formatting database summary: {str(e)}")
        return {
            'total_databases': 0,
            'databases': [],
            'catalog_name': catalog_name,
            'error': str(e)
        }

def format_execution_results(execution_result: Dict[str, Any]) -> Dict[str, Any]:
    """Format the complete execution result with query details and results.
    
    Args:
        execution_result: Complete execution result from execute_query_and_wait
    
    Returns:
        Dict containing formatted execution results
    """
    try:
        formatted = {
            'success': execution_result.get('success', False),
            'query_execution_id': execution_result.get('query_execution_id'),
            'status': execution_result.get('status')
        }
        
        # Add error if present
        if execution_result.get('error'):
            formatted['error'] = execution_result.get('error')
        
        # Format query execution details
        query_execution = execution_result.get('query_execution')
        if query_execution:
            formatted['execution_details'] = format_query_execution(query_execution)
        
        # Format query results
        results = execution_result.get('results')
        if results:
            formatted['query_results'] = format_query_results(results)
        
        return formatted
    
    except Exception as e:
        logger.error(f"Error formatting execution results: {str(e)}")
        return execution_result  # Return original data if formatting fails

def generate_query_recommendations(query_string: str, database: str) -> List[Dict[str, str]]:
    """Generate recommendations for query optimization and security.
    
    Args:
        query_string: The SQL query string
        database: Database name
    
    Returns:
        List of recommendation dictionaries
    """
    recommendations = []
    query_upper = query_string.upper()
    
    try:
        # Check for date filtering on CloudTrail/VPC Flow Logs
        if any(table in query_upper for table in ['CLOUDTRAIL', 'VPC_FLOW_LOGS', 'VPCFLOWLOGS']):
            if not any(date_filter in query_upper for date_filter in ['WHERE', 'LIMIT', 'DATE', 'TIMESTAMP']):
                recommendations.append({
                    'type': 'performance',
                    'severity': 'high',
                    'title': 'Add date/time filters',
                    'description': 'CloudTrail and VPC Flow Logs tables can be very large. Add WHERE clauses with date/time filters to limit the data scanned and improve performance.'
                })
        
        # Check for LIMIT clause
        if 'LIMIT' not in query_upper:
            recommendations.append({
                'type': 'performance',
                'severity': 'medium',
                'title': 'Consider adding LIMIT clause',
                'description': 'Adding a LIMIT clause can help control the size of result sets and prevent unexpectedly large query results.'
            })
        
        # Check for SELECT *
        if 'SELECT *' in query_upper:
            recommendations.append({
                'type': 'performance',
                'severity': 'medium',
                'title': 'Avoid SELECT *',
                'description': 'Select only the columns you need instead of using SELECT * to reduce data transfer and improve query performance.'
            })
        
        # Check for partitioning hints
        if any(table in query_upper for table in ['CLOUDTRAIL', 'VPC_FLOW_LOGS', 'VPCFLOWLOGS']):
            if 'YEAR' not in query_upper and 'MONTH' not in query_upper and 'DAY' not in query_upper:
                recommendations.append({
                    'type': 'performance',
                    'severity': 'medium',
                    'title': 'Use partition pruning',
                    'description': 'Use partition columns (year, month, day) in your WHERE clause to take advantage of partition pruning and reduce data scanned.'
                })
        
        # Security recommendations
        if any(sensitive in query_upper for sensitive in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
            recommendations.append({
                'type': 'security',
                'severity': 'high',
                'title': 'Avoid exposing sensitive data',
                'description': 'Be careful when querying columns that might contain sensitive information like passwords, secrets, or tokens.'
            })
        
    except Exception as e:
        logger.error(f"Error generating query recommendations: {str(e)}")
        recommendations.append({
            'type': 'error',
            'severity': 'low',
            'title': 'Recommendation generation failed',
            'description': f'Could not generate recommendations: {str(e)}'
        })
    
    return recommendations 