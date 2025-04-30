"""Formatters for AWS Lambda resources.

This module provides JSON-based formatting functions for AWS Lambda resources
to make them more suitable for API responses and LLM consumption.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime


def format_lambda_function_json(lambda_function: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Lambda function into structured data for JSON output.
    
    Args:
        lambda_function: Lambda function data dictionary
        
    Returns:
        Dictionary with formatted Lambda function data
    """
    # Format the last modified date
    last_modified = lambda_function.get('LastModified', '')
    if isinstance(last_modified, datetime):
        last_modified = last_modified.isoformat()
    
    # Calculate memory allocation
    memory_size = lambda_function.get('MemorySize', 0)
    memory_display = f"{memory_size} MB"
    
    # Calculate code size in readable format
    code_size = lambda_function.get('CodeSize', 0)
    code_size_kb = code_size / 1024
    code_size_mb = code_size_kb / 1024
    
    if code_size_mb >= 1:
        code_size_display = f"{code_size_mb:.2f} MB"
    else:
        code_size_display = f"{code_size_kb:.2f} KB"
    
    # Format the timeout
    timeout = lambda_function.get('Timeout', 0)
    timeout_display = f"{timeout} seconds"
    
    # Get runtime and architecture
    runtime = lambda_function.get('Runtime', '')
    architectures = lambda_function.get('Architectures', [])
    arch_display = ', '.join(architectures) if architectures else 'x86_64'
    
    # VPC Configuration
    vpc_config = lambda_function.get('VpcConfig', {})
    vpc_enabled = bool(vpc_config.get('VpcId', ''))
    subnet_count = len(vpc_config.get('SubnetIds', []))
    security_group_count = len(vpc_config.get('SecurityGroupIds', []))
    
    # Check if function has any layers
    layers = lambda_function.get('Layers', [])
    layer_count = len(layers)
    layer_names = [layer.get('Arn', '').split(':')[-2] for layer in layers]
    
    return {
        "function_name": lambda_function.get('FunctionName', ''),
        "function_arn": lambda_function.get('FunctionArn', ''),
        "runtime": runtime,
        "role": lambda_function.get('Role', ''),
        "handler": lambda_function.get('Handler', ''),
        "code_size": code_size_display,
        "code_size_bytes": code_size,
        "timeout": timeout_display,
        "timeout_seconds": timeout,
        "memory": memory_display,
        "memory_mb": memory_size,
        "last_modified": last_modified,
        "description": lambda_function.get('Description', ''),
        "environment_variables": lambda_function.get('Environment', {}).get('Variables', {}),
        "architectures": arch_display,
        "state": lambda_function.get('State', ''),
        "last_update_status": lambda_function.get('LastUpdateStatus', ''),
        "vpc": {
            "enabled": vpc_enabled,
            "vpc_id": vpc_config.get('VpcId', ''),
            "subnet_count": subnet_count,
            "security_group_count": security_group_count
        },
        "layers": {
            "count": layer_count,
            "names": layer_names
        },
        "concurrency": {
            "reserved": lambda_function.get('ReservedConcurrentExecutions', 0)
        },
        "tracing_config": lambda_function.get('TracingConfig', {}).get('Mode', 'PassThrough'),
        "tags": lambda_function.get('Tags', {}),
        "function_url": lambda_function.get('FunctionUrl', {})
    }


def format_lambda_alias_json(alias: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Lambda alias into structured data for JSON output.
    
    Args:
        alias: Lambda alias data dictionary
        
    Returns:
        Dictionary with formatted Lambda alias data
    """
    # Format routing config if present
    routing_config = None
    if 'RoutingConfig' in alias and 'AdditionalVersionWeights' in alias['RoutingConfig']:
        routing_config = {
            "additional_version_weights": alias['RoutingConfig']['AdditionalVersionWeights']
        }
    
    return {
        "alias_name": alias.get('Name', ''),
        "alias_arn": alias.get('AliasArn', ''),
        "function_version": alias.get('FunctionVersion', ''),
        "description": alias.get('Description', ''),
        "routing_config": routing_config,
        "revision_id": alias.get('RevisionId', '')
    }


def format_lambda_event_source_mapping_json(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Lambda event source mapping into structured data for JSON output.
    
    Args:
        mapping: Lambda event source mapping data dictionary
        
    Returns:
        Dictionary with formatted Lambda event source mapping data
    """
    # Format dates
    created_date = mapping.get('CreationDate')
    if isinstance(created_date, datetime):
        created_date = created_date.isoformat()
    
    last_modified = mapping.get('LastModified')
    if isinstance(last_modified, datetime):
        last_modified = last_modified.isoformat()
    
    return {
        "uuid": mapping.get('UUID', ''),
        "function_arn": mapping.get('FunctionArn', ''),
        "event_source_arn": mapping.get('EventSourceArn', ''),
        "enabled": mapping.get('State', '') == 'Enabled',
        "batch_size": mapping.get('BatchSize', 0),
        "starting_position": mapping.get('StartingPosition', ''),
        "starting_position_timestamp": mapping.get('StartingPositionTimestamp', ''),
        "last_processing_result": mapping.get('LastProcessingResult', ''),
        "state": mapping.get('State', ''),
        "state_transition_reason": mapping.get('StateTransitionReason', ''),
        "maximum_retry_attempts": mapping.get('MaximumRetryAttempts', 0),
        "maximum_record_age_in_seconds": mapping.get('MaximumRecordAgeInSeconds', 0),
        "parallelization_factor": mapping.get('ParallelizationFactor', 0),
        "topics": mapping.get('Topics', []),
        "queues": mapping.get('Queues', []),
        "source_access_configurations": mapping.get('SourceAccessConfigurations', []),
        "created_date": created_date,
        "last_modified": last_modified
    }


def format_lambda_version_json(version: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Lambda version into structured data for JSON output.
    
    Args:
        version: Lambda version data dictionary
        
    Returns:
        Dictionary with formatted Lambda version data
    """
    # Format the last modified time
    last_modified = version.get('LastModified')
    if isinstance(last_modified, datetime):
        last_modified = last_modified.isoformat()
    
    return {
        "function_name": version.get('FunctionName', ''),
        "function_arn": version.get('FunctionArn', ''),
        "version": version.get('Version', ''),
        "description": version.get('Description', ''),
        "runtime": version.get('Runtime', ''),
        "code_size": version.get('CodeSize', 0),
        "timeout": version.get('Timeout', 0),
        "memory_size": version.get('MemorySize', 0),
        "last_modified": last_modified,
        "code_sha256": version.get('CodeSha256', ''),
        "architectures": version.get('Architectures', [])
    }


def format_lambda_layer_json(layer: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Lambda layer into structured data for JSON output.
    
    Args:
        layer: Lambda layer data dictionary
        
    Returns:
        Dictionary with formatted Lambda layer data
    """
    # Format the layer versions
    layer_versions = []
    for version in layer.get('LatestMatchingVersion', {}).get('LayerVersionArn', '').split(':'):
        if version.isdigit():
            layer_versions.append(int(version))
    
    # Format the creation date
    created_date = layer.get('LatestMatchingVersion', {}).get('CreatedDate')
    if isinstance(created_date, datetime):
        created_date = created_date.isoformat()
    
    return {
        "layer_name": layer.get('LayerName', ''),
        "layer_arn": layer.get('LayerArn', ''),
        "latest_version": max(layer_versions) if layer_versions else None,
        "description": layer.get('LatestMatchingVersion', {}).get('Description', ''),
        "created_date": created_date,
        "compatible_runtimes": layer.get('LatestMatchingVersion', {}).get('CompatibleRuntimes', []),
        "compatible_architectures": layer.get('LatestMatchingVersion', {}).get('CompatibleArchitectures', []),
        "license_info": layer.get('LatestMatchingVersion', {}).get('LicenseInfo', ''),
        "layer_version_arn": layer.get('LatestMatchingVersion', {}).get('LayerVersionArn', '')
    }


def format_lambda_functions_summary_json(functions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Format a summary of Lambda functions into structured data for JSON output.
    
    Args:
        functions: List of Lambda function data dictionaries
        
    Returns:
        Dictionary with summary statistics for Lambda functions
    """
    # Count runtimes
    runtimes = {}
    for function in functions:
        runtime = function.get('Runtime', 'Unknown')
        runtimes[runtime] = runtimes.get(runtime, 0) + 1
    
    # Calculate total code size
    total_code_size = sum(function.get('CodeSize', 0) for function in functions)
    
    # Find memory usage statistics
    memory_sizes = [function.get('MemorySize', 0) for function in functions]
    avg_memory = sum(memory_sizes) / len(memory_sizes) if memory_sizes else 0
    
    # VPC vs non-VPC functions
    vpc_functions = sum(1 for function in functions 
                         if function.get('VpcConfig', {}).get('VpcId'))
    
    # Function with environment variables
    with_env_vars = sum(1 for function in functions 
                         if function.get('Environment', {}).get('Variables'))
    
    return {
        "total_functions": len(functions),
        "runtimes": runtimes,
        "total_code_size_bytes": total_code_size,
        "avg_memory_size_mb": avg_memory,
        "vpc_functions": vpc_functions,
        "non_vpc_functions": len(functions) - vpc_functions,
        "with_environment_variables": with_env_vars,
        "without_environment_variables": len(functions) - with_env_vars
    }


def format_function_url_config_json(url_config: Dict[str, Any]) -> Dict[str, Any]:
    """Format a Lambda function URL configuration into structured data for JSON output.
    
    Args:
        url_config: Lambda function URL configuration dictionary
        
    Returns:
        Dictionary with formatted Lambda function URL configuration data
    """
    # Handle creation time
    creation_time = url_config.get('CreationTime')
    if isinstance(creation_time, datetime):
        creation_time = creation_time.isoformat()
    
    # Handle last modified time
    last_modified = url_config.get('LastModifiedTime')
    if isinstance(last_modified, datetime):
        last_modified = last_modified.isoformat()
    
    return {
        "function_url": url_config.get('FunctionUrl', ''),
        "function_arn": url_config.get('FunctionArn', ''),
        "auth_type": url_config.get('AuthType', ''),
        "cors": url_config.get('Cors', {}),
        "creation_time": creation_time,
        "last_modified": last_modified,
        "invoke_mode": url_config.get('InvokeMode', 'BUFFERED')
    }


def format_function_url_discrepancy_json(discrepancy_check: Dict[str, Any]) -> Dict[str, Any]:
    """Format Lambda function URL discrepancy check results into structured data for JSON output.
    
    Args:
        discrepancy_check: Lambda function URL discrepancy check results
        
    Returns:
        Dictionary with formatted Lambda function URL discrepancy check results
    """
    result = {
        "function_name": discrepancy_check.get('function_name', ''),
        "has_function_url": discrepancy_check.get('has_function_url', False),
        "has_function_url_policy": discrepancy_check.get('has_function_url_policy', False),
        "discrepancy_detected": discrepancy_check.get('discrepancy', False),
        "security_issue": False
    }
    
    # Add function URL if it exists
    if discrepancy_check.get('function_url'):
        result["function_url"] = discrepancy_check.get('function_url')
    
    # Add authentication type if available
    if discrepancy_check.get('auth_type'):
        result["auth_type"] = discrepancy_check.get('auth_type')
        # Mark as security issue if it's a public URL (NONE auth type)
        if discrepancy_check.get('auth_type') == 'NONE':
            result["security_issue"] = True
    
    # Add policy condition details if available
    policy_condition_details = discrepancy_check.get('policy_condition_details')
    if policy_condition_details:
        result["policy_conditions"] = {
            "has_conditions": any(condition.get('has_conditions', False) for condition in policy_condition_details),
            "details": []
        }
        
        # Format each condition result
        for condition in policy_condition_details:
            if condition.get('has_conditions'):
                condition_info = {
                    "types": condition.get('condition_types', []),
                    "restriction_level": condition.get('restriction_level', 'None'),
                    "potential_public_access": condition.get('potential_public_access', True)
                }
                
                # Add condition details if available
                if condition.get('details'):
                    condition_info["details"] = condition.get('details')
                
                result["policy_conditions"]["details"].append(condition_info)
        
        # Update security assessment based on conditions
        if result["policy_conditions"]["has_conditions"]:
            # Check if any conditions provide strong restrictions
            has_strong_restrictions = any(
                condition.get('restriction_level') == 'Strong' 
                for condition in policy_condition_details
            )
            
            # Lower security issue severity if strong conditions exist
            if has_strong_restrictions and result["security_issue"]:
                result["security_level"] = "Low"
                result["condition_note"] = "Policy has strong conditional restrictions that may limit access"
    
    # Add discrepancy type if there's a discrepancy
    if discrepancy_check.get('discrepancy'):
        result["discrepancy_type"] = discrepancy_check.get('discrepancy_type')
        
        # Provide description based on discrepancy type
        if discrepancy_check.get('discrepancy_type') == 'MISSING_POLICY':
            result["description"] = "Function URL exists but no policy explicitly grants access to it"
            # If auth type is NONE, this isn't necessarily a security issue
            if discrepancy_check.get('auth_type') == 'NONE':
                result["security_level"] = "Info"
            else:
                result["security_level"] = "Low"
        elif discrepancy_check.get('discrepancy_type') == 'MISSING_URL':
            result["description"] = "Policy grants access to function URL but no URL is configured"
            result["security_level"] = "Medium"
            result["security_issue"] = True
            result["recommendation"] = "Remove unused function URL permissions from the resource policy"
    
    return result