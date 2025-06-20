"""ECS Service Wrapper for AWS Security MCP.

This wrapper consolidates all ECS operations into a single tool
while maintaining semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing ECS functions to reuse them
from aws_security_mcp.tools.ecs_tools import (
    list_ecs_clusters as _list_ecs_clusters,
    list_ecs_task_definitions as _list_ecs_task_definitions,
    get_ecs_task_definition as _get_ecs_task_definition,
    list_ecs_services as _list_ecs_services,
    list_ecs_tasks as _list_ecs_tasks,
    list_ecs_container_instances as _list_ecs_container_instances,
    get_ecs_service as _get_ecs_service,
    get_ecs_task as _get_ecs_task,
    search_ecs_services_by_ecr_repository as _search_ecs_services_by_ecr_repository
)

logger = logging.getLogger(__name__)

@register_tool()
async def ecs_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """ECS Security Operations Hub - Comprehensive container orchestration security monitoring.
    
    🏗️ CLUSTER MANAGEMENT:
    - list_clusters: List all ECS clusters with security configuration details
    
    📋 TASK DEFINITION ANALYSIS:
    - list_task_definitions: List task definitions with security configurations
    - get_task_definition: Get detailed task definition with security analysis
    
    🚀 SERVICE MONITORING:
    - list_services: List ECS services for a specific cluster with security details
    - get_service: Get detailed service information with security configuration
    
    📦 TASK MANAGEMENT:
    - list_tasks: List ECS tasks for cluster or service with security details
    - get_task: Get detailed task information with network and security configuration
    
    🖥️ INFRASTRUCTURE MONITORING:
    - list_container_instances: List container instances with security details
    
    🔍 ECR INTEGRATION:
    - search_services_by_ecr_repository: Find ECS services using a specific ECR repository
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🏗️ List all clusters:
    operation="list_clusters"
    
    📋 List all task definitions:
    operation="list_task_definitions"
    
    🔍 Get specific task definition:
    operation="get_task_definition", task_definition="my-app"
    
    🚀 List services in cluster:
    operation="list_services", cluster="my-cluster"
    
    📊 Get service details:
    operation="get_service", cluster="my-cluster", service="my-service"
    
    📦 List tasks in cluster:
    operation="list_tasks", cluster="my-cluster"
    
    🔍 List tasks for specific service:
    operation="list_tasks", cluster="my-cluster", service="my-service"
    
    📊 Get task details:
    operation="get_task", cluster="my-cluster", task="arn:aws:ecs:region:account:task/task-id"
    
    🖥️ List container instances:
    operation="list_container_instances", cluster="my-cluster"
    
    📋 Search task definitions by family:
    operation="list_task_definitions", family_prefix="web-app"
    
    🔍 Find services using ECR repository:
    operation="search_services_by_ecr_repository", repository_name="test-repo"
    
    🔍 Find services with limits (for large environments):
    operation="search_services_by_ecr_repository", repository_name="test-repo", max_clusters=5, max_services_per_cluster=20
    
    Args:
        operation: The ECS operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
        # Cluster parameters:
        cluster: ECS cluster name or ARN (required for cluster-specific operations)
        
        # Task definition parameters:
        task_definition: Task definition family name, ARN, or family:revision
        family_prefix: Family name prefix to filter task definitions
        status: Task definition status (ACTIVE or INACTIVE)
        
        # Service parameters:
        service: ECS service name or ARN
        
        # Task parameters:
        task: ECS task ARN or ID
        
        # ECR integration parameters:
        repository_name: ECR repository name to search for in services
        max_clusters: Maximum clusters to search (default: 10, prevents timeouts)
        max_services_per_cluster: Maximum services per cluster (default: 50, prevents timeouts)
        
    Returns:
        JSON formatted response with operation results and ECS security insights
    """
    
    logger.info(f"ECS operation requested: {operation} (session_context={session_context})")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_clusters":
            return json.dumps(await _list_ecs_clusters(session_context=session_context))
            
        elif operation == "list_task_definitions":
            family_prefix = params.get("family_prefix")
            status = params.get("status", "ACTIVE")
            
            return json.dumps(await _list_ecs_task_definitions(
                family_prefix=family_prefix,
                status=status,
                session_context=session_context
            ))
            
        elif operation == "get_task_definition":
            task_definition = params.get("task_definition")
            if not task_definition:
                return json.dumps({
                    "error": "task_definition parameter is required for get_task_definition",
                    "usage": "operation='get_task_definition', task_definition='my-app'"
                })
            
            cluster = params.get("cluster")
            return json.dumps(await _get_ecs_task_definition(
                task_definition=task_definition,
                cluster=cluster,
                session_context=session_context
            ))
            
        elif operation == "list_services":
            cluster = params.get("cluster")
            if not cluster:
                return json.dumps({
                    "error": "cluster parameter is required for list_services",
                    "usage": "operation='list_services', cluster='my-cluster'"
                })
            
            return json.dumps(await _list_ecs_services(cluster=cluster, session_context=session_context))
            
        elif operation == "get_service":
            cluster = params.get("cluster")
            service = params.get("service")
            if not cluster or not service:
                return json.dumps({
                    "error": "Both cluster and service parameters are required for get_service",
                    "usage": "operation='get_service', cluster='my-cluster', service='my-service'"
                })
            
            return json.dumps(await _get_ecs_service(
                cluster=cluster,
                service=service,
                session_context=session_context
            ))
            
        elif operation == "list_tasks":
            cluster = params.get("cluster")
            if not cluster:
                return json.dumps({
                    "error": "cluster parameter is required for list_tasks",
                    "usage": "operation='list_tasks', cluster='my-cluster'"
                })
            
            service = params.get("service")
            return json.dumps(await _list_ecs_tasks(
                cluster=cluster,
                service=service,
                session_context=session_context
            ))
            
        elif operation == "get_task":
            cluster = params.get("cluster")
            task = params.get("task")
            if not cluster or not task:
                return json.dumps({
                    "error": "Both cluster and task parameters are required for get_task",
                    "usage": "operation='get_task', cluster='my-cluster', task='arn:aws:ecs:region:account:task/task-id'"
                })
            
            return json.dumps(await _get_ecs_task(
                cluster=cluster,
                task=task,
                session_context=session_context
            ))
            
        elif operation == "list_container_instances":
            cluster = params.get("cluster")
            if not cluster:
                return json.dumps({
                    "error": "cluster parameter is required for list_container_instances",
                    "usage": "operation='list_container_instances', cluster='my-cluster'"
                })
            
            return json.dumps(await _list_ecs_container_instances(cluster=cluster, session_context=session_context))
            
        elif operation == "search_services_by_ecr_repository":
            repository_name = params.get("repository_name")
            if not repository_name:
                return json.dumps({
                    "error": "repository_name parameter is required for search_services_by_ecr_repository",
                    "usage": "operation='search_services_by_ecr_repository', repository_name='test-repo'"
                })
            
            # Performance optimization parameters
            max_clusters = params.get("max_clusters", 10)
            max_services_per_cluster = params.get("max_services_per_cluster", 50)
            
            return json.dumps(await _search_ecs_services_by_ecr_repository(
                repository_name=repository_name,
                max_clusters=max_clusters,
                max_services_per_cluster=max_services_per_cluster,
                session_context=session_context
            ))
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_clusters", "list_task_definitions", "get_task_definition",
                "list_services", "get_service", "list_tasks", "get_task",
                "list_container_instances", "search_services_by_ecr_repository"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_clusters": "operation='list_clusters'",
                    "list_services": "operation='list_services', cluster='my-cluster'",
                    "get_task_definition": "operation='get_task_definition', task_definition='my-app'",
                    "search_services_by_ecr_repository": "operation='search_services_by_ecr_repository', repository_name='test-repo', max_clusters=5"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in ECS operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing ECS operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool()
async def discover_ecs_operations() -> str:
    """Discover all available ECS operations with detailed usage examples.
    
    This tool provides comprehensive documentation of ECS operations available
    through the ecs_security_operations tool, including parameter requirements
    and practical usage examples for container security monitoring.
    
    Returns:
        Detailed catalog of ECS operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS ECS (Elastic Container Service)",
        "description": "Container orchestration security monitoring and management",
        "wrapper_tool": "ecs_security_operations",
        "supported_features": {
            "clusters": "Monitor and analyze ECS cluster configurations",
            "task_definitions": "Analyze container security configurations and IAM roles",
            "services": "Monitor service deployment and network security",
            "tasks": "Track running containers and their security context",
            "container_instances": "Monitor underlying EC2 infrastructure"
        },
        "operation_categories": {
            "cluster_management": {
                "list_clusters": {
                    "description": "List all ECS clusters with security configuration details",
                    "parameters": {
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='list_clusters')",
                        "ecs_security_operations(operation='list_clusters', session_context='123456789012_aws_dev')"
                    ]
                }
            },
            "task_definition_analysis": {
                "list_task_definitions": {
                    "description": "List task definitions with security configurations",
                    "parameters": {
                        "family_prefix": {"type": "str", "description": "Optional family name prefix to filter task definitions"},
                        "status": {"type": "str", "default": "ACTIVE", "description": "Task definition status (ACTIVE or INACTIVE)"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='list_task_definitions')",
                        "ecs_security_operations(operation='list_task_definitions', family_prefix='web-app')",
                        "ecs_security_operations(operation='list_task_definitions', status='INACTIVE')",
                        "ecs_security_operations(operation='list_task_definitions', session_context='123456789012_aws_dev')"
                    ]
                },
                "get_task_definition": {
                    "description": "Get detailed task definition with security analysis",
                    "parameters": {
                        "task_definition": {"type": "str", "required": True, "description": "Task definition family name, ARN, or family:revision"},
                        "cluster": {"type": "str", "description": "Optional cluster name to check for running tasks"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='get_task_definition', task_definition='my-app')",
                        "ecs_security_operations(operation='get_task_definition', task_definition='my-app:1')",
                        "ecs_security_operations(operation='get_task_definition', task_definition='my-app', cluster='production')",
                        "ecs_security_operations(operation='get_task_definition', task_definition='my-app', session_context='123456789012_aws_dev')"
                    ]
                }
            },
            "service_monitoring": {
                "list_services": {
                    "description": "List ECS services for a specific cluster with security details",
                    "parameters": {
                        "cluster": {"type": "str", "required": True, "description": "ECS cluster name or ARN"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='list_services', cluster='my-cluster')",
                        "ecs_security_operations(operation='list_services', cluster='arn:aws:ecs:region:account:cluster/my-cluster')",
                        "ecs_security_operations(operation='list_services', cluster='my-cluster', session_context='123456789012_aws_dev')"
                    ]
                },
                "get_service": {
                    "description": "Get detailed service information with security configuration",
                    "parameters": {
                        "cluster": {"type": "str", "required": True, "description": "ECS cluster name or ARN"},
                        "service": {"type": "str", "required": True, "description": "ECS service name or ARN"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='get_service', cluster='my-cluster', service='my-service')",
                        "ecs_security_operations(operation='get_service', cluster='production', service='web-app')",
                        "ecs_security_operations(operation='get_service', cluster='my-cluster', service='my-service', session_context='123456789012_aws_dev')"
                    ]
                }
            },
            "task_management": {
                "list_tasks": {
                    "description": "List ECS tasks for cluster or service with security details",
                    "parameters": {
                        "cluster": {"type": "str", "required": True, "description": "ECS cluster name or ARN"},
                        "service": {"type": "str", "description": "Optional service name to filter tasks"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='list_tasks', cluster='my-cluster')",
                        "ecs_security_operations(operation='list_tasks', cluster='my-cluster', service='my-service')",
                        "ecs_security_operations(operation='list_tasks', cluster='my-cluster', session_context='123456789012_aws_dev')"
                    ]
                },
                "get_task": {
                    "description": "Get detailed task information with network and security configuration",
                    "parameters": {
                        "cluster": {"type": "str", "required": True, "description": "ECS cluster name or ARN"},
                        "task": {"type": "str", "required": True, "description": "ECS task ARN or ID"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='get_task', cluster='my-cluster', task='arn:aws:ecs:region:account:task/task-id')",
                        "ecs_security_operations(operation='get_task', cluster='production', task='1234567890abcdef')",
                        "ecs_security_operations(operation='get_task', cluster='my-cluster', task='task-id', session_context='123456789012_aws_dev')"
                    ]
                }
            },
            "infrastructure_monitoring": {
                "list_container_instances": {
                    "description": "List container instances with security details",
                    "parameters": {
                        "cluster": {"type": "str", "required": True, "description": "ECS cluster name or ARN"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='list_container_instances', cluster='my-cluster')",
                        "ecs_security_operations(operation='list_container_instances', cluster='production')",
                        "ecs_security_operations(operation='list_container_instances', cluster='my-cluster', session_context='123456789012_aws_dev')"
                    ]
                }
            },
            "ecr_integration": {
                "search_services_by_ecr_repository": {
                    "description": "Find ECS services that use a specific ECR repository (optimized for large environments)",
                    "parameters": {
                        "repository_name": {"type": "str", "required": True, "description": "Name of the ECR repository to search for"},
                        "max_clusters": {"type": "int", "default": 10, "description": "Maximum clusters to search (prevents timeouts)"},
                        "max_services_per_cluster": {"type": "int", "default": 50, "description": "Maximum services per cluster (prevents timeouts)"},
                        "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                    },
                    "examples": [
                        "ecs_security_operations(operation='search_services_by_ecr_repository', repository_name='test-repo')",
                        "ecs_security_operations(operation='search_services_by_ecr_repository', repository_name='my-app-backend', max_clusters=5)",
                        "ecs_security_operations(operation='search_services_by_ecr_repository', repository_name='api-server', max_clusters=3, max_services_per_cluster=20)",
                        "ecs_security_operations(operation='search_services_by_ecr_repository', repository_name='api-server', session_context='123456789012_aws_dev')"
                    ],
                    "use_cases": [
                        "Find which services might be affected by ECR repository vulnerabilities",
                        "Audit container image usage across your ECS infrastructure",
                        "Track deployment of specific container images",
                        "Security impact analysis for container updates",
                        "Optimized search for large environments with many clusters/services"
                    ]
                }
            }
        },
        "ecs_security_insights": {
            "common_operations": [
                "List all clusters: operation='list_clusters'",
                "List services in cluster: operation='list_services', cluster='my-cluster'",
                "Get task definition details: operation='get_task_definition', task_definition='my-app'",
                "Monitor running tasks: operation='list_tasks', cluster='my-cluster'",
                "Find services using ECR repo: operation='search_services_by_ecr_repository', repository_name='test-repo'"
            ],
            "security_monitoring_patterns": [
                "Audit task definition IAM roles and execution roles",
                "Review container security configurations (privileged mode, capabilities)",
                "Monitor network modes and security group configurations",
                "Check secrets and environment variable handling",
                "Validate logging configurations for audit trails",
                "Monitor resource limits and container isolation",
                "Track ECR repository usage across services for vulnerability impact analysis"
            ],
            "security_best_practices": [
                "Use task IAM roles instead of container-level AWS credentials",
                "Avoid privileged containers unless absolutely necessary",
                "Implement proper secrets management with AWS Secrets Manager",
                "Use awslogs driver for centralized logging",
                "Configure appropriate security groups for tasks",
                "Enable CloudTrail for ECS API call monitoring",
                "Use Fargate for improved container isolation",
                "Implement network segmentation with VPC and subnets",
                "Regularly scan ECR repositories and update affected services"
            ],
            "compliance_considerations": [
                "Ensure containers don't run as root user when possible",
                "Validate that sensitive data is not passed via environment variables",
                "Check that containers use read-only file systems where appropriate",
                "Audit network configurations for proper isolation",
                "Monitor container image sources and vulnerability scanning",
                "Ensure proper logging and monitoring for compliance requirements",
                "Track container image lineage and deployment patterns"
            ],
            "cost_and_performance": [
                "Monitor CPU and memory utilization for right-sizing",
                "Review task placement strategies for optimal resource usage",
                "Analyze service scaling patterns and auto-scaling configurations",
                "Check for unused or idle services and task definitions"
            ],
            "ecr_integration_benefits": [
                "Quickly identify services affected by ECR repository vulnerabilities",
                "Audit container image usage across your ECS infrastructure",
                "Track deployment patterns and container image lineage",
                "Enable rapid response to security incidents in container images",
                "Simplify container image lifecycle management"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 