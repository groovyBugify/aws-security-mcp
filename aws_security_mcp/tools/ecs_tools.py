"""MCP tools for AWS ECS (Elastic Container Service) security."""

import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.services import ecs
from aws_security_mcp.tools import register_tool
from aws_security_mcp.formatters.ecs_formatter import (
    format_ecs_service,
    format_ecs_task_definition,
    format_ecs_task,
    format_ecs_container_instance,
    format_ecs_cluster
)

logger = logging.getLogger(__name__)

@register_tool()
async def list_ecs_clusters(session_context: Optional[str] = None) -> Dict[str, Any]:
    """List all ECS clusters in the AWS account.
    
    This tool retrieves all ECS clusters and provides information about their
    configuration and security settings.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
    
    Returns:
        Dict containing ECS clusters information
    """
    logger.info(f"Listing ECS clusters (session_context={session_context})")
    result = await ecs.get_clusters(session_context=session_context)
    
    if result["success"]:
        # Apply security-focused formatting to reduce response size
        formatted_clusters = [format_ecs_cluster(cluster) for cluster in result.get("clusters", [])]
        result["clusters"] = formatted_clusters
    
    return result

@register_tool()
async def list_ecs_task_definitions(family_prefix: Optional[str] = None, status: str = "ACTIVE", session_context: Optional[str] = None) -> Dict[str, Any]:
    """List ECS task definitions with their security configurations.
    
    This tool retrieves all task definitions and extracts security-relevant configurations
    such as IAM roles, secrets, volumes, and network settings.
    
    Args:
        family_prefix: Optional family name prefix to filter task definitions
        status: Task definition status to filter by (ACTIVE or INACTIVE)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing task definitions with security information
    """
    logger.info(f"Listing ECS task definitions with status {status} (session_context={session_context})")
    result = await ecs.get_task_definitions(family_prefix, status, session_context=session_context)
    
    if result["success"]:
        # Apply security-focused formatting to reduce response size
        formatted_task_defs = [format_ecs_task_definition(task_def) for task_def in result.get("taskDefinitions", [])]
        result["taskDefinitions"] = formatted_task_defs
    
    return result

@register_tool()
async def get_ecs_task_definition(task_definition: str, cluster: Optional[str] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get detailed information about the latest active ECS task definition with running tasks.
    
    This tool focuses on finding task definitions that are currently in use. When a family
    name is provided without a specific revision, it will find the latest active revision
    that has running tasks. If no running tasks are found, it falls back to the latest revision.
    
    Args:
        task_definition: The task definition family name, ARN, or family:revision
        cluster: Optional cluster name to check for running tasks (if not provided, checks all clusters)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing detailed task definition information with a flag indicating if it has running tasks
    """
    logger.info(f"Getting active ECS task definition: {task_definition}" + (f" in cluster: {cluster}" if cluster else "") + f" (session_context={session_context})")
    result = await ecs.get_task_definition(task_definition, cluster, session_context=session_context)
    
    if result["success"] and result.get("taskDefinition"):
        # Apply security-focused formatting to reduce response size
        result["taskDefinition"] = format_ecs_task_definition(result["taskDefinition"])
    
    return result

@register_tool()
async def list_ecs_services(cluster: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List ECS services for a specific cluster with security details.
    
    This tool retrieves all services in the specified cluster and extracts security-relevant
    information such as network configuration, IAM roles, and load balancer settings.
    
    Args:
        cluster: The ECS cluster ARN or name
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing services with security information
    """
    logger.info(f"Listing ECS services for cluster: {cluster} (session_context={session_context})")
    result = await ecs.get_services(cluster, session_context=session_context)
    
    if result["success"]:
        # Apply security-focused formatting to reduce response size
        formatted_services = [format_ecs_service(service) for service in result.get("services", [])]
        result["services"] = formatted_services
    
    return result

@register_tool()
async def list_ecs_tasks(cluster: str, service: Optional[str] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List ECS tasks for a specific cluster or service with security details.
    
    This tool retrieves all tasks in the specified cluster or service and extracts
    security-relevant information such as task IAM roles, network configuration,
    and container details.
    
    Args:
        cluster: The ECS cluster ARN or name
        service: Optional service name to filter tasks
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing tasks with security information
    """
    logger.info(f"Listing ECS tasks for cluster: {cluster}" + (f" and service: {service}" if service else "") + f" (session_context={session_context})")
    result = await ecs.get_tasks(cluster, service, session_context=session_context)
    
    if result["success"]:
        # Apply security-focused formatting to reduce response size
        formatted_tasks = [format_ecs_task(task) for task in result.get("tasks", [])]
        result["tasks"] = formatted_tasks
    
    return result

@register_tool()
async def list_ecs_container_instances(cluster: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """List ECS container instances for a specific cluster with security details.
    
    This tool retrieves all container instances in the specified cluster and extracts
    security-relevant information such as EC2 instance details, agent status,
    and attached resources.
    
    Args:
        cluster: The ECS cluster ARN or name
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing container instances with security information
    """
    logger.info(f"Listing ECS container instances for cluster: {cluster} (session_context={session_context})")
    result = await ecs.get_container_instances(cluster, session_context=session_context)
    
    if result["success"]:
        # Apply security-focused formatting to reduce response size
        formatted_instances = [format_ecs_container_instance(instance) for instance in result.get("containerInstances", [])]
        result["containerInstances"] = formatted_instances
    
    return result

@register_tool()
async def get_ecs_service(cluster: str, service: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get detailed information about a specific ECS service.
    
    This tool retrieves comprehensive details about a specified service in a cluster
    including its network configuration, IAM roles, and security settings.
    
    Args:
        cluster: The ECS cluster ARN or name
        service: The service ARN or name
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing detailed service information
    """
    logger.info(f"Getting ECS service: {service} in cluster: {cluster} (session_context={session_context})")
    result = await ecs.get_service(cluster, service, session_context=session_context)
    
    if result["success"] and result.get("service"):
        # Apply security-focused formatting to reduce response size
        result["service"] = format_ecs_service(result["service"])
    
    return result

@register_tool()
async def get_ecs_task(cluster: str, task: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Get detailed information about a specific ECS task.
    
    This tool retrieves comprehensive details about a specified task in a cluster
    including its network interfaces, security groups, and container details.
    
    Args:
        cluster: The ECS cluster ARN or name
        task: The task ARN or ID
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing detailed task information
    """
    logger.info(f"Getting ECS task: {task} in cluster: {cluster} (session_context={session_context})")
    result = await ecs.get_task(cluster, task, session_context=session_context)
    
    if result["success"] and result.get("task"):
        # Apply security-focused formatting to reduce response size
        result["task"] = format_ecs_task(result["task"])
    
    return result

@register_tool()
async def search_ecs_services_by_ecr_repository(repository_name: str, max_clusters: int = 10, max_services_per_cluster: int = 50, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Search for ECS services that use a specific ECR repository (optimized version).
    
    This tool searches through services and checks their task definitions only when needed.
    Includes limits to prevent timeouts in large environments. This is essential for security 
    analysis to understand which services might be affected by vulnerabilities in a specific 
    container image.
    
    Args:
        repository_name: Name of the ECR repository to search for (e.g., "test-repo")
        max_clusters: Maximum number of clusters to search (default: 10, helps prevent timeouts)
        max_services_per_cluster: Maximum services per cluster to check (default: 50, helps prevent timeouts)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing services using the specified ECR repository with security information
    """
    logger.info(f"Searching for ECS services using ECR repository: {repository_name} (max_clusters={max_clusters}, max_services_per_cluster={max_services_per_cluster}) (session_context={session_context})")
    result = await ecs.search_services_by_ecr_repository(repository_name, max_clusters, max_services_per_cluster, session_context=session_context)
    
    if result["success"] and result.get("services_using_repository"):
        # Apply security-focused formatting to reduce response size
        formatted_services = []
        for service in result["services_using_repository"]:
            # Keep all the essential security information but ensure consistent formatting
            formatted_service = {
                "service_name": service.get("service_name"),
                "service_arn": service.get("service_arn"),
                "cluster_name": service.get("cluster_name"),
                "cluster_arn": service.get("cluster_arn"),
                "task_definition": {
                    "arn": service.get("task_definition_arn"),
                    "family": service.get("task_definition_family"),
                    "revision": service.get("task_definition_revision")
                },
                "container": {
                    "name": service.get("container_name"),
                    "image_uri": service.get("image_uri")
                },
                "status": service.get("status"),
                "running_count": service.get("running_count", 0),
                "desired_count": service.get("desired_count", 0),
                "created_at": service.get("created_at")
            }
            formatted_services.append(formatted_service)
        
        result["services_using_repository"] = formatted_services
    
    return result 