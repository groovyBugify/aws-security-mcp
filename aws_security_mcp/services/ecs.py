"""AWS ECS (Elastic Container Service) service for container orchestration security."""

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from botocore.exceptions import ClientError

from aws_security_mcp.config import config
from aws_security_mcp.services.base import get_client

logger = logging.getLogger(__name__)

async def get_clusters() -> Dict[str, Any]:
    """Retrieve all ECS clusters.
    
    Returns:
        Dict containing ECS clusters or error information
    """
    try:
        client = get_client('ecs')
        
        # Use paginator to handle pagination
        paginator = client.get_paginator('list_clusters')
        
        all_clusters = []
        
        # Iterate through pages
        for page in paginator.paginate():
            clusters = page.get('clusterArns', [])
            all_clusters.extend(clusters)
        
        # Get detailed information for each cluster
        detailed_clusters = []
        
        if all_clusters:
            # Process in batches of 100 (AWS API limitation)
            for i in range(0, len(all_clusters), 100):
                batch = all_clusters[i:i+100]
                response = client.describe_clusters(
                    clusters=batch,
                    include=["ATTACHMENTS", "SETTINGS", "STATISTICS", "TAGS"]
                )
                detailed_clusters.extend(response.get('clusters', []))
                # Track any failures
                failures = response.get('failures', [])
                if failures:
                    logger.warning(f"Failed to describe {len(failures)} clusters: {failures}")
        
        return {
            "success": True,
            "clusters": detailed_clusters,
            "count": len(detailed_clusters)
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECS clusters: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "clusters": [],
            "count": 0
        }

async def get_task_definitions(family_prefix: Optional[str] = None, status: str = "ACTIVE") -> Dict[str, Any]:
    """Retrieve ECS task definitions with security focus.
    
    Args:
        family_prefix: Optional family name prefix to filter task definitions
        status: Task definition status to filter by (ACTIVE or INACTIVE)
        
    Returns:
        Dict containing task definitions or error information
    """
    try:
        client = get_client('ecs')
        
        # Use paginator to handle pagination
        paginator = client.get_paginator('list_task_definitions')
        
        # Build pagination parameters
        params = {
            "status": status
        }
        
        if family_prefix:
            params["familyPrefix"] = family_prefix
        
        all_task_definitions = []
        
        # Iterate through pages
        for page in paginator.paginate(**params):
            task_definitions = page.get('taskDefinitionArns', [])
            all_task_definitions.extend(task_definitions)
        
        # Get detailed information for each task definition with security focus
        detailed_task_definitions = []
        
        for task_def_arn in all_task_definitions:
            try:
                response = client.describe_task_definition(
                    taskDefinition=task_def_arn,
                    include=["TAGS"]
                )
                detailed_task_definitions.append(response.get('taskDefinition', {}))
            except ClientError as e:
                logger.warning(f"Failed to describe task definition {task_def_arn}: {str(e)}")
        
        return {
            "success": True,
            "taskDefinitions": detailed_task_definitions,
            "count": len(detailed_task_definitions)
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECS task definitions: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "taskDefinitions": [],
            "count": 0
        }

async def get_services(cluster: str) -> Dict[str, Any]:
    """Retrieve ECS services with security focus.
    
    Args:
        cluster: The cluster ARN or name
        
    Returns:
        Dict containing services or error information
    """
    try:
        client = get_client('ecs')
        
        # Use paginator to handle pagination
        paginator = client.get_paginator('list_services')
        
        all_services = []
        
        # Iterate through pages
        for page in paginator.paginate(cluster=cluster):
            services = page.get('serviceArns', [])
            all_services.extend(services)
        
        # Get detailed information for services with security focus
        detailed_services = []
        
        if all_services:
            # Process in batches of 10 (AWS API limitation)
            for i in range(0, len(all_services), 10):
                batch = all_services[i:i+10]
                response = client.describe_services(
                    cluster=cluster,
                    services=batch,
                    include=["TAGS"]
                )
                detailed_services.extend(response.get('services', []))
                # Track any failures
                failures = response.get('failures', [])
                if failures:
                    logger.warning(f"Failed to describe {len(failures)} services: {failures}")
        
        return {
            "success": True,
            "services": detailed_services,
            "count": len(detailed_services),
            "cluster": cluster
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECS services for cluster {cluster}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "services": [],
            "count": 0,
            "cluster": cluster
        }

async def get_tasks(cluster: str, service: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve ECS tasks with security focus.
    
    Args:
        cluster: The cluster ARN or name
        service: Optional service name to filter tasks
        
    Returns:
        Dict containing tasks or error information
    """
    try:
        client = get_client('ecs')
        
        # Use paginator to handle pagination
        paginator = client.get_paginator('list_tasks')
        
        # Build pagination parameters
        params = {
            "cluster": cluster
        }
        
        if service:
            params["serviceName"] = service
        
        all_tasks = []
        
        # Iterate through pages
        for page in paginator.paginate(**params):
            tasks = page.get('taskArns', [])
            all_tasks.extend(tasks)
        
        # Get detailed information for tasks with security focus
        detailed_tasks = []
        
        if all_tasks:
            # Process in batches of 100 (AWS API limitation)
            for i in range(0, len(all_tasks), 100):
                batch = all_tasks[i:i+100]
                response = client.describe_tasks(
                    cluster=cluster,
                    tasks=batch,
                    include=["TAGS"]
                )
                detailed_tasks.extend(response.get('tasks', []))
                # Track any failures
                failures = response.get('failures', [])
                if failures:
                    logger.warning(f"Failed to describe {len(failures)} tasks: {failures}")
        
        return {
            "success": True,
            "tasks": detailed_tasks,
            "count": len(detailed_tasks),
            "cluster": cluster,
            "service": service
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECS tasks for cluster {cluster}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "tasks": [],
            "count": 0,
            "cluster": cluster,
            "service": service
        }

async def get_container_instances(cluster: str) -> Dict[str, Any]:
    """Retrieve ECS container instances with security focus.
    
    Args:
        cluster: The cluster ARN or name
        
    Returns:
        Dict containing container instances or error information
    """
    try:
        client = get_client('ecs')
        
        # Use paginator to handle pagination
        paginator = client.get_paginator('list_container_instances')
        
        all_container_instances = []
        
        # Iterate through pages
        for page in paginator.paginate(cluster=cluster):
            container_instances = page.get('containerInstanceArns', [])
            all_container_instances.extend(container_instances)
        
        # Get detailed information for container instances with security focus
        detailed_container_instances = []
        
        if all_container_instances:
            # Process in batches of 100 (AWS API limitation)
            for i in range(0, len(all_container_instances), 100):
                batch = all_container_instances[i:i+100]
                response = client.describe_container_instances(
                    cluster=cluster,
                    containerInstances=batch,
                    include=["TAGS"]
                )
                detailed_container_instances.extend(response.get('containerInstances', []))
                # Track any failures
                failures = response.get('failures', [])
                if failures:
                    logger.warning(f"Failed to describe {len(failures)} container instances: {failures}")
        
        return {
            "success": True,
            "containerInstances": detailed_container_instances,
            "count": len(detailed_container_instances),
            "cluster": cluster
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECS container instances for cluster {cluster}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "containerInstances": [],
            "count": 0,
            "cluster": cluster
        }

async def get_task_definition(task_definition_input: str, cluster: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve detailed information about the latest active ECS task definition with running tasks.
    
    This function prioritizes finding task definitions that are actually in use. If a family
    name is provided without a revision, it will find the latest active revision with running tasks.
    
    Args:
        task_definition_input: The task definition family name or ARN or family:revision
        cluster: Optional cluster name to check for running tasks (if None, checks all clusters)
        
    Returns:
        Dict containing task definition details or error information
    """
    try:
        client = get_client('ecs')
        
        # If input looks like a family name only (no ARN format, no colon for revision)
        is_family_only = not task_definition_input.startswith('arn:') and ':' not in task_definition_input
        
        task_definition_to_use = task_definition_input
        
        # If only family name was provided, find the latest active revision
        if is_family_only:
            logger.info(f"Finding latest active revision for family {task_definition_input}")
            
            # List all active task definitions in this family
            paginator = client.get_paginator('list_task_definitions')
            active_task_defs = []
            
            # Collect all active task definitions for this family
            for page in paginator.paginate(familyPrefix=task_definition_input, status="ACTIVE"):
                active_task_defs.extend(page.get('taskDefinitionArns', []))
            
            if not active_task_defs:
                return {
                    "success": False,
                    "error": f"No active task definitions found for family {task_definition_input}",
                    "taskDefinition": {}
                }
            
            # Get clusters to check for running tasks
            clusters_to_check = []
            if cluster:
                clusters_to_check = [cluster]
            else:
                # Get all clusters if none specified
                cluster_paginator = client.get_paginator('list_clusters')
                for page in cluster_paginator.paginate():
                    clusters_to_check.extend(page.get('clusterArns', []))
            
            # Find the latest revision with running tasks
            task_def_with_running_tasks = None
            
            for cluster_arn in clusters_to_check:
                # Check if any tasks are running with these task definitions
                for task_def_arn in active_task_defs:
                    # List running tasks with this task definition in this cluster
                    task_paginator = client.get_paginator('list_tasks')
                    running_tasks = []
                    
                    for page in task_paginator.paginate(cluster=cluster_arn, family=task_definition_input):
                        running_tasks.extend(page.get('taskArns', []))
                    
                    if running_tasks:
                        # Get one task to check its task definition
                        task_details = client.describe_tasks(
                            cluster=cluster_arn,
                            tasks=[running_tasks[0]]
                        )
                        
                        if task_details.get('tasks'):
                            task = task_details['tasks'][0]
                            task_def_with_running_tasks = task.get('taskDefinitionArn')
                            logger.info(f"Found running task using task definition: {task_def_with_running_tasks}")
                            break
                
                if task_def_with_running_tasks:
                    break
            
            # If no running tasks found, use the latest revision
            if not task_def_with_running_tasks:
                # Sort by revision (which is the last part of the ARN)
                sorted_task_defs = sorted(
                    active_task_defs,
                    key=lambda arn: int(arn.split('/')[-1].split(':')[-1]),
                    reverse=True
                )
                task_def_with_running_tasks = sorted_task_defs[0]
                logger.info(f"No running tasks found, using latest revision: {task_def_with_running_tasks}")
            
            task_definition_to_use = task_def_with_running_tasks
        
        # Get the detailed task definition
        response = client.describe_task_definition(
            taskDefinition=task_definition_to_use,
            include=["TAGS"]
        )
        
        task_def_details = response.get('taskDefinition', {})
        
        # Add information about running tasks
        task_def_details['hasRunningTasks'] = bool(task_def_with_running_tasks) if is_family_only else None
        
        return {
            "success": True,
            "taskDefinition": task_def_details
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECS task definition {task_definition_input}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "taskDefinition": {}
        }

async def get_service(cluster: str, service: str) -> Dict[str, Any]:
    """Retrieve detailed information about a specific ECS service.
    
    Args:
        cluster: The cluster ARN or name
        service: The service ARN or name
        
    Returns:
        Dict containing service details or error information
    """
    try:
        client = get_client('ecs')
        
        # Get detailed information about the service
        response = client.describe_services(
            cluster=cluster,
            services=[service],
            include=["TAGS"]
        )
        
        services = response.get('services', [])
        failures = response.get('failures', [])
        
        if failures:
            logger.warning(f"Failed to describe service {service}: {failures}")
            return {
                "success": False,
                "error": f"Failed to describe service: {failures[0].get('reason', 'Unknown reason')}",
                "service": None,
                "cluster": cluster
            }
        
        if not services:
            return {
                "success": False,
                "error": f"Service {service} not found in cluster {cluster}",
                "service": None,
                "cluster": cluster
            }
        
        return {
            "success": True,
            "service": services[0],
            "cluster": cluster
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECS service {service} in cluster {cluster}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "service": None,
            "cluster": cluster
        }

async def get_task(cluster: str, task: str) -> Dict[str, Any]:
    """Retrieve detailed information about a specific ECS task.
    
    Args:
        cluster: The cluster ARN or name
        task: The task ARN or ID
        
    Returns:
        Dict containing task details or error information
    """
    try:
        client = get_client('ecs')
        
        # Get detailed information about the task
        response = client.describe_tasks(
            cluster=cluster,
            tasks=[task],
            include=["TAGS"]
        )
        
        tasks = response.get('tasks', [])
        failures = response.get('failures', [])
        
        if failures:
            logger.warning(f"Failed to describe task {task}: {failures}")
            return {
                "success": False,
                "error": f"Failed to describe task: {failures[0].get('reason', 'Unknown reason')}",
                "task": None,
                "cluster": cluster
            }
        
        if not tasks:
            return {
                "success": False,
                "error": f"Task {task} not found in cluster {cluster}",
                "task": None,
                "cluster": cluster
            }
        
        return {
            "success": True,
            "task": tasks[0],
            "cluster": cluster
        }
    
    except ClientError as e:
        logger.error(f"Error retrieving ECS task {task} in cluster {cluster}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "task": None,
            "cluster": cluster
        } 