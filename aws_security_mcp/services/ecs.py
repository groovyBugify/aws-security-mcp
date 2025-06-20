"""AWS ECS (Elastic Container Service) service for container orchestration security."""

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from botocore.exceptions import ClientError

from aws_security_mcp.config import config
from aws_security_mcp.services.base import get_client

logger = logging.getLogger(__name__)

async def get_clusters(session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve all ECS clusters.
    
    Args:
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
    
    Returns:
        Dict containing ECS clusters or error information
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
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

async def get_task_definitions(family_prefix: Optional[str] = None, status: str = "ACTIVE", session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve ECS task definitions with security focus.
    
    Args:
        family_prefix: Optional family name prefix to filter task definitions
        status: Task definition status to filter by (ACTIVE or INACTIVE)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing task definitions or error information
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
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

async def get_services(cluster: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve ECS services with security focus.
    
    Args:
        cluster: The cluster ARN or name
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing services or error information
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
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

async def get_tasks(cluster: str, service: Optional[str] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve ECS tasks with security focus.
    
    Args:
        cluster: The cluster ARN or name
        service: Optional service name to filter tasks
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing tasks or error information
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
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

async def get_container_instances(cluster: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve ECS container instances with security focus.
    
    Args:
        cluster: The cluster ARN or name
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing container instances or error information
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
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

async def get_task_definition(task_definition_input: str, cluster: Optional[str] = None, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve detailed information about the latest active ECS task definition with running tasks.
    
    This function prioritizes finding task definitions that are actually in use. If a family
    name is provided without a revision, it will find the latest active revision with running tasks.
    
    Args:
        task_definition_input: The task definition family name or ARN or family:revision
        cluster: Optional cluster name to check for running tasks (if None, checks all clusters)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing task definition details or error information
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
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

async def get_service(cluster: str, service: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve detailed information about a specific ECS service.
    
    Args:
        cluster: The cluster ARN or name
        service: The service ARN or name
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing service details or error information
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
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

async def get_task(cluster: str, task: str, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve detailed information about a specific ECS task.
    
    Args:
        cluster: The cluster ARN or name
        task: The task ARN or ID
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing task details or error information
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
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

async def search_services_by_ecr_repository(repository_name: str, max_clusters: int = 10, max_services_per_cluster: int = 50, session_context: Optional[str] = None) -> Dict[str, Any]:
    """Search for ECS services that use a specific ECR repository (optimized version).
    
    This function uses an optimized approach: instead of checking all task definitions first,
    it searches through services and checks their task definitions only when needed.
    Includes limits to prevent timeouts in large environments.
    
    Args:
        repository_name: Name of the ECR repository to search for (e.g., "test-repo")
        max_clusters: Maximum number of clusters to search (default: 10)
        max_services_per_cluster: Maximum services per cluster to check (default: 50)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        
    Returns:
        Dict containing services using the specified ECR repository
    """
    try:
        client = get_client('ecs', session_context=session_context)
        
        logger.info(f"Searching for ECS services using ECR repository: {repository_name} (max_clusters={max_clusters}, max_services_per_cluster={max_services_per_cluster})")
        
        services_using_repository = []
        task_definitions_checked = set()  # Cache to avoid checking same task def multiple times
        matching_task_definitions = []
        clusters_searched = 0
        total_services_checked = 0
        
        # Get clusters (limited)
        cluster_paginator = client.get_paginator('list_clusters')
        
        for cluster_page in cluster_paginator.paginate():
            cluster_arns = cluster_page.get('clusterArns', [])
            
            for cluster_arn in cluster_arns:
                if clusters_searched >= max_clusters:
                    logger.info(f"Reached max_clusters limit ({max_clusters}), stopping search")
                    break
                    
                clusters_searched += 1
                services_in_cluster = 0
                
                logger.info(f"Searching cluster {clusters_searched}/{max_clusters}: {cluster_arn.split('/')[-1]}")
                
                try:
                    # Get services for this cluster (limited)
                    service_paginator = client.get_paginator('list_services')
                    
                    for service_page in service_paginator.paginate(cluster=cluster_arn):
                        service_arns = service_page.get('serviceArns', [])
                        
                        if not service_arns:
                            continue
                            
                        # Limit services per cluster
                        remaining_services = max_services_per_cluster - services_in_cluster
                        if remaining_services <= 0:
                            logger.info(f"Reached max_services_per_cluster limit ({max_services_per_cluster}) for cluster")
                            break
                            
                        # Take only what we can process
                        service_arns = service_arns[:remaining_services]
                        
                        # Process services in batches of 10 (AWS limit)
                        for i in range(0, len(service_arns), 10):
                            batch = service_arns[i:i+10]
                            services_in_cluster += len(batch)
                            total_services_checked += len(batch)
                            
                            try:
                                response = client.describe_services(
                                    cluster=cluster_arn,
                                    services=batch
                                )
                                
                                for service in response.get('services', []):
                                    service_task_def = service.get('taskDefinition', '')
                                    
                                    # Skip if we already checked this task definition
                                    if service_task_def in task_definitions_checked:
                                        continue
                                        
                                    task_definitions_checked.add(service_task_def)
                                    
                                    # Check if this task definition uses our ECR repository
                                    try:
                                        task_def_response = client.describe_task_definition(taskDefinition=service_task_def)
                                        task_def = task_def_response.get('taskDefinition', {})
                                        
                                        # Check each container definition
                                        for container in task_def.get('containerDefinitions', []):
                                            image_uri = container.get('image', '')
                                            
                                            # Parse ECR URI to extract repository name
                                            if '.dkr.ecr.' in image_uri and '.amazonaws.com/' in image_uri:
                                                try:
                                                    repo_part = image_uri.split('.amazonaws.com/')[-1]
                                                    extracted_repo_name = repo_part.split(':')[0]
                                                    
                                                    if extracted_repo_name == repository_name:
                                                        # Found a match!
                                                        matching_task_def = {
                                                            'taskDefinitionArn': service_task_def,
                                                            'family': task_def.get('family'),
                                                            'revision': task_def.get('revision'),
                                                            'container_name': container.get('name'),
                                                            'image_uri': image_uri
                                                        }
                                                        
                                                        if matching_task_def not in matching_task_definitions:
                                                            matching_task_definitions.append(matching_task_def)
                                                        
                                                        services_using_repository.append({
                                                            'service_name': service.get('serviceName'),
                                                            'service_arn': service.get('serviceArn'),
                                                            'cluster_arn': cluster_arn,
                                                            'cluster_name': cluster_arn.split('/')[-1],
                                                            'task_definition_arn': service_task_def,
                                                            'task_definition_family': task_def.get('family'),
                                                            'task_definition_revision': task_def.get('revision'),
                                                            'container_name': container.get('name'),
                                                            'image_uri': image_uri,
                                                            'status': service.get('status'),
                                                            'running_count': service.get('runningCount', 0),
                                                            'desired_count': service.get('desiredCount', 0),
                                                            'created_at': service.get('createdAt').isoformat() if service.get('createdAt') else None
                                                        })
                                                        
                                                        logger.info(f"Found service using {repository_name}: {service.get('serviceName')}")
                                                        break  # Found match in this task definition
                                                        
                                                except Exception as e:
                                                    logger.warning(f"Error parsing image URI {image_uri}: {e}")
                                                    
                                    except ClientError as e:
                                        logger.warning(f"Error describing task definition {service_task_def}: {e}")
                                        
                            except ClientError as e:
                                logger.warning(f"Error describing services in cluster {cluster_arn}: {e}")
                                
                        if services_in_cluster >= max_services_per_cluster:
                            break  # Break out of service pagination
                            
                except ClientError as e:
                    logger.warning(f"Error listing services in cluster {cluster_arn}: {e}")
                    
            if clusters_searched >= max_clusters:
                break  # Break out of cluster iteration
        
        result = {
            "success": True,
            "repository_name": repository_name,
            "services_using_repository": services_using_repository,
            "services_count": len(services_using_repository),
            "matching_task_definitions": len(matching_task_definitions),
            "task_definitions_found": [td['taskDefinitionArn'] for td in matching_task_definitions],
            "search_stats": {
                "clusters_searched": clusters_searched,
                "total_services_checked": total_services_checked,
                "unique_task_definitions_checked": len(task_definitions_checked),
                "max_clusters": max_clusters,
                "max_services_per_cluster": max_services_per_cluster
            }
        }
        
        logger.info(f"Search completed: found {len(services_using_repository)} services using {repository_name}")
        return result
        
    except ClientError as e:
        logger.error(f"Error searching for services using ECR repository {repository_name}: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "repository_name": repository_name,
            "services_using_repository": [],
            "services_count": 0
        } 