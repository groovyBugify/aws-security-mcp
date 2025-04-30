"""Formatters for AWS ECS (Elastic Container Service) resources.

This module provides security-focused formatting functions for AWS ECS resources
to make them more suitable for API responses and LLM consumption by filtering out
only security-relevant information.
"""

from typing import Dict, List, Any, Optional


def format_ecs_service(service: Dict[str, Any]) -> Dict[str, Any]:
    """Format an ECS service into a security-focused representation.
    
    Args:
        service: The raw ECS service data dictionary
        
    Returns:
        Dictionary with only security-relevant service information
    """
    # Extract network configuration (security-relevant)
    network_config = service.get('networkConfiguration', {}).get('awsvpcConfiguration', {})
    security_groups = network_config.get('securityGroups', [])
    subnets = network_config.get('subnets', [])
    assign_public_ip = network_config.get('assignPublicIp', 'DISABLED') == 'ENABLED'
    
    # Extract IAM role information
    execution_role = service.get('executionRoleArn', None)
    task_role = service.get('taskDefinition', '').split('/')[-1] if service.get('taskDefinition') else None
    
    # Extract load balancer configuration (security-relevant)
    load_balancers = []
    for lb in service.get('loadBalancers', []):
        load_balancers.append({
            'targetGroupArn': lb.get('targetGroupArn', ''),
            'loadBalancerName': lb.get('loadBalancerName', ''),
            'containerName': lb.get('containerName', ''),
            'containerPort': lb.get('containerPort', 0)
        })
    
    # Extract deployment configuration (partially security-relevant)
    deployment_config = service.get('deploymentConfiguration', {})
    deployment_controller = service.get('deploymentController', {}).get('type', 'ECS')
    
    # Extract service discovery information (security-relevant for network exposure)
    service_discovery = []
    for registry in service.get('serviceRegistries', []):
        service_discovery.append({
            'registryArn': registry.get('registryArn', ''),
            'containerName': registry.get('containerName', ''),
            'containerPort': registry.get('containerPort', 0)
        })
    
    # Build the formatted output with only security-relevant information
    return {
        "service_name": service.get('serviceName', ''),
        "service_arn": service.get('serviceArn', ''),
        "cluster_arn": service.get('clusterArn', ''),
        "task_definition": task_role,
        "security": {
            "execution_role": execution_role,
            "network": {
                "vpc_enabled": bool(network_config),
                "assign_public_ip": assign_public_ip,
                "security_groups": security_groups,
                "subnet_count": len(subnets),
                "subnets": subnets
            },
            "service_discovery": service_discovery,
            "load_balancers": load_balancers
        },
        "deployment": {
            "controller_type": deployment_controller,
            "circuit_breaker_enabled": deployment_config.get('deploymentCircuitBreaker', {}).get('enable', False),
            "rollback_on_failure": deployment_config.get('deploymentCircuitBreaker', {}).get('rollback', False)
        },
        "enable_execute_command": service.get('enableExecuteCommand', False)
    }


def format_ecs_task_definition(task_definition: Dict[str, Any]) -> Dict[str, Any]:
    """Format an ECS task definition into a security-focused representation.
    
    Args:
        task_definition: The raw ECS task definition data dictionary
        
    Returns:
        Dictionary with only security-relevant task definition information
    """
    # Extract container definitions with security focus
    secure_containers = []
    for container in task_definition.get('containerDefinitions', []):
        # Get only security-relevant container properties
        secure_container = {
            "name": container.get('name', ''),
            "image": container.get('image', ''),
            "privileged": container.get('privileged', False),
            "user": container.get('user', 'None'),
            "readonly_rootfs": container.get('readonlyRootFilesystem', False),
            "secure_environment": bool(container.get('secrets', [])),
            "has_environment_vars": bool(container.get('environment', [])),
            "port_mappings_count": len(container.get('portMappings', [])),
            "mount_points_count": len(container.get('mountPoints', [])),
            "ulimits": bool(container.get('ulimits', [])),
            "linux_parameters": bool(container.get('linuxParameters', {})),
            "log_configuration": bool(container.get('logConfiguration', {}))
        }
        
        # If there are secrets, list them by name only (not values)
        if container.get('secrets'):
            secure_container['secrets'] = [
                secret.get('name', '') for secret in container.get('secrets', [])
            ]
        
        # Include all environment variables with their actual values
        if container.get('environment'):
            env_vars = {}
            for env in container.get('environment', []):
                env_name = env.get('name', '')
                env_value = env.get('value', '')
                env_vars[env_name] = env_value
            
            secure_container['environment'] = env_vars
        
        secure_containers.append(secure_container)
    
    # Extract volumes with security focus
    secure_volumes = []
    for volume in task_definition.get('volumes', []):
        secure_volume = {
            "name": volume.get('name', ''),
            "efs_volume": bool(volume.get('efsVolumeConfiguration', {})),
            "docker_volume": bool(volume.get('dockerVolumeConfiguration', {})),
            "host_path": volume.get('host', {}).get('sourcePath', None)
        }
        
        # Add EFS volume details if present
        if volume.get('efsVolumeConfiguration'):
            efs_config = volume.get('efsVolumeConfiguration', {})
            secure_volume['efs'] = {
                "file_system_id": efs_config.get('fileSystemId', ''),
                "root_directory": efs_config.get('rootDirectory', '/'),
                "transit_encryption": efs_config.get('transitEncryption', 'DISABLED'),
                "iam_auth": efs_config.get('authorizationConfig', {}).get('iam', 'DISABLED')
            }
        
        secure_volumes.append(secure_volume)
    
    # Build the formatted output with only security-relevant information
    return {
        "family": task_definition.get('family', ''),
        "revision": task_definition.get('revision', 0),
        "task_definition_arn": task_definition.get('taskDefinitionArn', ''),
        "security": {
            "task_role_arn": task_definition.get('taskRoleArn', 'None'),
            "execution_role_arn": task_definition.get('executionRoleArn', 'None'),
            "network_mode": task_definition.get('networkMode', 'bridge'),
            "pid_mode": task_definition.get('pidMode', 'host') if task_definition.get('pidMode') else 'None',
            "ipc_mode": task_definition.get('ipcMode', 'host') if task_definition.get('ipcMode') else 'None',
            "containers": secure_containers,
            "volumes": secure_volumes
        },
        "requires_compatibilities": task_definition.get('requiresCompatibilities', []),
        "cpu": task_definition.get('cpu', 'None'),
        "memory": task_definition.get('memory', 'None'),
        "status": task_definition.get('status', '')
    }


def format_ecs_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """Format an ECS task into a security-focused representation.
    
    Args:
        task: The raw ECS task data dictionary
        
    Returns:
        Dictionary with only security-relevant task information
    """
    # Extract attachments (like ENIs) with security focus
    attachments = []
    for attachment in task.get('attachments', []):
        if attachment.get('type') == 'ElasticNetworkInterface':
            eni_details = {}
            for detail in attachment.get('details', []):
                eni_details[detail.get('name')] = detail.get('value')
            
            attachments.append({
                "id": attachment.get('id', ''),
                "type": attachment.get('type', ''),
                "status": attachment.get('status', ''),
                "subnet_id": eni_details.get('subnetId', ''),
                "security_groups": [eni_details.get('networkInterfaceSecurityGroups', '')],
                "private_ipv4_address": eni_details.get('privateIPv4Address', ''),
                "ipv6_address": eni_details.get('privateIPv6Address', '')
            })
    
    # Extract container details with security focus
    containers = []
    for container in task.get('containers', []):
        containers.append({
            "name": container.get('name', ''),
            "image": container.get('image', ''),
            "image_digest": container.get('imageDigest', '').split(':')[-1] if container.get('imageDigest') else '',
            "last_status": container.get('lastStatus', ''),
            "exit_code": container.get('exitCode', None),
            "reason": container.get('reason', ''),
            "health_status": container.get('healthStatus', 'UNKNOWN')
        })
    
    # Build the formatted output with only security-relevant information
    return {
        "task_arn": task.get('taskArn', ''),
        "cluster_arn": task.get('clusterArn', ''),
        "task_definition_arn": task.get('taskDefinitionArn', ''),
        "security": {
            "enableExecuteCommand": task.get('enableExecuteCommand', False),
            "group": task.get('group', ''),
            "launch_type": task.get('launchType', ''),
            "network_interfaces": attachments,
            "containers": containers,
            "platform_version": task.get('platformVersion', '')
        },
        "started_by": task.get('startedBy', ''),
        "version": task.get('version', 0),
        "connectivity": task.get('connectivity', ''),
        "last_status": task.get('lastStatus', '')
    }


def format_ecs_container_instance(container_instance: Dict[str, Any]) -> Dict[str, Any]:
    """Format an ECS container instance into a security-focused representation.
    
    Args:
        container_instance: The raw ECS container instance data dictionary
        
    Returns:
        Dictionary with only security-relevant container instance information
    """
    # Extract instance attributes with security focus
    attributes = {}
    for attr in container_instance.get('attributes', []):
        # Only include security-relevant attributes
        attr_name = attr.get('name', '')
        if any(keyword in attr_name.lower() for keyword in 
               ['ecs.capability', 'ecs.vpc', 'ecs.subnet', 'ecs.security-group', 
                'ecs.instance-type', 'ecs.ami-id', 'ecs.instance-role']):
            attributes[attr_name] = attr.get('value', '')
    
    # Build the formatted output with only security-relevant information
    return {
        "container_instance_arn": container_instance.get('containerInstanceArn', ''),
        "ec2_instance_id": container_instance.get('ec2InstanceId', ''),
        "security": {
            "status": container_instance.get('status', ''),
            "agent_connected": container_instance.get('agentConnected', False),
            "agent_version": container_instance.get('versionInfo', {}).get('agentVersion', ''),
            "security_attributes": attributes
        },
        "running_tasks_count": container_instance.get('runningTasksCount', 0),
        "pending_tasks_count": container_instance.get('pendingTasksCount', 0)
    }


def format_ecs_cluster(cluster: Dict[str, Any]) -> Dict[str, Any]:
    """Format an ECS cluster into a security-focused representation.
    
    Args:
        cluster: The raw ECS cluster data dictionary
        
    Returns:
        Dictionary with only security-relevant cluster information
    """
    # Extract settings with security focus
    settings = {}
    for setting in cluster.get('settings', []):
        # Only include security-relevant settings
        setting_name = setting.get('name', '')
        if setting_name in ['containerInsights', 'fargateEphemeralStorageKMSKey']:
            settings[setting_name] = setting.get('value', '')
    
    # Build the formatted output with only security-relevant information
    return {
        "cluster_name": cluster.get('clusterName', ''),
        "cluster_arn": cluster.get('clusterArn', ''),
        "security": {
            "status": cluster.get('status', ''),
            "security_settings": settings,
            "capacity_providers": cluster.get('capacityProviders', []),
            "default_capacity_provider_strategy": cluster.get('defaultCapacityProviderStrategy', [])
        },
        "active_services_count": cluster.get('activeServicesCount', 0),
        "running_tasks_count": cluster.get('runningTasksCount', 0),
        "pending_tasks_count": cluster.get('pendingTasksCount', 0),
        "registered_container_instances_count": cluster.get('registeredContainerInstancesCount', 0)
    } 