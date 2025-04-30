# AWS Security MCP - Service Modules

This directory contains service modules for interacting with various AWS services. Each module provides a set of functions to interact with a specific AWS service, handling pagination, error handling, and formatting of responses.

## Service Modules

### Resource Tagging Service (`resource_tagging.py`)

The Resource Tagging Service module provides functionality to interact with the AWS Resource Groups Tagging API. It includes functions to retrieve tag keys, tag values, and resources by tags.

#### Key Functions:

1. **`get_tag_keys`**: Retrieves all tag keys used in the AWS account, with support for pagination.
2. **`get_tag_values`**: Retrieves all values for a specific tag key, with support for pagination.
3. **`check_tag_key_exists`**: Checks if a specific tag key exists in the AWS account.
4. **`check_tag_value_exists`**: Checks if a specific tag value exists for a given tag key.
5. **`get_resources_by_tags`**: Retrieves AWS resources filtered by tag key and optionally tag value, with support for pagination and resource type filtering.

### Load Balancer Service (`load_balancer.py`)

The Load Balancer Service module provides functionality to interact with the AWS Elastic Load Balancing API. It includes functions to retrieve load balancers, target groups, and listeners.

#### Key Functions:

1. **`get_all_load_balancers_v2`**: Retrieves all Application and Network Load Balancers.
2. **`get_all_classic_load_balancers`**: Retrieves all Classic Load Balancers.
3. **`get_all_target_groups`**: Retrieves all target groups.
4. **`get_all_listeners`**: Retrieves all listeners for a load balancer.

## Error Handling

All service functions handle exceptions and return standardized error responses. The error responses include:

- A clear error message
- The original exception details
- Empty result sets to avoid null reference errors

## Pagination

Service functions support pagination through:

- `next_token`: A token for retrieving the next set of results
- `max_items`: Maximum number of items to return in a single call

## Usage Example

```python
from aws_security_mcp.services.resource_tagging import get_resources_by_tags

# Get all EC2 instances with the tag "Environment=Production"
resources = await get_resources_by_tags(
    tag_key="Environment",
    tag_value="Production",
    resource_types=["ec2:instance"]
)
``` 