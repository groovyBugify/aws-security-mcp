# AWS Security MCP - Formatter Modules

This directory contains formatter modules that transform the responses from AWS service APIs into standardized, user-friendly formats. These formatters ensure consistent response structures across all MCP tools.

## Formatter Structure

Each formatter module contains functions that format responses from a specific AWS service. These functions:

1. Extract relevant information from AWS API responses
2. Transform complex data structures into simpler, more readable formats
3. Add additional context or derived information where useful
4. Standardize error responses

## Formatter Modules

### Resource Tagging Formatters (`resource_tagging.py`)

The Resource Tagging Formatters module provides functions to format responses from the AWS Resource Groups Tagging API.

#### Key Functions:

1. **`format_resource_details`**: Formats a single resource's details, extracting information from the ARN and tags.
2. **`format_resources_response`**: Formats the response from `get_resources_by_tags`, transforming resource mappings into a user-friendly format.
3. **`format_tag_keys_response`**: Formats the response from `get_tag_keys`, providing tag keys and pagination information.
4. **`format_tag_values_response`**: Formats the response from `get_tag_values`, providing tag key, values, and pagination information.

### Load Balancer Formatters (`load_balancer.py`)

The Load Balancer Formatters module provides functions to format responses from the AWS Elastic Load Balancing API.

#### Key Functions:

1. **`format_load_balancer_response`**: Formats the response from `get_all_load_balancers_v2`, providing load balancer details in a standardized format.
2. **`format_target_group_response`**: Formats the response from `get_all_target_groups`, providing target group details in a standardized format.
3. **`format_listener_response`**: Formats the response from `get_all_listeners`, providing listener details in a standardized format.

## Standardized Response Format

All formatter functions follow a standardized response format:

```json
{
  "resource_type": [
    {
      "id": "resource-id",
      "name": "resource-name",
      "arn": "resource-arn",
      ... additional resource-specific fields ...
    }
  ],
  "resource_count": 1,
  "next_token": "pagination-token"
}
```

In case of errors, the response includes an `error` field:

```json
{
  "resource_type": [],
  "resource_count": 0,
  "error": "Error message"
}
```

## Usage Example

```python
from aws_security_mcp.services.resource_tagging import get_resources_by_tags
from aws_security_mcp.formatters.resource_tagging import format_resources_response

# Get raw response from service
raw_response = await get_resources_by_tags(
    tag_key="Environment",
    tag_value="Production"
)

# Format the response
formatted_response = format_resources_response(raw_response)

# Convert to JSON
import json
json_response = json.dumps(formatted_response)
``` 