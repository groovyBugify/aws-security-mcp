# AWS Security MCP Formatters

This directory contains formatter modules that transform raw AWS API responses into structured, readable formats optimized for Claude's consumption.

## Purpose

Formatters standardize AWS responses, which can be complex and verbose, into consistent structures with:
- Relevant security information prioritized
- Unnecessary fields removed
- Nested structures flattened where appropriate
- Standardized field naming

## Available Formatters

### Security Analysis
- **[iam_formatter.py](iam_formatter.py)** - Formats IAM resources like users, roles, and policies
- **[securityhub.py](securityhub.py)** - Formats SecurityHub findings and compliance data
- **[guardduty.py](guardduty.py)** - Formats GuardDuty threat detection findings
- **[shield.py](shield.py)** - Formats Shield DDoS protection data
- **[waf.py](waf.py)** - Formats WAF rules and web ACLs

### Infrastructure & Networking
- **[ec2.py](ec2.py)** - Formats EC2 instances, security groups, and VPC resources
- **[load_balancer.py](load_balancer.py)** - Formats load balancer configurations (ELB/ALB/NLB)
- **[route53.py](route53.py)** - Formats Route53 DNS records and hosted zones
- **[cloudfront.py](cloudfront.py)** - Formats CloudFront distribution data

### Storage & Data
- **[s3_formatter.py](s3_formatter.py)** - Formats S3 bucket configurations and policies
- **[ecr.py](ecr.py)** - Formats ECR repository data and image scan results

### Compute & Applications
- **[lambda_formatter.py](lambda_formatter.py)** - Formats Lambda function information
- **[ecs_formatter.py](ecs_formatter.py)** - Formats ECS cluster, service, and task data

### Analytics & Monitoring
- **[athena.py](athena.py)** - Formats Athena query results, database schemas, and execution metadata

### Organization & Resource Management
- **[org_formatter.py](org_formatter.py)** - Formats AWS Organizations structure and accounts
- **[resource_tagging.py](resource_tagging.py)** - Formats resource tag information

## Common Formatting Patterns

The formatter modules follow consistent design patterns:
- Security-relevant information is prioritized
- Large responses are summarized appropriately
- Timestamps are converted to human-readable format
- ARNs are parsed into component parts when useful
- Pagination information is properly structured
- Error conditions are gracefully handled

## Athena Formatter Features

The **[athena.py](athena.py)** formatter provides specialized formatting for:

### Database & Schema Information
- Database summaries with metadata
- Table schema details including columns, partitions, and storage information
- Table metadata formatting with security-relevant details

### Query Execution & Results
- Query execution status and performance metrics
- Formatted query results with proper column mapping
- Execution statistics (execution time, data scanned, costs)
- Query validation and security recommendations

### Performance & Security Recommendations
- Built-in query optimization suggestions
- Security best practices for CloudTrail/VPC Flow Logs queries
- Performance recommendations for large datasets
- Partition pruning and date filtering advice

### Specialized Formatters
- `format_query_results()` - Converts raw Athena results to structured data with column headers
- `format_query_execution()` - Provides comprehensive execution status and statistics
- `format_table_metadata()` - Formats table schemas for easy consumption
- `generate_query_recommendations()` - Provides security and performance recommendations

The Athena formatter is particularly optimized for security analysis use cases, providing intelligent recommendations for querying CloudTrail logs and VPC Flow Logs with proper date/time filtering to control costs and performance.

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