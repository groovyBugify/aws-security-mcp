# AWS Security MCP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A Model Context Protocol (MCP) server that enables AI assistants to perform comprehensive AWS security analysis through natural language queries.


## Overview

AWS Security MCP bridges AI assistants like Claude with AWS security services, enabling real-time infrastructure analysis through conversational queries. The system automatically discovers and analyzes resources across multiple AWS accounts, providing security insights without requiring deep AWS CLI knowledge.

### Key Capabilities

- **Cross-Account Discovery**: Automatic detection and access to AWS Organization accounts
- **Natural Language Interface**: Query AWS resources using plain English
- **Security Analysis**: Integrated findings from GuardDuty, SecurityHub, and Access Analyzer  
- **Infrastructure Mapping**: Network topology, threat modelling, security review and blast radius analysis
- **Log Analytics**: Athena-powered analysis of CloudTrail, VPC Flow Logs, and security events

## Prerequisites

- **Python**: 3.11 or higher
- **Package Manager**: [uv](https://docs.astral.sh/uv/getting-started/installation/)
- **AWS Account**: With appropriate IAM permissions
- **MCP Client**: Claude Desktop, Cline, or compatible client

### AWS Requirements

MCP Server's AWS credentials must have the following permissions:

#### Core MCP Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CrossAccountAccess",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::*:role/aws-security-mcp-cross-account-access"
    },
    {
      "Sid": "OrganizationDiscovery",
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Athena Integration Permissions

For advanced log analysis capabilities, additional permissions are required:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AthenaQueryExecution",
      "Effect": "Allow",
      "Action": [
        "athena:BatchGetQueryExecution",
        "athena:GetQueryExecution",
        "athena:GetQueryResults",
        "athena:GetWorkGroup",
        "athena:GetTableMetadata",
        "athena:ListQueryExecutions",
        "athena:StartQueryExecution",
        "athena:GetQueryResultsStream",
        "athena:GetDataCatalog",
        "athena:ListDataCatalogs",
        "athena:ListDatabases",
        "athena:ListTableMetadata"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GlueCatalogAccess",
      "Effect": "Allow",
      "Action": [
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetTable",
        "glue:GetTables",
        "glue:GetPartition",
        "glue:GetPartitions",
        "glue:BatchGetPartition"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3LogDataAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-cloudtrail-bucket/*",
        "arn:aws:s3:::your-cloudtrail-bucket",
        "arn:aws:s3:::your-vpc-flow-logs-bucket/*",
        "arn:aws:s3:::your-vpc-flow-logs-bucket",
        "arn:aws:s3:::your-security-logs-bucket/*",
        "arn:aws:s3:::your-security-logs-bucket"
      ]
    },
    {
      "Sid": "AthenaResultsAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::your-athena-results-bucket/*",
        "arn:aws:s3:::your-athena-results-bucket"
      ]
    }
  ]
}
```

#### Required AWS Managed Policies

**SecurityAudit Policy (Required)**

Attach the AWS managed SecurityAudit policy to your MCP Server's IAM user or IAM role:

```
Policy ARN: arn:aws:iam::aws:policy/SecurityAudit
```

This policy provides comprehensive read-only access to AWS security services and is **essential** for AWS Security MCP functionality. It includes permissions for:

- **IAM**: Users, roles, policies, access analysis
- **EC2**: Security groups, instances, VPC configurations  
- **S3**: Bucket policies, ACLs, public access settings
- **GuardDuty**: Findings, detectors, threat intelligence
- **SecurityHub**: Security standards, compliance findings
- **Access Analyzer**: IAM access analysis and findings
- **Lambda**: Function configurations and permissions
- **CloudFront**: Distribution security settings
- **Route53**: DNS configurations and health checks
- **WAF**: Web ACL rules and configurations
- **All other security-related AWS services**

**Optional Managed Policies**

- **AthenaFullAccess**: `arn:aws:iam::aws:policy/AmazonAthenaFullAccess` (for simplified Athena log analysis)

#### Important Notes

- It's best to use this MCP Server with Claude Desktop Pro/Max Plan or any other platform that allows you to deal with token size greater than 100,000
- Replace bucket names in the S3 permissions with your actual CloudTrail, VPC Flow Logs, and Athena results bucket names
- The SecurityAudit policy is **mandatory** for basic AWS Security MCP functionality
- Athena integration permissions are optional and only required for advanced log analysis features
- All permissions follow the principle of least privilege with read-only access where possible

## Quick Start ~ local setup

1. **Update config.yml**
  ```
  aws:
    region: "us-east-1"
    profile: {profileName}
    .
    .
    .
  ```
2. Configure your AWS Credentials via ~ local setup
  - aws sso
    ```bash
    $ aws configure sso
    SSO Session Name - email@example.com
    URL - https://yourDomain.awsapps.com/start/#
    Region - us-east-1
    ```
  - env variabls
    ```bash
    export AWS_ACCESS_KEY_ID=
    export export AWS_SECRET_ACCESS_KEY=
    export export AWS_SESSION_TOKEN=
    ```

3. **Run the following commands**
   ```bash
   git clone https://github.com/groovyBugify/aws-security-mcp.git
   uv venv
   source .venv/bin/activate
   uv pip install -r requirements.txt
   ```

3. **Configure MCP Client**
   ```bash
   # Install mcp-proxy
   uv tool install mcp-proxy
   
   # Check location of mcp-proxy
   which mcp-proxy

   # Add to Claude Desktop config
   {
     "mcpServers": {
       "aws-security": {
         "command": "/path/to/mcp-proxy",
         "args": ["http://localhost:8000/sse"]
       }
     }
   }
   ```

## Quick Start ~ as AWS ECS Service
1. **Login to AWS ECR**
  ```bash
  $ aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {accountID}.dkr.ecr.{region}.amazonaws.com
  ```
2. **Create ECR Repo**
  ```bash
  $ aws ecr create-repository --repository-name aws-security-mcp --region {region}
  ```
3. **Build Docker Image**
  ```bash
  $ cd aws-security-mcp/
  $ docker buildx build --platform linux/amd64 -t aws-security-mcp .
  $ docker tag aws-security-mcp:latest {accountID}.dkr.ecr.{region}.amazonaws.com/aws-security-mcp:latest
  $ docker push {accountID}.dkr.ecr.{region}.amazonaws.com/aws-security-mcp:latest
  ```
4. **Deploying as AWS ECS Service**
   - Create a Task Definition with "2048" CPU and "4096" Memory, this is optional, you can choose any values
   - Configure the Task definition to do port mapping for port 8000
   - Create ECS Task Role with the following permissions
     - SecurityAudit IAM Policy
     - Athena Access (Policy mentioned above)
     - STS Assume Role permissions to assume cross account roles
   - Create ECS Task Execution Role with basic permissions
   - Once the Task Definition is completed. 
   - Create an AWS ECS Service using the Task definition
     - You can configure Load Balancer as well
     - Make Sure to turn off the Stickness Session on Load Balancers
   - Register the ALB's taget group and listeners for port 80/443 -> ECS Service(8000)
   - Register the ALB for Route53 domain.

5. **Configure MCP Client**
   ```bash
   # Install mcp-proxy
   uv tool install mcp-proxy
   
   # Check location of mcp-proxy
   which mcp-proxy

   # Add to Claude Desktop config
   {
     "mcpServers": {
       "aws-security": {
         "command": "/path/to/mcp-proxy",
         "args": ["http://{alb}/sse"]
       }
     }
   }
   ```
   
## Configuration

### YAML Configuration

Edit `config.yaml` in the project root according to your needs:

```yaml
aws:
  region: "us-east-1"
  profile: null

server:
  log_level: "info"
  startup_quiet: false
  tool_quiet: false

cross_account:
  role_name: "aws-security-mcp-cross-account-access"
  auto_setup_on_startup: true
  max_concurrent_assumptions: 5
```

### Environment Variable Override

Environment variables take precedence over YAML configuration:

```bash
export MCP_LOG_LEVEL=debug
export MCP_STARTUP_QUIET=false
export AWS_DEFAULT_REGION=eu-west-1
```

## Usage Examples

### Basic Infrastructure Queries

```
Query: "Can you share a list of running ec2 instances?"

Query: "Share all the secrets stored on env variables of Lambda functions, and share a list of functions for remediating this issue."

Query: "Check my 'prod-ecs-cluster' and share more details about the 'user-login' service, is it deployed?"
```

### Security Analysis

```
Query: "Show all GuardDuty findings from the last 7 days, and priortise based on the risk of exposure."

Query: "Analyze IAM roles with administrative privileges"

Query: "Generate blast radius analysis for IP 172.16.1.10"

Query: "Fetch more details about the ip - 172.22.141.11, and share a network map for this resource.
```

### Cross-Account Operations

```
Query: "List all connected AWS accounts"
Query: "Refresh my AWS session"
Query: "Find resources tagged Team:Security across all accounts"
Query: "Show compliance status across organization"
```

## Architecture

### Cross-Account Access

AWS Security MCP implements a hub-and-spoke model for multi-account access:

1. **Discovery**: Uses `organizations:ListAccounts` to identify target accounts
2. **Role Assumption**: Assumes `aws-security-mcp-cross-account-access` role in each account
3. **Session Management**: Maintains temporary credentials with automatic refresh
4. **Fallback**: Uses default credential chain for non-organization accounts

### Required IAM Role Setup

Create this role in each target AWS account:

**Role Name**: `aws-security-mcp-cross-account-access`

**Trust Policy**:
   ```json
   {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR-MASTER-ACCOUNT-ID:root"
      },
      "Action": "sts:AssumeRole"
       }
  ]
   }
   ```

**Permissions**: Attach AWS managed policy `arn:aws:iam::aws:policy/SecurityAudit`

## Athena Integration

### Overview

AWS Security MCP integrates with Amazon Athena to provide advanced log analysis capabilities. This feature requires pre-existing Athena tables containing your security-relevant logs.

### Supported Log Types

While the MCP server can analyze any log source through Athena, the following sources are recommended to provide comprehensive security metadata to your MCP client. For optimal security coverage, we recommend implementing at least CloudTrail and VPC Flow Logs:

**Recommended Log Sources:**
- **AWS CloudTrail**: API call auditing and user activity tracking
- **VPC Flow Logs**: Network traffic pattern analysis  
- **CloudFront Logs**: CDN request and response analysis
- **ALB Access Logs**: Application load balancer traffic insights
- **WAF Logs**: Web application firewall events and blocks(Cloudflare/AWS WAF/Akamai)
- **AWS Shield Logs**: DDoS protection and mitigation events

**Flexibility for Custom Log Sources**

The MCP server supports querying any log type stored in S3, giving you complete flexibility to analyze custom or additional log sources. To enable analysis of any log source, ensure:

1. **S3 Storage**: Your logs are stored in an S3 bucket
2. **Athena Table**: A properly configured Athena table exists for the log format
3. **IAM Permissions**: The MCP server has `s3:GetObject` and `s3:ListBucket` permissions for the target bucket

This architecture allows you to extend security analysis beyond standard AWS logs to include application logs, custom security events, or third-party security tool outputs.

### Query Capabilities

Once tables are configured, you can perform advanced queries:

```
Query: "Show all failed login attempts from external IPs in the last 24 hours"

Query: "Can you share what did 'saransh.rana@company.com' did in past 24 hours on my aws account? and share a timeline report?"

Query: "Can you check for all the 'Access Denied/Error/Forbidden' on my PCI(123456789012) aws account and share the username and userIP of the principal, and do a reverse IP checkup if this IP is coming from my own AWS Org or external party."

Query: "Correlate GuardDuty findings with CloudTrail and VPC Flow logs events"
```

### Setup Prerequisites

1. **S3 Buckets**: CloudTrail and VPC Flow Logs must be stored in S3
2. **Athena Workgroup**: Configure appropriate workgroup with result location
3. **Partitioning**: Enable partition projection for performance
4. **IAM Permissions**: Grant Athena query permissions to the MCP execution role

## Supported AWS Services

### Currently Available

| Service | Capabilities |
|---------|-------------|
| **IAM** | Users, roles, policies, access keys, permission analysis |
| **EC2** | Instances, security groups, VPCs, subnets, network interfaces |
| **S3** | Buckets, permissions, public access analysis |
| **GuardDuty** | Findings, detectors, threat intelligence |
| **SecurityHub** | Findings, compliance standards, security scores |
| **Lambda** | Functions, permissions, configurations, triggers |
| **CloudFront** | Distributions, origins, behaviors, security policies |
| **ELB/ALB/NLB** | Load balancers, target groups, listeners, health checks |
| **Route53** | Hosted zones, DNS records, health checks |
| **WAF** | Web ACLs, rules, rate limiting |
| **Shield** | DDoS protection status and metrics |
| **Access Analyzer** | IAM access analysis and findings |
| **ECS/ECR** | Container services, repositories, image scanning |
| **Organizations** | Account structure, SCPs, organizational units |
| **Athena** | Log analysis, security event correlation |

### Planned Additions

- Oauth Authentication
- AWS Config compliance analysis
- AWS Security Hub CSPM integration
- External CSPM integration

## Advanced Configuration

### Production Deployment

For production environments, use the following configuration:

```yaml
server:
  host: "0.0.0.0"
  log_level: "error"
  startup_quiet: true
  tool_quiet: true
  minimal_logging: true

cross_account:
  max_concurrent_assumptions: 10
  session_duration_seconds: 7200
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8000
CMD ["python", "aws_security_mcp/main.py", "sse"]
```

   ```bash
   docker build -t aws-security-mcp .
   docker run -p 8000:8000 \
     -e AWS_ACCESS_KEY_ID=your_key \
     -e AWS_SECRET_ACCESS_KEY=your_secret \
     aws-security-mcp
   ```

### Load Balancer Configuration

- **Health Check**: `GET /health`
- **SSE Endpoint**: `/sse`
- **Timeout**: 60 seconds minimum
- **Sticky Sessions**: Not required

## Troubleshooting

### Common Issues

**Tool Discovery Fails**
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify cross-account role exists
aws iam get-role --role-name aws-security-mcp-cross-account-access
```

**Cross-Account Access Denied**
```bash
# Test role assumption manually
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET-ACCOUNT:role/aws-security-mcp-cross-account-access \
  --role-session-name test-session
```

**Performance Issues**
```yaml
# Reduce concurrent operations
cross_account:
  max_concurrent_assumptions: 3
  
# Enable minimal logging
server:
  minimal_logging: true
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
export MCP_LOG_LEVEL=debug
export MCP_STARTUP_QUIET=false
python3 aws_security_mcp/main.py sse
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 

## Support

- **Issues**: [GitHub Issues](https://github.com/groovyBugify/aws-security-mcp/issues)
- **Documentation**: [Project Wiki](https://github.com/groovyBugify/aws-security-mcp/wiki)
- **Security Issues**: Please report privately to the maintainers 