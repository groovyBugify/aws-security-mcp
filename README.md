# AWS Security MCP

AWS Security MCP is a Model Context Protocol (MCP) server that enables AI assistants like Claude to interact with AWS security services. Think of it as a bridge that lets AI assistants directly inspect and analyze your AWS infrastructure for security issues, just by asking questions in plain English.


## Features

* **Natural Language Queries**: Ask questions like "show me all running EC2 instances of type t2.large" and get immediate answers
* **Cross-Account Support**: Automatically discovers and queries multiple AWS accounts in your organization
* **Security Analysis**: Query findings from GuardDuty, SecurityHub, and IAM Access Analyzer
* **Resource Inspection**: List and inspect AWS resources for security misconfigurations
* **IAM Analysis**: Analyze roles, policies, and permissions for security issues
* **Network Security**: Examine EC2 instances, security groups, and networking components
* **Threat Intelligence**: Generate threat modeling reports and contextual security recommendations
* **Network Visualization**: Generate network maps to visualize your AWS infrastructure
* **Blast Radius Analysis**: Understand the impact scope of any service, resource, or team
* **Smart Search**: Search seamlessly between your **tagged** resources across accounts
* **Optimized Performance**: Reduced from 110+ tools to 38 streamlined tools with nested functionality

## AWS Services Coverage

### Currently Supported

- **IAM**: Roles, users, policies, access keys, and permission analysis
- **EC2**: Instances, security groups, Elastic Network Interfaces, VPCs, Subnets, and route tables
- **S3**: Buckets, permissions, and public access analysis
- **GuardDuty**: Findings and detectors
- **SecurityHub**: Findings and standards compliance
- **Lambda**: Functions, permissions, and configurations
- **Cloudfront**: Cloudfront Distributions, Origin Mapping, API Route Mapping
- **LoadBalancer**: ALB, ELB, NLB, Target Groups, Listeners
- **Route53**: Hosted Zones, RecordSets
- **WAF**: WebACL, AWS WAF
- **Shield**: AWS DDOS Protection
- **IAM Access Analyser**: Security findings on IAM Access Analyser
- **ECS/ECR**: Container repositories, images, and scan findings
- **Organizations**: AWS Organization structure, accounts, SCPs and organization-level controls

### Work In Progress

- **CloudTrail**: Audit logging analysis
- **KMS**: Key management and encryption
- **Config**: Configuration compliance

## Installation

### Prerequisites

* **uv** (Python package manager) - [Installation Guide](https://docs.astral.sh/uv/getting-started/installation/#installation-methods)
* **Python 3.11+**
* **AWS Account** with proper credentials
* **MCP Client** (Claude Desktop, Cline, 5ire, etc.)

## Configuration

### YAML Configuration (Recommended)

AWS Security MCP uses a `config.yaml` file for easy configuration management. The file is automatically created with sensible defaults. You can customize it for your environment:

```yaml
# AWS Security MCP Configuration
aws:
  region: "us-east-1"              # Your primary AWS region
  profile: null                    # AWS profile (null = auto-detect)

server:
  host: "127.0.0.1"                # Server bind address
  port: 8000                       # Server port
  log_level: "warning"             # debug, info, warning, error, critical
  startup_quiet: true              # Reduce startup noise
  tool_quiet: true                 # Reduce tool execution logs
  minimal_logging: false           # Ultra-minimal mode for production

cross_account:
  role_name: "aws-security-mcp-cross-account-access"
  auto_setup_on_startup: true      # Auto-discover organization accounts
  max_concurrent_assumptions: 5    # Parallel role assumptions
  session_duration_seconds: 3600   # 1 hour session duration
```

### Configuration Priority

The configuration system follows this priority order (highest to lowest):
1. **Environment Variables** (highest priority - always override everything)
2. **config.yaml file** (single source of truth for all defaults)
3. **Emergency fallbacks** (minimal built-in defaults only if config.yaml is missing)

**`config.yaml` is the single source of truth for all default values.** The Python code contains no hardcoded defaults - everything comes from your YAML configuration file.

### Security Note

**AWS credentials are never stored in YAML files.** Always use environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
# export AWS_SESSION_TOKEN=token    # If using temporary credentials
# export AWS_PROFILE=profile_name   # If using AWS profiles
```

### Quick Configuration Examples

**For Development (Verbose Logging):**
```yaml
server:
  log_level: "debug"
  startup_quiet: false
  tool_quiet: false
```

**For Production (Minimal Logging):**
```yaml
server:
  log_level: "error" 
  startup_quiet: true
  tool_quiet: true
  minimal_logging: true
```

**For Large Organizations (Performance Optimized):**
```yaml
cross_account:
  max_concurrent_assumptions: 10
  session_duration_seconds: 7200  # 2 hours
server:
  max_concurrent_requests: 20
```

## Cross-Account Access Setup 

### How Cross-Account Access Works

AWS Security MCP automatically discovers and accesses multiple AWS accounts using a smart approach:

1. **Organization Discovery**: First, it attempts to list accounts using `aws organizations list-accounts`
2. **Role Assumption**: For each discovered account, it tries to assume the IAM role: `aws-security-mcp-cross-account-access`
3. **Fallback**: If an account is not part of an AWS Organization, it defaults to standard AWS credential resolution (profile/environment/IMDS/ECS)

### Setting Up Cross-Account Access

For each AWS account you want to access, create an IAM role with these specifications:

**Role Name:** `aws-security-mcp-cross-account-access`

**Trust Policy:**
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

**Attached Policy:** `SecurityAudit` (AWS Managed Policy)

This setup allows the MCP server to securely access resources across all your AWS accounts with read-only security permissions.


## MCP Client Setup (Step-by-Step)

### Primary Method: Server-Sent Events (SSE) - Recommended

**This is the primary and recommended way to run AWS Security MCP.** SSE provides better performance, stability, and compatibility with various MCP clients.

1. **Configure your AWS Credentials**: 

   AWS Security MCP automatically detects and uses AWS credentials from your ~/.aws/credentials, AWS_PROFILE, env variables or metadata endpoints.
   
   **Required IAM Permissions**: Your default AWS profile/credentials must have the following permissions:
   
   1. **Cross-Account Role Assumption Policy:**
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
               "Resource": [
                   "arn:aws:iam::*:role/aws-security-mcp-cross-account-access"
               ]
           }
       ]
   }
   ```
   
   2. **Organization Discovery Policy:**
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Sid": "OrganizationAccess",
               "Effect": "Allow",
               "Action": [
                   "organizations:ListAccounts"
               ],
               "Resource": "*"
           }
       ]
   }
   ```
   
   3. **AWS SecurityAudit Managed Policy** (attach to your user/role):
   ```
   arn:aws:iam::aws:policy/SecurityAudit
   ```
   
   **Important**: These permissions allow the default profile to discover organization accounts, assume cross-account roles, and perform security audits across your AWS infrastructure.
   
   **Security Note**: At no point can the MCP Client retrieve AWS credentials. All credential handling is done securely by the MCP server, and only API responses are shared with the client.
   
   **Cross-Account Access**: The system automatically discovers AWS Organization accounts and assumes the `aws-security-mcp-cross-account-access` role where available.

2. **Start the SSE Server locally:**
   ```bash
   # Navigate to the aws-security-mcp directory
   cd /path/to/aws-security-mcp
   
   # Start the SSE server
   python aws_security_mcp/main.py sse
   ```

2. **Configure Your MCP Client:**
   
   **For Claude Desktop with SSE:**
   
   First, install the mcp-proxy tool:
   ```bash
   # Install mcp-proxy using uv
   uv tool install mcp-proxy
   
   # Find the absolute path of mcp-proxy (you'll need this for the config)
   which mcp-proxy
   # Example output: /Users/username/.local/bin/mcp-proxy
   ```
   
   Then configure Claude Desktop:
   ```json
   {
     "mcpServers": {
       "aws-security": {
         "command": "/Users/username/.local/bin/mcp-proxy",
         "args": ["http://localhost:8000/sse"]
       }
     }
   }
   ```
   
   **Important:** Replace `/Users/username/.local/bin/mcp-proxy` with the actual path from the `which mcp-proxy` command above.

   **For Other MCP Clients:**
   - Connect to: `http://localhost:8000/sse`
   - Use Server-Sent Events transport
   - Health check: `http://localhost:8000/health`

### Alternative Method: stdio (Claude Desktop Legacy)

**Note:** This method is kept for backward compatibility but SSE is recommended.

1. **Configure Claude Desktop with stdio:**
   ```json
   {
     "mcpServers": {
       "aws-security": {
         "command": "/full/path/to/aws-security-mcp/run_aws_security.sh",
         "args": ["stdio"]
       }
     }
   }
   ```

2. **Direct File Edit Locations:**
   - **macOS:** `/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
   - **Linux:** `~/.config/Claude/claude_desktop_config.json`

3. **Restart Claude Desktop** to load the new configuration

## Advanced SSE Usage

### Testing and Development

1. **Test with MCP Inspector:**
   ```bash
   # Use the MCP Inspector to test the connection:
   npx @modelcontextprotocol/inspector http://127.0.0.1:8000/sse
   ```

2. **Direct SSE Testing:**
   ```bash
   # Test the SSE endpoint directly:
   curl -N -H "Accept: text/event-stream" http://localhost:8000/sse
   ```

3. **Health Check:**
   ```bash
   # Check server health:
   curl http://localhost:8000/health
   ```

### Production Deployment

1. **Docker Deployment:**
   ```bash
   # Build the container:
   docker build -t aws-security-mcp .
   
   # Run with environment variables:
   docker run -p 8000:8000 \
     -e AWS_ACCESS_KEY_ID=your_key \
     -e AWS_SECRET_ACCESS_KEY=your_secret \
     -e AWS_DEFAULT_REGION=us-east-1 \
     aws-security-mcp
   ```

2. **Configuration Methods:**

   **Option A: YAML Configuration (Recommended)**
   
   Edit the `config.yaml` file in the project root:
   ```yaml
   server:
     host: "0.0.0.0"          # Bind to all interfaces
     port: 8000               # Server port
     log_level: "warning"     # Logging level
     startup_quiet: true      # Suppress startup details
     tool_quiet: true         # Suppress tool execution logs
     minimal_logging: true    # Ultra-minimal output mode
   
   aws:
     region: "us-east-1"      # Your preferred AWS region
     profile: null            # AWS profile (leave null for auto-detection)
   
   cross_account:
     auto_setup_on_startup: true    # Auto-discover accounts
     max_concurrent_assumptions: 5  # Parallel role assumptions
   ```
   
   **Option B: Environment Variables (Legacy)**
   ```bash
   # Optional SSE configuration
   export MCP_HOST=0.0.0.0          # Bind to all interfaces
   export MCP_PORT=8000             # Server port
   export MCP_LOG_LEVEL=warning     # Logging level (debug, info, warning, error, critical)
   export MCP_DEBUG=false           # Debug mode
   
   # Minimal logging options
   export MCP_MINIMAL_LOGGING=true  # Ultra-minimal output mode
   export MCP_STARTUP_QUIET=true    # Suppress startup details
   export MCP_TOOL_QUIET=true       # Suppress tool execution logs
   ```
   
   **Note:** AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) must always be set as environment variables for security. Environment variables always override YAML settings.

### Load Balancer Configuration

When deploying behind a load balancer:

- **Health Check Path:** `/health`
- **SSE Endpoint:** `/sse` 
- **Important:** Configure your load balancer to NOT redirect `/sse` to `/sse/`
- **Sticky Sessions:** Not required (stateless design)
- **Timeout:** Set appropriate timeouts for SSE connections (recommended: 30+ seconds)

### Benefits of SSE over stdio

- **Better Performance:** Reduced overhead and better resource management
- **Scalability:** Multiple clients can connect to the same server
- **Monitoring:** Built-in health checks and observability
- **Cloud Native:** Works seamlessly in containerized environments
- **Flexibility:** Compatible with various MCP clients and custom integrations

## Sample Queries and Usage

### Cross-Account Queries

**Query:** "Can you share connected AWS accounts?"

**Response:** The MCP tool will return a list of all AWS accounts in your organization that the server can access, including account IDs, names, and status.

**Query:** "Can you refresh my AWS session?"

**Response:** The MCP tool refreshes all valid boto3 sessions across multiple AWS accounts, ensuring you have the latest credentials and permissions.

### Infrastructure Queries

**Query:** "As an experienced Senior Security Engineer, find the following \"172.24.12.44\" IP in all my connected aws accounts, and post that do a blast radius analysis of the associated AWS Resources with the IP address."

**Query:** "using \"sequentialThinking\" tool, find the subdomain *subdomain.example.com* in my route53 account, post that share a network visualisation graph"

**Query:** "list all resources tagged under Team: Security"

**Query:** "find all domains under my route53 that have "/login" added under the behaiour of the associated cloudfront distributions."

**Query:** "Generate a network map for my production environment"

**Query:** "What's the blast radius if the web-tier security group is compromised?"

## Performance Optimization

### Streamlined Tool Architecture

AWS Security MCP has been optimized from **110+ individual tools** to **38 core tools** with nested functionality. This provides several benefits:

- **Reduced Memory Usage**: Prevents server memory errors in resource-constrained environments
- **Faster Loading**: Quicker startup and tool discovery
- **Better Organization**: Related functions are grouped logically
- **Improved Reliability**: Fewer tools mean less complexity and fewer failure points

## Running AWS Security MCP on Steroids

You can combine AWS Security MCP with other MCP servers for enhanced capabilities:

### Recommended MCP Combinations

- **[Sequential Thinking](https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking)**: For complex reasoning and analysis
- **[Shodan](https://github.com/BurtTheCoder/mcp-shodan)**: For external threat intelligence
- **[Brave Web Search](https://github.com/modelcontextprotocol/servers/tree/main/src/brave-search)**: For researching security vulnerabilities
- **[CVE Search](https://github.com/modelcontextprotocol/servers/tree/main/src/cve)**: For vulnerability database queries

### Example Multi-MCP Configuration

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "/Users/username/.local/bin/mcp-proxy",
      "args": [
        "http://localhost:8000/sse"
      ]
    },
    "shodan": {
      "command": "npx",
      "args": ["@mcp/shodan"],
      "env": {
        "SHODAN_API_KEY": "your-shodan-key"
      }
    },
    "brave-search": {
      "command": "npx",
      "args": ["@mcp/brave-search"],
      "env": {
        "BRAVE_API_KEY": "your-brave-key"
      }
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **"No tools available" or empty tool list:**
   - Check AWS credentials are properly configured
   - Verify the `run_aws_security.sh` script is executable
   - Ensure you're using Claude Pro (free version has token limitations)

2. **Cross-account access not working:**
   - Verify the `aws-security-mcp-cross-account-access` role exists in target accounts
   - Check the trust policy allows your master account
   - Ensure the SecurityAudit policy is attached

3. **MCP server crashes or memory errors:**
   - This should be resolved with the new 38-tool architecture
   - If issues persist, check system resources and Python memory limits

4. **Slow response times:**
   - Large AWS environments may take time to query
   - Consider using more specific queries to reduce scope
   - Check AWS API rate limits in CloudTrail

### Debugging

**MCP Server Logs:**
- **macOS:** `/Users/{userName}/Library/Logs/Claude`
- **Windows:** `%APPDATA%\Claude\Logs`
- **Linux:** `~/.local/share/Claude/Logs`

**Enable Debug Mode:**
```bash
# Add to run_aws_security.sh
export MCP_DEBUG=true
export AWS_SDK_DEBUG=true
```

**Reduce Logging Verbosity:**
```bash
# For minimal output (only errors and critical messages)
export MCP_LOG_LEVEL=error
export MCP_MINIMAL_LOGGING=true
export MCP_STARTUP_QUIET=true
export MCP_TOOL_QUIET=true

# For moderate output (warnings and above)
export MCP_LOG_LEVEL=warning
export MCP_STARTUP_QUIET=true

# For default output but without startup noise
export MCP_STARTUP_QUIET=true
```

**Example Output with Progress Bars:**
```bash
# With startup_quiet=false (default)
Starting MCP server...
Setting up AWS environment...
Validating AWS credentials...
AWS credentials validated successfully
Initializing cross-account credential sessions...
Assuming roles: [████████░░] 8/10 accounts (8 successful, 2 failed)
Cross-account setup complete: 8 successful, 2 failed (10 total)
Registering MCP tools...
Tool registration complete: 45 tools registered
Multi-account tools available (sessions: 8)
AWS Security MCP ready: 8 accounts accessible

# With startup_quiet=true
Assuming roles: [████████░░] 8/10 accounts (8 successful, 2 failed)
AWS Security MCP ready: 8 accounts accessible

# Examples with different account counts:
# 3 accounts: Assuming roles: [██░] 2/3 accounts (2 successful, 1 failed)
# 5 accounts: Assuming roles: [████░] 4/5 accounts (4 successful, 1 failed) 
# 15 accounts: Assuming roles: [████████████░░░] 12/15 accounts (11 successful, 1 failed)
# 50+ accounts: Assuming roles: [████████████████████████████████████████████████░░] 48/52 accounts (capped at 50 chars)
```

**Test MCP Server Directly:**
```bash
# Test the server without Claude
python -m aws_security_mcp.server --transport stdio
```

## Security Considerations

- **Least Privilege**: The SecurityAudit policy provides read-only access
- **Credential Management**: Use IAM roles instead of access keys when possible
- **Network Security**: Consider running in private subnets for production use
- **Audit Logging**: All AWS API calls are logged in CloudTrail
- **Session Management**: Sessions are automatically refreshed and expire safely

## System Requirements

- **Memory**: Minimum 2GB RAM (4GB recommended for large AWS environments)
- **Python**: Version 3.11 or higher
- **Network**: Internet access for AWS API calls
- **Disk Space**: ~100MB for installation and logs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
