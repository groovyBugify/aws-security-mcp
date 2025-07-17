[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/groovybugify-aws-security-mcp-badge.png)](https://mseep.ai/app/groovybugify-aws-security-mcp)

# AWS Security MCP

AWS Security MCP is a Model Context Protocol server that provides a MCP Client like Claude to interact to AWS security services, allowing AI assistants to autonomously inspect and analyze your AWS infrastructure for security issues.

## Features

* Query AWS Infrastructure with Natural Lang query for example - "share a list of running ec2 instances that are of type t2.large"
* Query security findings from GuardDuty, SecurityHub, and IAM Access Analyzer
* List and inspect AWS resources for security misconfigurations
* Analyze IAM roles, policies, and permissions for security issues
* Examine EC2 instances, security groups, and networking components
* Scan for sensitive information in environment variables and configurations
* Generate Threat Modelling reports on the fly
* Generate Contextual Security Recommendations on the fly
* Generate network map on the fly to visualise how network map of you AWS Infrastructure Looks like
* Generate blast radius analysis of any service/resource or teams that are tagged.
* Search Seamlessly between you **tagged** resources

## AWS Services Coverage

### Currently Supported

- **IAM**: Roles, users, policies, access keys, and permission analysis
- **EC2**: Instances, security groups, Elastic Network Interfaces, VPCs, Subnets, and route tables
- **S3**: Buckets, permissions, and public access analysis
- **GuardDuty**: Findings and detectors
- **SecurityHub**: Findings and standards compliance
- **Lambda**: Functions, permissions, and configurations
- **Cloudfront**: Cloudfront Distributions, Origin Mapping, API Route Mapping
- **LoadBalancer**: ALB, ELB, NLB, Target Groups, Listeners,
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

* uv
* Python 3.11+
* AWS Account with proper credentials - Can work with either AWS Access Keys or AWS STS Credentials!
* MCP Client (Claude Desktop, Cline, 5ire, etc.)

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/groovyBugify/aws-security-mcp.git
   cd aws-security-mcp
   ```
2. Make sure you have installed `uv` https://docs.astral.sh/uv/getting-started/installation/#installation-methods

2. Make the runner script executable:
   ```bash
   chmod +x run_aws_security.sh
   ```
3. Update `run_aws_security.sh` file with valid AWS Credentials 
    ```bash
    export AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY=YOUR_SECRET_ACCESS_KEY
    ```

> You can utilise AWS STS Credentials, AWS Profiles as well, you just need to export them before running the MCP Client.

## MCP Client Setup

Theoretically, any MCP client should work with AWS Security MCP. Sharing Claude Desktop setup below.

To set up Claude Desktop as an AWS Security MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "/path/to/aws-security-mcp/run_aws_security.sh"
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

## Running AWS Security MCP on steroids

Using any MCP Client we can couple multiple MCPs toghthere for example - 

*   [Sequentialthinking](https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking)
*   [Shodan](https://github.com/BurtTheCoder/mcp-shodan)
*   [Brave-WebSearch](https://github.com/modelcontextprotocol/servers/tree/main/src/brave-search)

## Troubleshooting

If at any point you face issues with running the MCP server, you can try checking the MCP Server logs that are usually stored on your system `/Users/{userName}/Library/Logs/Claude`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
