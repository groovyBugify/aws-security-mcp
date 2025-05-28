"""Configuration management for AWS Security MCP."""

import os
from pathlib import Path
from typing import Any, Dict, Optional, Union
import logging

from dotenv import load_dotenv
from pydantic import BaseModel, Field, validator

# Load environment variables from .env file if present
load_dotenv()

class AWSConfig(BaseModel):
    """AWS configuration settings."""
    
    aws_access_key_id: Optional[str] = Field(
        default=None, 
        description="AWS access key ID"
    )
    aws_secret_access_key: Optional[str] = Field(
        default=None, 
        description="AWS secret access key"
    )
    aws_session_token: Optional[str] = Field(
        default=None, 
        description="AWS session token for temporary credentials"
    )
    aws_region: str = Field(
        default="ap-south-1",
        description="AWS region for API calls"
    )
    aws_profile: Optional[str] = Field(
        default=None,
        description="AWS profile name to use"
    )
    
    @validator('aws_region')
    def validate_region(cls, v: str) -> str:
        """Validate AWS region format."""
        if not v:
            return "us-east-1"
        
        # Basic format validation for common region prefixes
        valid_prefixes = ["us-", "eu-", "ap-", "ca-", "sa-", "af-", "me-"]
        if not any(v.startswith(prefix) for prefix in valid_prefixes):
            raise ValueError(f"Invalid AWS region format: {v}. Must start with one of {valid_prefixes}")
        
        return v
    
    @property
    def has_iam_credentials(self) -> bool:
        """Check if IAM access key credentials are set."""
        return bool(self.aws_access_key_id and self.aws_secret_access_key)
    
    @property
    def has_sts_credentials(self) -> bool:
        """Check if STS temporary credentials are set."""
        return bool(self.aws_access_key_id and self.aws_secret_access_key and self.aws_session_token)
    
    @property
    def has_profile(self) -> bool:
        """Check if an AWS profile is set."""
        return bool(self.aws_profile)
    
    @property
    def credentials_source(self) -> str:
        """Determine the source of credentials to use."""
        if self.has_profile:
            return "profile"
        elif self.has_sts_credentials:
            return "sts"
        elif self.has_iam_credentials:
            return "iam"
        else:
            return "auto"  # Let boto3 handle credential resolution (ECS task role, instance profile, etc.)
    
    @property
    def is_ecs_environment(self) -> bool:
        """Check if running in ECS environment."""
        import os
        # ECS provides these environment variables
        return bool(
            os.getenv("AWS_EXECUTION_ENV") or 
            os.getenv("ECS_CONTAINER_METADATA_URI") or
            os.getenv("ECS_CONTAINER_METADATA_URI_V4") or
            os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        )
    
    @property
    def is_ec2_environment(self) -> bool:
        """Check if running in EC2 environment with instance profile."""
        import os
        # EC2 instance metadata service availability (simplified check)
        return bool(os.getenv("AWS_EXECUTION_ENV") == "EC2-Instance")
    
    def validate_ecs_credentials(self) -> bool:
        """Validate that ECS task role credentials are accessible.
        
        Returns:
            True if ECS credentials are accessible, False otherwise
        """
        if not self.is_ecs_environment:
            return False
            
        try:
            import boto3
            # Try to create a session and get caller identity
            session = boto3.Session(region_name=self.aws_region)
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            
            # If we get here, credentials are working
            logging.getLogger(__name__).info(f"✅ ECS task role validated: {identity.get('Arn', 'Unknown ARN')}")
            return True
            
        except Exception as e:
            logging.getLogger(__name__).error(f"❌ ECS task role validation failed: {e}")
            return False

class CrossAccountConfig(BaseModel):
    """Cross-account credential configuration settings."""
    
    role_name: str = Field(
        default="aws-security-mcp-cross-account-access",
        description="Name of the role to assume in target accounts"
    )
    session_name: str = Field(
        default="aws-security-mcp-session",
        description="Session name for assumed roles"
    )
    session_duration_seconds: int = Field(
        default=3600,
        description="Duration of assumed role sessions in seconds"
    )
    refresh_threshold_minutes: int = Field(
        default=10,
        description="Refresh sessions when they expire within this many minutes"
    )
    auto_setup_on_startup: bool = Field(
        default=True,
        description="Automatically set up cross-account sessions on server startup"
    )
    auto_refresh_enabled: bool = Field(
        default=True,
        description="Automatically refresh expiring sessions"
    )
    max_concurrent_assumptions: int = Field(
        default=5,
        description="Maximum number of concurrent role assumptions"
    )

class MCPServerConfig(BaseModel):
    """MCP server configuration settings."""
    
    host: str = Field(
        default="127.0.0.1",
        description="Host address to bind the server"
    )
    port: int = Field(
        default=8000,
        description="Port to run the server on"
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode"
    )
    log_level: str = Field(
        default="info",
        description="Logging level"
    )
    max_concurrent_requests: int = Field(
        default=10,
        description="Maximum number of concurrent AWS API requests"
    )
    client_cache_ttl: int = Field(
        default=3600,
        description="Time to live for cached AWS clients in seconds"
    )
    
    @validator('log_level')
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["debug", "info", "warning", "error", "critical"]
        if v.lower() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.lower()

class AppConfig(BaseModel):
    """Main application configuration."""
    
    aws: AWSConfig = Field(default_factory=AWSConfig)
    server: MCPServerConfig = Field(default_factory=MCPServerConfig)
    cross_account: CrossAccountConfig = Field(default_factory=CrossAccountConfig)
    
    class Config:
        """Pydantic config options."""
        extra = "ignore"

def load_config() -> AppConfig:
    """Load configuration from environment variables.
    
    Returns:
        AppConfig instance with loaded configuration
    """
    # Extract AWS configuration from environment
    # For ECS tasks, AWS_DEFAULT_REGION is more commonly used than AWS_REGION
    aws_region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
    
    aws_config = {
        "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "aws_session_token": os.getenv("AWS_SESSION_TOKEN"),
        "aws_region": aws_region,
        "aws_profile": os.getenv("AWS_PROFILE"),
    }
    
    # Extract server configuration from environment
    server_config = {
        "host": os.getenv("MCP_HOST", "127.0.0.1"),
        "port": int(os.getenv("MCP_PORT", "8000")),
        "debug": os.getenv("MCP_DEBUG", "False").lower() in ("true", "1", "yes"),
        "log_level": os.getenv("MCP_LOG_LEVEL", "info"),
        "max_concurrent_requests": int(os.getenv("MCP_MAX_CONCURRENT_REQUESTS", "10")),
        "client_cache_ttl": int(os.getenv("MCP_CLIENT_CACHE_TTL", "3600")),
    }
    
    # Extract cross-account configuration from environment
    cross_account_config = {
        "role_name": os.getenv("MCP_CROSS_ACCOUNT_ROLE_NAME", "aws-security-mcp-cross-account-access"),
        "session_name": os.getenv("MCP_CROSS_ACCOUNT_SESSION_NAME", "aws-security-mcp-session"),
        "session_duration_seconds": int(os.getenv("MCP_SESSION_DURATION_SECONDS", "3600")),
        "refresh_threshold_minutes": int(os.getenv("MCP_REFRESH_THRESHOLD_MINUTES", "10")),
        "auto_setup_on_startup": os.getenv("MCP_AUTO_SETUP_SESSIONS", "True").lower() in ("true", "1", "yes"),
        "auto_refresh_enabled": os.getenv("MCP_AUTO_REFRESH_ENABLED", "True").lower() in ("true", "1", "yes"),
        "max_concurrent_assumptions": int(os.getenv("MCP_MAX_CONCURRENT_ASSUMPTIONS", "5")),
    }
    
    # Create the config object
    app_config = AppConfig(
        aws=AWSConfig(**aws_config),
        server=MCPServerConfig(**server_config),
        cross_account=CrossAccountConfig(**cross_account_config),
    )
    
    # Verify AWS credential configuration and log information
    logging.getLogger(__name__).info(f"AWS Region: {app_config.aws.aws_region}")
    
    if app_config.aws.has_profile:
        logging.getLogger(__name__).info(f"AWS credentials source: Profile ({app_config.aws.aws_profile})")
    elif app_config.aws.has_sts_credentials:
        logging.getLogger(__name__).info("AWS credentials source: STS temporary credentials")
    elif app_config.aws.has_iam_credentials:
        logging.getLogger(__name__).info("AWS credentials source: IAM access key credentials")
    else:
        # Provide more specific logging for container environments
        if app_config.aws.is_ecs_environment:
            logging.getLogger(__name__).info("AWS credentials source: ECS Task Role (auto-resolution)")
        elif app_config.aws.is_ec2_environment:
            logging.getLogger(__name__).info("AWS credentials source: EC2 Instance Profile (auto-resolution)")
        else:
            logging.getLogger(__name__).info(
                "AWS credentials source: Auto-resolution (environment variables, ~/.aws/credentials, ECS task role, or instance profile)"
            )
    
    return app_config

# Global config instance
config = load_config() 