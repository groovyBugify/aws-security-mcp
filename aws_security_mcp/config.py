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
        
        # Basic format validation
        if not v.startswith("us-") and not v.startswith("eu-") and not v.startswith("ap-"):
            raise ValueError(f"Invalid AWS region format: {v}")
        
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
            return "auto"  # Let boto3 handle credential resolution

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
    
    class Config:
        """Pydantic config options."""
        extra = "ignore"

def load_config() -> AppConfig:
    """Load configuration from environment variables.
    
    Returns:
        AppConfig instance with loaded configuration
    """
    # Extract AWS configuration from environment
    aws_config = {
        "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "aws_session_token": os.getenv("AWS_SESSION_TOKEN"),
        "aws_region": os.getenv("AWS_REGION", "ap-south-1"),
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
    
    # Create the config object
    app_config = AppConfig(
        aws=AWSConfig(**aws_config),
        server=MCPServerConfig(**server_config),
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
        logging.getLogger(__name__).info(
            "AWS credentials source: Auto-resolution (environment variables, ~/.aws/credentials, or instance profile)"
        )
    
    return app_config

# Global config instance
config = load_config() 