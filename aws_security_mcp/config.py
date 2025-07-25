"""Configuration management for AWS Security MCP."""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, Union
import logging

from dotenv import load_dotenv
from pydantic import BaseModel, Field, validator

# Load environment variables from .env file if present
load_dotenv()

def load_yaml_config() -> Dict[str, Any]:
    """Load configuration from config.yaml file.
    
    Returns:
        Dictionary containing configuration from YAML file
    """
    # Look for config.yaml in the project root (parent directory of aws_security_mcp)
    config_paths = [
        Path(__file__).parent.parent / "config.yaml",  # Project root
        Path("config.yaml"),                          # Current directory
        Path(__file__).parent / "config.yaml",       # Same directory as this file
    ]
    
    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                logging.getLogger(__name__).warning(f"Error loading config from {config_path}: {e}")
                continue
    
    # If no config file found, return minimal defaults (config.yaml should exist)
    logging.getLogger(__name__).warning("No config.yaml found, using minimal built-in defaults")
    return {
        "aws": {
            "region": "us-east-1",
            "profile": None
        },
        "server": {
            "host": "127.0.0.1",
            "port": 8000,
            "log_level": "info",
            "debug": False,
            "minimal_logging": False,
            "startup_quiet": True,
            "tool_quiet": True,
            "max_concurrent_requests": 10,
            "client_cache_ttl": 3600
        },
        "cross_account": {
            "role_name": "aws-security-mcp-cross-account-access",
            "session_name": "aws-security-mcp-session",
            "session_duration_seconds": 14400,
            "refresh_threshold_minutes": 30,
            "auto_setup_on_startup": True,
            "auto_refresh_enabled": True,
            "max_concurrent_assumptions": 50,
            "connection_pool_size": 100,
            "retry_max_attempts": 3,
            "retry_backoff_factor": 1.5,
            "progress_update_interval": 10
        }
    }

class AWSConfig(BaseModel):
    """AWS configuration settings."""
    
    # AWS credentials - ALWAYS from environment variables for security
    aws_access_key_id: Optional[str] = Field(
        description="AWS access key ID (environment variable only)"
    )
    aws_secret_access_key: Optional[str] = Field(
        description="AWS secret access key (environment variable only)"
    )
    aws_session_token: Optional[str] = Field(
        description="AWS session token for temporary credentials (environment variable only)"
    )
    
    # Non-sensitive AWS settings - from YAML with environment overrides
    aws_region: str = Field(
        description="AWS region for API calls"
    )
    aws_profile: Optional[str] = Field(
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
            logging.getLogger(__name__).debug(f"ECS task role validated: {identity.get('Arn', 'Unknown ARN')}")
            return True
            
        except Exception as e:
            logging.getLogger(__name__).error(f"ECS task role validation failed: {e}")
            return False

class CrossAccountConfig(BaseModel):
    """Cross-account credential configuration settings."""
    
    role_name: str = Field(
        description="Name of the role to assume in target accounts"
    )
    session_name: str = Field(
        description="Session name for assumed roles"
    )
    session_duration_seconds: int = Field(
        description="Duration of assumed role sessions in seconds"
    )
    refresh_threshold_minutes: int = Field(
        description="Refresh sessions when they expire within this many minutes"
    )
    auto_setup_on_startup: bool = Field(
        description="Automatically set up cross-account sessions on server startup"
    )
    auto_refresh_enabled: bool = Field(
        description="Automatically refresh expiring sessions"
    )
    max_concurrent_assumptions: int = Field(
        description="Maximum number of concurrent role assumptions (0 = unlimited)"
    )
    connection_pool_size: int = Field(
        description="Size of boto3 connection pool for STS client"
    )
    retry_max_attempts: int = Field(
        description="Maximum retry attempts for failed assume role operations"
    )
    retry_backoff_factor: float = Field(
        description="Exponential backoff factor for retries (seconds)"
    )
    progress_update_interval: int = Field(
        description="Update progress every N accounts processed (0 = every account)"
    )

class AthenaConfig(BaseModel):
    """Athena configuration settings."""
    
    default_output_location: str = Field(
        description="Default S3 location for Athena query results"
    )
    default_workgroup: str = Field(
        description="Default Athena workgroup for queries"
    )
    default_catalog: str = Field(
        description="Default data catalog for Athena queries"
    )
    
    @validator('default_output_location')
    def validate_output_location(cls, v: str) -> str:
        """Validate S3 output location format."""
        if not v:
            raise ValueError("Default output location cannot be empty")
        
        if not v.startswith('s3://'):
            raise ValueError("Default output location must be a valid S3 URI starting with 's3://'")
        
        if v == 's3://':
            raise ValueError("Default output location must include bucket name")
        
        if not v.endswith('/'):
            raise ValueError("Default output location should end with '/' to specify a directory")
        
        return v

class MCPServerConfig(BaseModel):
    """MCP server configuration settings."""
    
    host: str = Field(
        description="Host address to bind the server"
    )
    port: int = Field(
        description="Port to run the server on"
    )
    debug: bool = Field(
        description="Enable debug mode"
    )
    log_level: str = Field(
        description="Logging level"
    )
    minimal_logging: bool = Field(
        description="Enable minimal logging mode for production"
    )
    startup_quiet: bool = Field(
        description="Suppress detailed startup logging"
    )
    tool_quiet: bool = Field(
        description="Suppress tool execution logging"
    )
    max_concurrent_requests: int = Field(
        description="Maximum number of concurrent AWS API requests"
    )
    client_cache_ttl: int = Field(
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
    
    aws: AWSConfig
    server: MCPServerConfig
    cross_account: CrossAccountConfig
    athena: AthenaConfig
    
    class Config:
        """Pydantic config options."""
        extra = "ignore"

def load_config() -> AppConfig:
    """Load configuration from config.yaml and environment variables.
    
    Returns:
        AppConfig instance with loaded configuration
    """
    # Load YAML configuration (single source of truth for defaults)
    yaml_config = load_yaml_config()
    
    # AWS configuration - credentials from env, settings from YAML with env overrides
    aws_yaml = yaml_config.get("aws", {})
    aws_config = {
        # Credentials - environment only (never in YAML)
        "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "aws_session_token": os.getenv("AWS_SESSION_TOKEN"),
        
        # Non-sensitive settings - YAML defaults with env override
        "aws_region": os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or aws_yaml.get("region"),
        "aws_profile": os.getenv("AWS_PROFILE") or aws_yaml.get("profile"),
    }
    
    # Server configuration - YAML defaults with environment overrides
    server_yaml = yaml_config.get("server", {})
    server_config = {
        "host": os.getenv("MCP_HOST") or server_yaml.get("host"),
        "port": int(os.getenv("MCP_PORT") or server_yaml.get("port")),
        "debug": _parse_bool(os.getenv("MCP_DEBUG")) if os.getenv("MCP_DEBUG") else server_yaml.get("debug"),
        "log_level": os.getenv("MCP_LOG_LEVEL") or server_yaml.get("log_level"),
        "minimal_logging": _parse_bool(os.getenv("MCP_MINIMAL_LOGGING")) if os.getenv("MCP_MINIMAL_LOGGING") else server_yaml.get("minimal_logging"),
        "startup_quiet": _parse_bool(os.getenv("MCP_STARTUP_QUIET")) if os.getenv("MCP_STARTUP_QUIET") else server_yaml.get("startup_quiet"),
        "tool_quiet": _parse_bool(os.getenv("MCP_TOOL_QUIET")) if os.getenv("MCP_TOOL_QUIET") else server_yaml.get("tool_quiet"),
        "max_concurrent_requests": int(os.getenv("MCP_MAX_CONCURRENT_REQUESTS") or server_yaml.get("max_concurrent_requests")),
        "client_cache_ttl": int(os.getenv("MCP_CLIENT_CACHE_TTL") or server_yaml.get("client_cache_ttl")),
    }
    
    # Cross-account configuration - YAML defaults with environment overrides
    cross_account_yaml = yaml_config.get("cross_account", {})
    cross_account_config = {
        "role_name": os.getenv("MCP_CROSS_ACCOUNT_ROLE_NAME") or cross_account_yaml.get("role_name"),
        "session_name": os.getenv("MCP_CROSS_ACCOUNT_SESSION_NAME") or cross_account_yaml.get("session_name"),
        "session_duration_seconds": int(os.getenv("MCP_SESSION_DURATION_SECONDS") or cross_account_yaml.get("session_duration_seconds")),
        "refresh_threshold_minutes": int(os.getenv("MCP_REFRESH_THRESHOLD_MINUTES") or cross_account_yaml.get("refresh_threshold_minutes")),
        "auto_setup_on_startup": _parse_bool(os.getenv("MCP_AUTO_SETUP_SESSIONS")) if os.getenv("MCP_AUTO_SETUP_SESSIONS") else cross_account_yaml.get("auto_setup_on_startup"),
        "auto_refresh_enabled": _parse_bool(os.getenv("MCP_AUTO_REFRESH_ENABLED")) if os.getenv("MCP_AUTO_REFRESH_ENABLED") else cross_account_yaml.get("auto_refresh_enabled"),
        "max_concurrent_assumptions": int(os.getenv("MCP_MAX_CONCURRENT_ASSUMPTIONS") or cross_account_yaml.get("max_concurrent_assumptions")),
        "connection_pool_size": int(os.getenv("MCP_CONNECTION_POOL_SIZE") or cross_account_yaml.get("connection_pool_size")),
        "retry_max_attempts": int(os.getenv("MCP_RETRY_MAX_ATTEMPTS") or cross_account_yaml.get("retry_max_attempts")),
        "retry_backoff_factor": float(os.getenv("MCP_RETRY_BACKOFF_FACTOR") or cross_account_yaml.get("retry_backoff_factor")),
        "progress_update_interval": int(os.getenv("MCP_PROGRESS_UPDATE_INTERVAL") or cross_account_yaml.get("progress_update_interval")),
    }
    
    # Athena configuration - YAML defaults with environment overrides
    athena_yaml = yaml_config.get("athena", {})
    athena_config = {
        "default_output_location": os.getenv("MCP_ATHENA_OUTPUT_LOCATION") or athena_yaml.get("default_output_location"),
        "default_workgroup": os.getenv("MCP_ATHENA_WORKGROUP") or athena_yaml.get("default_workgroup"),
        "default_catalog": os.getenv("MCP_ATHENA_CATALOG") or athena_yaml.get("default_catalog"),
    }
    
    # Create the config object
    app_config = AppConfig(
        aws=AWSConfig(**aws_config),
        server=MCPServerConfig(**server_config),
        cross_account=CrossAccountConfig(**cross_account_config),
        athena=AthenaConfig(**athena_config),
    )
    
    # Verify AWS credential configuration and log information
    if not app_config.server.startup_quiet:
        logger = logging.getLogger(__name__)
        logger.debug(f"AWS Region: {app_config.aws.aws_region}")
        
        if app_config.aws.has_profile:
            logger.debug(f"AWS credentials source: Profile ({app_config.aws.aws_profile})")
        elif app_config.aws.has_sts_credentials:
            logger.debug("AWS credentials source: STS temporary credentials")
        elif app_config.aws.has_iam_credentials:
            logger.debug("AWS credentials source: IAM access key credentials")
        else:
            # Provide more specific logging for container environments
            if app_config.aws.is_ecs_environment:
                logger.debug("AWS credentials source: ECS Task Role (auto-resolution)")
            elif app_config.aws.is_ec2_environment:
                logger.debug("AWS credentials source: EC2 Instance Profile (auto-resolution)")
            else:
                logger.debug(
                    "AWS credentials source: Auto-resolution (environment variables, ~/.aws/credentials, ECS task role, or instance profile)"
                )
    
    return app_config

def _parse_bool(value: str) -> bool:
    """Parse string boolean values."""
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "1", "yes", "on")

# Global config instance
config = load_config() 