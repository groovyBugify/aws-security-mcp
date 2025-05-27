#!/bin/bash

# AWS Security MCP Launcher
# This script ensures all dependencies are installed and runs the application


# Determine script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"


# Install dependencies directly with uv (no virtual env)
uv pip install -r requirements.txt

# Set environment variables for Python to find modules
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"


# AWS credentials should be set before running
# You can either set them here as environment variables:
# export AWS_ACCESS_KEY_ID=access-key
# export AWS_SECRET_ACCESS_KEY=secret-key
# export AWS_DEFAULT_REGION=your_region
# Or use AWS CLI profiles:
# export AWS_PROFILE=default
# export AWS_DEFAULT_REGION=us-east-1

# Run the module with uv to ensure dependencies are available
uv run aws_security_mcp/main.py 