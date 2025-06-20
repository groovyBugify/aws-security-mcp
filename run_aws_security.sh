#!/bin/bash

# AWS Security MCP Launcher
# This script ensures all dependencies are installed and runs the application

# Function to display usage
show_usage() {
    echo "AWS Security MCP Launcher"
    echo "Usage: $0 [mode]"
    echo ""
    echo "Modes:"
    echo "  stdio  - Standard I/O transport (default, for Claude Desktop)"
    echo "  http   - HTTP REST API server (port 8000)"
    echo "  sse    - Server-Sent Events transport (port 8000)"
    echo "  help   - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 stdio   # For Claude Desktop integration"
    echo "  $0 http    # REST API server"
    echo "  $0 sse     # SSE server for streaming"
}

# Check for help argument
if [[ "$1" == "help" || "$1" == "-h" || "$1" == "--help" ]]; then
    show_usage
    exit 0
fi

# Determine script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Install dependencies directly with uv (no virtual env)
echo "📦 Installing dependencies..."
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

# Configuration: Edit config.yaml for most settings (recommended)
# or use environment variables (see README.md for details)

# Get mode argument (default to stdio)
MODE=${1:-stdio}

echo "🚀 Starting AWS Security MCP in '$MODE' mode..."

case $MODE in
    stdio)
        echo "📱 Starting for Claude Desktop (stdio transport)"
        echo "💡 Make sure this is configured in your claude_desktop_config.json"
        ;;
    http)
        echo "🌐 Starting HTTP REST API server"
        echo "📡 Server will be available at: http://127.0.0.1:8000"
        ;;
    sse)
        echo "📡 Starting Server-Sent Events server"
        echo "🔗 SSE endpoint: http://127.0.0.1:8000/sse"
        echo "📨 Messages endpoint: http://127.0.0.1:8000/messages"
        echo "🔍 Health check: http://127.0.0.1:8000/health"
        ;;
    *)
        echo "❌ Unknown mode: $MODE"
        echo ""
        show_usage
        exit 1
        ;;
esac

echo ""

# Run the module with uv to ensure dependencies are available
uv run aws_security_mcp/main.py $MODE 