# Create this file: Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY aws_security_mcp/ ./aws_security_mcp/
COPY run_aws_security.sh .
COPY config.yaml .

# Make the script executable
RUN chmod +x run_aws_security.sh

# Create non-root user for security
RUN useradd -m -u 1000 mcpuser && chown -R mcpuser:mcpuser /app
USER mcpuser

# Set Python path so the aws_security_mcp module can be found
ENV PYTHONPATH=/app

# Expose the SSE port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the SSE server - Execute main.py with proper PYTHONPATH
CMD ["python", "aws_security_mcp/main.py", "sse"]