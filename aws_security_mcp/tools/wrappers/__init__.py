"""Service wrapper tools for AWS Security MCP.

This module contains wrapper tools that consolidate multiple operations
into service-level interfaces while maintaining semantic richness.
"""

# Import wrapper modules to register their tools
from . import ec2_wrapper
from . import load_balancer_wrapper
from . import cloudfront_wrapper 