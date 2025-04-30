"""Policy evaluation utility functions.

This module provides utilities for evaluating AWS IAM policy conditions
and determining their security impact across services.
"""

import logging
from typing import Any, Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)

def evaluate_policy_conditions(statement: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate conditional statements in a policy statement to determine access restrictions.
    
    This function analyzes different types of IAM policy conditions to determine:
    1. What types of restrictions are applied (source IP, AWS principal, time-based, etc.)
    2. How restrictive the conditions are (strong, partial, or none)
    3. Whether conditions effectively prevent public access
    
    Args:
        statement: Policy statement containing conditions to evaluate
        
    Returns:
        Dict with evaluation results including restriction level and details
    """
    result = {
        "has_conditions": False,
        "restriction_level": "None",  # None, Partial, Strong
        "condition_types": [],
        "potential_public_access": True,  # Default assumption
        "details": {}
    }
    
    # Check if conditions exist
    conditions = statement.get('Condition', {})
    if not conditions:
        return result
    
    result["has_conditions"] = True
    
    # Track different condition types
    source_ip_conditions = []
    aws_principal_conditions = []
    temporal_conditions = []
    request_conditions = []
    resource_conditions = []
    other_conditions = []
    
    # Analyze different condition types
    for condition_type, condition_values in conditions.items():
        condition_type_lower = condition_type.lower()
        
        # Source IP restrictions
        if 'ip' in condition_type_lower or 'vpce' in condition_type_lower:
            result["condition_types"].append("SourceIP")
            
            # Extract IP information
            for key, value in condition_values.items():
                if key == 'aws:SourceIp':
                    if isinstance(value, str):
                        source_ip_conditions.append(value)
                    elif isinstance(value, list):
                        source_ip_conditions.extend(value)
                        
        # AWS principal conditions (account, principal type, etc.)
        elif 'aws' in condition_type_lower and 'principal' in condition_type_lower:
            result["condition_types"].append("AWSPrincipal")
            
            for key, value in condition_values.items():
                aws_principal_conditions.append({key: value})
        
        # Time-based conditions
        elif 'date' in condition_type_lower or 'time' in condition_type_lower:
            result["condition_types"].append("Temporal")
            
            for key, value in condition_values.items():
                temporal_conditions.append({key: value})
        
        # Request-related conditions (http method, referrer, etc.)
        elif 'referer' in condition_type_lower or 'http' in condition_type_lower:
            result["condition_types"].append("RequestProperty")
            
            for key, value in condition_values.items():
                request_conditions.append({key: value})
                
        # Resource-related conditions (tags, properties)
        elif 'resource' in condition_type_lower or 'tag' in condition_type_lower:
            result["condition_types"].append("ResourceProperty")
            
            for key, value in condition_values.items():
                resource_conditions.append({key: value})
        
        # Other condition types
        else:
            result["condition_types"].append("Other")
            
            for key, value in condition_values.items():
                other_conditions.append({key: value})
    
    # Remove duplicates from condition types
    result["condition_types"] = list(set(result["condition_types"]))
    
    # Determine restriction level and potential public access
    # Check for source IP restrictions that would limit public access
    if source_ip_conditions:
        result["details"]["source_ip"] = source_ip_conditions
        
        # Check if IP restrictions allow broad public access (0.0.0.0/0 or similar)
        has_public_ip_range = False
        for ip_range in source_ip_conditions:
            if ip_range == '0.0.0.0/0' or ip_range == '::/0':
                has_public_ip_range = True
                break
        
        if not has_public_ip_range:
            # IP restrictions are limiting access to specific IPs/ranges
            result["restriction_level"] = "Strong"
            result["potential_public_access"] = False
    
    # AWS principal conditions generally restrict access to specific AWS identities
    if aws_principal_conditions:
        result["details"]["aws_principal"] = aws_principal_conditions
        
        # AWS principal conditions usually indicate strong restrictions
        if result["restriction_level"] == "None":
            result["restriction_level"] = "Strong"
            result["potential_public_access"] = False
    
    # Temporal conditions provide time-based restrictions, which are partial
    if temporal_conditions:
        result["details"]["temporal"] = temporal_conditions
        
        if result["restriction_level"] == "None":
            result["restriction_level"] = "Partial"
    
    # Request conditions can vary in restrictiveness
    if request_conditions:
        result["details"]["request"] = request_conditions
        
        if result["restriction_level"] == "None":
            result["restriction_level"] = "Partial"
    
    # Resource conditions typically apply restrictions to specific resources
    if resource_conditions:
        result["details"]["resource"] = resource_conditions
        
        if result["restriction_level"] == "None":
            result["restriction_level"] = "Partial"
    
    # Other conditions 
    if other_conditions:
        result["details"]["other"] = other_conditions
        
        if result["restriction_level"] == "None":
            result["restriction_level"] = "Partial"
    
    return result


def evaluate_policy_for_public_access(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate an entire policy document to determine if it allows public access.
    
    Args:
        policy: Complete policy document with statements
        
    Returns:
        Dict with evaluation results including public access determination
    """
    if not policy:
        return {
            "allows_public_access": False,
            "public_statements": [],
            "has_conditions": False, 
            "condition_mitigations": []
        }
    
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        # Handle case where Statement is a single statement object
        statements = [statements]
    
    public_statements = []
    condition_mitigations = []
    
    for statement in statements:
        # Only check Allow statements
        if statement.get("Effect") != "Allow":
            continue
        
        # Check for public principal
        principal = statement.get("Principal")
        is_public_principal = False
        
        if principal == "*" or principal == {"AWS": "*"}:
            is_public_principal = True
        elif isinstance(principal, dict) and (
            principal.get("AWS") == "*" or 
            (isinstance(principal.get("AWS"), list) and "*" in principal.get("AWS", []))
        ):
            is_public_principal = True
        
        # If public principal, check for condition mitigations
        if is_public_principal:
            # Evaluate conditions
            condition_analysis = evaluate_policy_conditions(statement)
            
            # Check if conditions provide strong mitigation
            if condition_analysis["has_conditions"]:
                if condition_analysis["restriction_level"] == "Strong":
                    condition_mitigations.append({
                        "statement_effect": "Allow",
                        "condition_analysis": condition_analysis
                    })
                    # Still record as public but with strong mitigation
                    public_statements.append({
                        "effect": statement.get("Effect"),
                        "principal": principal,
                        "action": statement.get("Action"),
                        "resource": statement.get("Resource"),
                        "has_strong_condition": True
                    })
                else:
                    # Public with only partial mitigation
                    public_statements.append({
                        "effect": statement.get("Effect"),
                        "principal": principal, 
                        "action": statement.get("Action"),
                        "resource": statement.get("Resource"),
                        "has_strong_condition": False,
                        "condition_analysis": condition_analysis
                    })
            else:
                # Public with no conditions
                public_statements.append({
                    "effect": statement.get("Effect"),
                    "principal": principal,
                    "action": statement.get("Action"),
                    "resource": statement.get("Resource"),
                    "has_condition": False
                })
    
    has_unmitigated_public_access = any(
        not stmt.get("has_strong_condition", False) 
        for stmt in public_statements
    )
    
    return {
        "allows_public_access": len(public_statements) > 0,
        "has_unmitigated_public_access": has_unmitigated_public_access,
        "public_statements": public_statements,
        "has_condition_mitigations": len(condition_mitigations) > 0,
        "condition_mitigations": condition_mitigations
    } 