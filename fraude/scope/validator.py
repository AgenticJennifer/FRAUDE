"""
Scope Validation Engine

This module implements the safety-critical core of FRAUDE's scope enforcement.

Design Invariants (enforced by this module):
1. FAIL CLOSED: Invalid or missing scope config raises ScopeConfigError, not warnings
2. EXCLUSIONS WIN: If a target matches an exclusion, it's denied regardless of allow lists
3. WILDCARDS ARE SUBDOMAIN-ONLY: *.example.com does NOT match bare example.com
4. IP MATCHING: Uses CIDR notation; single IPs should be specified as /32
5. DETERMINISTIC: Same input always produces same output (no randomness)

The validator operates on a single target at a time, making decisions based on
the loaded ScopeConfig. All tool integrations must call validate_target() before
execution to ensure scope compliance.
"""

import os
import re
from typing import Optional
from ipaddress import IPv4Network, IPv4Address, ip_network

import yaml

from .models import ScopeConfig, ScopeConfigError, ScopeViolation, Target


def load_scope(config_path: str = "scope.yaml") -> ScopeConfig:
    """
    Load and validate scope configuration from YAML file.
    
    Args:
        config_path: Path to scope.yaml file
        
    Returns:
        ScopeConfig object if valid
        
    Raises:
        ScopeConfigError: If file is missing, invalid, or incomplete
    """
    # Check file exists
    if not os.path.exists(config_path):
        raise ScopeConfigError(f"Scope config file not found: {config_path}")
    
    # Parse YAML
    try:
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ScopeConfigError(f"Invalid YAML in scope config: {e}")
    
    # Check required metadata
    if not data:
        raise ScopeConfigError("Empty scope config file")
    
    if 'metadata' not in data:
        raise ScopeConfigError("Missing required 'metadata' section")
    
    if 'authorized_by' not in data.get('metadata', {}):
        raise ScopeConfigError("Missing required 'metadata.authorized_by' field")
    
    authorized_by = data['metadata']['authorized_by']
    
    # Validate IP ranges
    ip_ranges = []
    if 'ip_ranges' in data:
        if not isinstance(data['ip_ranges'], list):
            raise ScopeConfigError("'ip_ranges' must be a list")
        for ip_range in data['ip_ranges']:
            try:
                # Validate CIDR notation
                ip_network(ip_range, strict=False)
                ip_ranges.append(ip_range)
            except ValueError as e:
                raise ScopeConfigError(f"Invalid CIDR notation '{ip_range}': {e}")
    
    # Validate domains
    domains = []
    if 'domains' in data:
        if not isinstance(data['domains'], list):
            raise ScopeConfigError("'domains' must be a list")
        for domain in data['domains']:
            if not isinstance(domain, str) or not domain.strip():
                raise ScopeConfigError("Domain entries must be non-empty strings")
            domains.append(domain.strip())
    
    # Validate exclusions (optional)
    exclusions = {"domains": [], "ip_ranges": []}
    if 'exclusions' in data:
        if not isinstance(data['exclusions'], dict):
            raise ScopeConfigError("'exclusions' must be a dictionary")
        
        # Exclusions can be partial (only domains or only ip_ranges)
        if 'domains' in data['exclusions']:
            if not isinstance(data['exclusions']['domains'], list):
                raise ScopeConfigError("'exclusions.domains' must be a list")
            exclusions['domains'] = [d.strip() for d in data['exclusions']['domains'] if d.strip()]
        
        if 'ip_ranges' in data['exclusions']:
            if not isinstance(data['exclusions']['ip_ranges'], list):
                raise ScopeConfigError("'exclusions.ip_ranges' must be a list")
            for ip_range in data['exclusions']['ip_ranges']:
                try:
                    ip_network(ip_range, strict=False)
                    exclusions['ip_ranges'].append(ip_range)
                except ValueError as e:
                    raise ScopeConfigError(f"Invalid CIDR in exclusions '{ip_range}': {e}")
    
    # Check that at least one target is defined
    if not ip_ranges and not domains:
        raise ScopeConfigError("Scope must define at least one ip_range or domain")
    
    return ScopeConfig(
        authorized_by=authorized_by,
        ip_ranges=ip_ranges,
        domains=domains,
        exclusions=exclusions
    )


def _matches_ip(target_ip: str, ip_patterns: list) -> bool:
    """
    Check if target IP matches any of the CIDR patterns.
    
    Args:
        target_ip: IP address to check
        ip_patterns: List of CIDR notation strings
        
    Returns:
        True if target matches any pattern
    """
    try:
        target_addr = IPv4Address(target_ip)
    except ValueError:
        return False
    
    for pattern in ip_patterns:
        try:
            network = ip_network(pattern, strict=False)
            if target_addr in network:
                return True
        except ValueError:
            continue
    
    return False


def _matches_domain(target: str, domain_patterns: list) -> bool:
    """
    Check if target domain matches any of the patterns.
    
    Supports wildcards: *.example.com matches sub.example.com but NOT example.com
    
    Args:
        target: Domain to check
        domain_patterns: List of domain patterns (may include wildcards)
        
    Returns:
        True if target matches any pattern
    """
    target = target.lower().strip()
    
    for pattern in domain_patterns:
        pattern = pattern.lower().strip()
        
        # Exact match
        if target == pattern:
            return True
        
        # Wildcard match (subdomain only)
        if pattern.startswith('*.'):
            suffix = pattern[2:]  # Remove '*.'
            # Check if target is a subdomain of the suffix
            if target.endswith('.' + suffix):
                return True
    
    return False


def validate_target(target: str, scope: ScopeConfig) -> bool:
    """
    Validate that a target is within the authorized scope.
    
    This is the main entry point for scope validation. All tool integrations
    must call this before executing any operation.
    
    Args:
        target: Target string (IP, domain, or URL)
        scope: Loaded ScopeConfig object
        
    Returns:
        True if target is in scope
        
    Raises:
        ScopeViolation: If target is out of scope
    """
    target = target.strip()
    
    # Parse target
    parsed = Target.parse(target)
    
    # Get the actual value to check (hostname for URLs)
    check_value = parsed.get_hostname() if parsed.target_type == 'url' else target
    
    # Check exclusions FIRST (exclusions always win)
    if parsed.target_type == 'ip':
        if _matches_ip(check_value, scope.exclusions.get('ip_ranges', [])):
            raise ScopeViolation(target, "IP is in exclusion list")
    elif parsed.target_type in ('domain', 'url'):
        if _matches_domain(check_value, scope.exclusions.get('domains', [])):
            raise ScopeViolation(target, "Domain is in exclusion list")
    
    # Check allow lists
    if parsed.target_type == 'ip':
        if scope.ip_ranges and _matches_ip(check_value, scope.ip_ranges):
            return True
        # Out of scope IP
        raise ScopeViolation(target, "IP not in authorized range")
    
    elif parsed.target_type in ('domain', 'url'):
        if scope.domains and _matches_domain(check_value, scope.domains):
            return True
        # Out of scope domain
        raise ScopeViolation(target, "Domain not in authorized list")
    
    # Should not reach here, but handle gracefully
    raise ScopeViolation(target, "Target type not recognized")


# Global scope instance (loaded once)
_scope: Optional[ScopeConfig] = None


def get_scope(config_path: str = "scope.yaml") -> ScopeConfig:
    """
    Get the loaded scope configuration (singleton pattern).
    
    Loads from file on first call, caches for subsequent calls.
    """
    global _scope
    if _scope is None:
        _scope = load_scope(config_path)
    return _scope


def reset_scope():
    """Reset the cached scope (useful for testing)."""
    global _scope
    _scope = None