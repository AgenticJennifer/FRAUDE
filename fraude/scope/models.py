"""
Scope Configuration Models

Defines the data structures for scope configuration including:
- ScopeConfig: Main configuration container
- ScopeViolation: Exception raised when targets are out of scope
"""

from dataclasses import dataclass, field
from typing import List, Optional
from ipaddress import IPv4Network, IPv4Address
import yaml


@dataclass
class ScopeConfig:
    """
    Scope configuration model representing authorized targets for pentest operations.
    
    Design Invariant: This model is immutable once loaded - any modification
    requires reloading the configuration file.
    """
    authorized_by: str
    ip_ranges: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    exclusions: dict = field(default_factory=lambda: {"domains": [], "ip_ranges": []})
    
    def has_targets(self) -> bool:
        """Check if scope has any authorized targets defined."""
        return bool(self.ip_ranges or self.domains)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        return {
            "authorized_by": self.authorized_by,
            "ip_ranges": self.ip_ranges,
            "domains": self.domains,
            "exclusions": self.exclusions
        }


class ScopeConfigError(Exception):
    """Raised when scope configuration is invalid or missing required fields."""
    pass


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized scope."""
    
    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation: {target} - {reason}")


@dataclass
class Target:
    """Represents a target to be validated (IP, domain, or URL)."""
    value: str
    target_type: str  # 'ip', 'domain', 'url'
    
    @classmethod
    def parse(cls, value: str) -> 'Target':
        """Parse a string value into a Target object."""
        value = value.strip().rstrip('/')
        
        # Check if it's a URL (has scheme or path)
        if value.startswith(('http://', 'https://')):
            return cls(value=value, target_type='url')
        
        # Check if it's an IP address
        try:
            IPv4Address(value)
            return cls(value=value, target_type='ip')
        except:
            pass
        
        # Otherwise assume domain
        return cls(value=value, target_type='domain')
    
    def get_hostname(self) -> str:
        """Extract hostname from target (removes scheme, port, path)."""
        if self.target_type == 'url':
            # Remove scheme
            host = self.value.split('://', 1)[-1]
            # Remove path
            host = host.split('/', 1)[0]
            # Remove port
            host = host.split(':', 1)[0]
            return host
        return self.value