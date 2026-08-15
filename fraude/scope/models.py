"""Scope configuration data model.

ScopeConfig is the single source of truth for what a given engagement
is allowed to touch. It is loaded from scope.yaml and never mutated
at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import List, Mapping, Optional
from urllib.parse import urlparse


class ScopeConfigError(ValueError):
    """Raised when scope configuration is missing or invalid."""


class ScopeViolation(PermissionError):
    """Raised when a requested target is outside the authorized scope."""

    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"Target '{target}' is out of scope: {reason}")


@dataclass(frozen=True)
class ScopeMetadata:
    """Authorization metadata that must be present for any valid scope."""

    authorized_by: str
    engagement_name: str = ""
    notes: str = ""


@dataclass(frozen=True)
class Target:
    """Normalized validation target."""

    raw: str
    target_type: str
    hostname: Optional[str] = None

    @classmethod
    def parse(cls, value: str) -> "Target":
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return cls(raw=value, target_type="url", hostname=parsed.hostname or parsed.netloc)

        try:
            ip_address(value)
            return cls(raw=value, target_type="ip", hostname=value)
        except ValueError:
            return cls(raw=value, target_type="domain", hostname=value)

    @property
    def value(self) -> str:
        return self.raw

    def get_hostname(self) -> str:
        return self.hostname or self.raw


@dataclass(frozen=True, init=False)
class ScopeConfig:
    """Immutable representation of an engagement's authorized scope.

    Design invariants (enforced by load_scope / validate_target):
    1. At least one of domains or ip_ranges must be non-empty.
    2. authorized_by is required and non-empty.
    3. Every ip_range must be a valid CIDR.
    4. Wildcards are subdomain-only (*.example.com never matches example.com).
    5. Exclusions always beat inclusions.
    """

    metadata: ScopeMetadata
    domains: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    exclude_domains: List[str] = field(default_factory=list)
    exclude_ip_ranges: List[str] = field(default_factory=list)
    ports: Optional[List[int]] = None
    strict_resolution: bool = False
    require_dns_match: bool = False
    exclusions: Mapping[str, List[str]] = field(default_factory=dict)

    def __init__(
        self,
        metadata: ScopeMetadata | None = None,
        authorized_by: str | None = None,
        domains: Optional[List[str]] = None,
        ip_ranges: Optional[List[str]] = None,
        exclude_domains: Optional[List[str]] = None,
        exclude_ip_ranges: Optional[List[str]] = None,
        exclusions: Optional[Mapping[str, List[str]]] = None,
        ports: Optional[List[int]] = None,
        strict_resolution: bool = False,
        require_dns_match: bool = False,
    ) -> None:
        if metadata is None:
            metadata = ScopeMetadata(authorized_by=authorized_by or "")

        normalized_exclusions = {
            "domains": list((exclusions or {}).get("domains", exclude_domains or [])),
            "ip_ranges": list((exclusions or {}).get("ip_ranges", exclude_ip_ranges or [])),
        }

        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "domains", list(domains or []))
        object.__setattr__(self, "ip_ranges", list(ip_ranges or []))
        object.__setattr__(self, "exclude_domains", normalized_exclusions["domains"])
        object.__setattr__(self, "exclude_ip_ranges", normalized_exclusions["ip_ranges"])
        object.__setattr__(self, "ports", ports)
        object.__setattr__(self, "strict_resolution", strict_resolution)
        object.__setattr__(self, "require_dns_match", require_dns_match)
        object.__setattr__(self, "exclusions", normalized_exclusions)

    @property
    def authorized_by(self) -> str:
        return self.metadata.authorized_by

    def has_targets(self) -> bool:
        return bool(self.ip_ranges or self.domains)

    def to_dict(self) -> dict:
        return {
            "metadata": {
                "authorized_by": self.authorized_by,
                "engagement_name": self.metadata.engagement_name,
                "notes": self.metadata.notes,
            },
            "authorized_by": self.authorized_by,
            "ip_ranges": list(self.ip_ranges),
            "domains": list(self.domains),
            "exclusions": {
                "domains": list(self.exclusions.get("domains", [])),
                "ip_ranges": list(self.exclusions.get("ip_ranges", [])),
            },
            "ports": self.ports,
            "strict_resolution": self.strict_resolution,
            "require_dns_match": self.require_dns_match,
        }
