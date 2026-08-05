"""Scope configuration data model.

ScopeConfig is the single source of truth for what a given engagement
is allowed to touch. It is loaded from scope.yaml and never mutated
at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class ScopeMetadata:
    """Authorization metadata that must be present for any valid scope."""

    authorized_by: str
    engagement_name: str = ""
    notes: str = ""


@dataclass(frozen=True)
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
