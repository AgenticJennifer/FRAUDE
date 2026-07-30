"""Scope validation module."""

from .models import ScopeConfig, ScopeViolation, ScopeConfigError, Target
from .validator import load_scope, validate_target, get_scope, reset_scope

__all__ = [
    "ScopeConfig",
    "ScopeViolation",
    "ScopeConfigError", 
    "Target",
    "load_scope",
    "validate_target",
    "get_scope",
    "reset_scope",
]