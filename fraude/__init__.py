"""
FRAUDE - Framework for Automated Understanding & Discovery of Exploits
"""

__version__ = "0.1.0"

from .scope.models import ScopeConfig, ScopeViolation, ScopeConfigError, Target
from .scope.validator import load_scope, validate_target, get_scope, reset_scope
from .executor.docker_wrapper import run_containerized_tool, build_command, ExecutionResult
from .audit.logger import AuditLogger, log_scope_decision, log_execution

__all__ = [
    "ScopeConfig",
    "ScopeViolation", 
    "ScopeConfigError",
    "Target",
    "load_scope",
    "validate_target",
    "get_scope",
    "reset_scope",
    "run_containerized_tool",
    "build_command",
    "ExecutionResult",
    "AuditLogger",
    "log_scope_decision",
    "log_execution",
]