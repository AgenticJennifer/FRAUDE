"""
Docker Execution Wrapper

Provides a hardened interface for running pentest tools in Docker containers.

Security Features:
- Read-only root filesystem by default
- Dropped all Linux capabilities
- Non-root user execution
- Resource limits (CPU, memory, PIDs)
- Scope enforcement before any container run
- Command allowlisting for tool safety

This module is the CHOKEPOINT for all tool execution - every Phase 2+ tool
must go through run_containerized_tool() to inherit scope enforcement.
"""

import subprocess
from typing import List, Optional, Dict, Callable
from dataclasses import dataclass, field

from ..scope.validator import validate_target, get_scope
from ..scope.models import ScopeViolation, ScopeConfig


# Default hardening flags for all containers
DEFAULT_HARDENING_FLAGS = [
    "--read-only",
    "--cap-drop", "ALL",
    "--user", "1000:1000",
    "--memory", "512m",
    "--cpus", "1.0",
    "--pids-limit", "100",
]


@dataclass
class ToolConfig:
    """Configuration for a specific tool."""
    image: str
    default_args: List[str] = field(default_factory=list)
    requires_tmpfs: bool = False


@dataclass
class ExecutionResult:
    """Result from a container execution."""
    success: bool
    stdout: str
    stderr: str
    returncode: int


# Allowed tools that can be run (allowlist) - lazy initialization
_ALLOWED_TOOLS: Dict[str, ToolConfig] = {}


def _get_allowed_tools() -> Dict[str, ToolConfig]:
    """Get the allowed tools dictionary, creating it if needed."""
    if not _ALLOWED_TOOLS:
        _ALLOWED_TOOLS['nmap'] = ToolConfig(
            image="instrumentisto/nmap",
            default_args=[],
            requires_tmpfs=True,  # Some nmap scripts need writable /tmp
        )
        _ALLOWED_TOOLS['sublist3r'] = ToolConfig(
            image="abridges/sublist3r",
            default_args=[],
            requires_tmpfs=True,
        )
        _ALLOWED_TOOLS['httpx'] = ToolConfig(
            image="projectdiscovery/httpx",
            default_args=[],
            requires_tmpfs=True,
        )
        _ALLOWED_TOOLS['nuclei'] = ToolConfig(
            image="projectdiscovery/nuclei",
            default_args=["-json"],
            requires_tmpfs=True,
        )
        _ALLOWED_TOOLS['semgrep'] = ToolConfig(
            image="returntocorp/semgrep",
            default_args=["--json", "--metrics=off"],
            requires_tmpfs=False,
        )
    return _ALLOWED_TOOLS


# Exported configs for server/tool integrations
TOOL_CONFIGS_LIST: Dict[str, ToolConfig] = {}


def get_tool_configs() -> Dict[str, ToolConfig]:
    if not TOOL_CONFIGS_LIST:
        TOOL_CONFIGS_LIST.update(_get_allowed_tools())
    return TOOL_CONFIGS_LIST


def build_command(
    tool_name: str,
    target: str,
    args: Optional[List[str]] = None,
    tool_configs: Optional[Dict[str, ToolConfig]] = None
) -> List[str]:
    """
    Build a hardened Docker command for running a pentest tool.
    
    Args:
        tool_name: Name of the tool (must be in ALLOWED_TOOLS)
        target: Target to scan (IP, domain, or URL)
        args: Additional tool-specific arguments
        tool_configs: Override tool configurations (for testing)
        
    Returns:
        List of command parts ready for subprocess
    """
    if tool_configs is None:
        tool_configs = _get_allowed_tools()
    
    if tool_name not in tool_configs:
        raise ValueError(f"Tool '{tool_name}' is not in the allowed list")
    
    config = tool_configs[tool_name]
    
    # Build base command
    cmd = ["docker", "run", "--rm"]
    
    # Add hardening flags
    cmd.extend(DEFAULT_HARDENING_FLAGS)
    
    # Add tmpfs if required (for tools that need writable /tmp)
    if config.requires_tmpfs:
        cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=100m"])
    
    # Add network mode for scanning tools
    cmd.extend(["--network", "host"])
    
    # Add the image
    cmd.append(config.image)
    
    # Build tool arguments
    tool_args = list(config.default_args)
    if args:
        tool_args.extend(args)
    
    # Add target as positional argument
    if target:
        tool_args.insert(0, target)
    
    cmd.extend(tool_args)
    
    return cmd


def run_containerized_tool(
    tool_name: str,
    target: str,
    args: Optional[List[str]] = None,
    scope_config: Optional[ScopeConfig] = None,
    tool_configs: Optional[Dict[str, ToolConfig]] = None,
    subprocess_runner: Optional[Callable] = None
) -> ExecutionResult:
    """
    Run a pentest tool in a hardened Docker container with scope enforcement.
    
    This is the MAIN ENTRY POINT for all tool execution. It:
    1. Validates the target is in scope
    2. Builds a hardened Docker command
    3. Executes the container
    4. Returns structured results
    
    Args:
        tool_name: Name of the tool (must be in ALLOWED_TOOLS)
        target: Target to scan (IP, domain, or URL)
        args: Additional tool-specific arguments
        scope_config: ScopeConfig to validate against (uses default loader if None)
        tool_configs: Override tool configurations (for testing)
        subprocess_runner: Override subprocess runner (for testing)
        
    Returns:
        ExecutionResult with success status, output, and return code
        
    Raises:
        ScopeViolation: If target is not in scope
        ValueError: If tool is not in allowlist
    """
    # STEP 1: Validate scope BEFORE doing anything
    if scope_config is None:
        scope_config = get_scope()
    validate_target(target, scope_config)
    
    # STEP 2: Build the hardened command
    cmd = build_command(tool_name, target, args, tool_configs)
    
    # STEP 3: Execute (use injected runner for testing, real subprocess otherwise)
    runner = subprocess_runner if subprocess_runner else subprocess.run
    
    try:
        result = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute default timeout
        )
        
        return ExecutionResult(
            success=result.returncode == 0,
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            success=False,
            stdout="",
            stderr="Command timed out after 300 seconds",
            returncode=-1
        )
    except Exception as e:
        return ExecutionResult(
            success=False,
            stdout="",
            stderr=str(e),
            returncode=-1
        )


def get_tool_image(tool_name: str, tool_configs: Optional[Dict[str, ToolConfig]] = None) -> str:
    """Get the Docker image for a tool."""
    if tool_configs is None:
        tool_configs = _get_allowed_tools()
    
    if tool_name not in tool_configs:
        raise ValueError(f"Tool '{tool_name}' is not in the allowed list")
    
    return tool_configs[tool_name].image
