"""Docker execution wrapper with mandatory scope gate.

Every tool invocation MUST go through ``run_containerized_tool``.
There is intentionally no public helper that shells out to Docker
without first calling ``validate_target``.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from fraude.scope.validator import ScopeConfig, ScopeViolation, validate_target

__all__ = [
    "run_containerized_tool",
    "build_command",
    "ScopeViolation",
    "DEFAULT_HARDENING_FLAGS",
    "ExecutionResult",
]

DEFAULT_HARDENING_FLAGS: List[str] = [
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", "65534:65534",
    "--memory", "512m",
    "--cpus", "1.0",
    "--network", "bridge",
    "--rm",
]


@dataclass
class ExecutionResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    target: str
    image: str


def build_command(
    image: str,
    tool_args: Sequence[str],
    *,
    extra_docker_args: Optional[Sequence[str]] = None,
    hardening: Optional[Sequence[str]] = None,
) -> List[str]:
    flags = list(hardening if hardening is not None else DEFAULT_HARDENING_FLAGS)
    if extra_docker_args:
        flags.extend(extra_docker_args)
    cmd = ["docker", "run"] + flags + [image] + list(tool_args)
    return cmd


def run_containerized_tool(
    *,
    target: str,
    scope: ScopeConfig,
    image: str,
    tool_args: Sequence[str],
    extra_docker_args: Optional[Sequence[str]] = None,
    hardening: Optional[Sequence[str]] = None,
    timeout: Optional[float] = 300.0,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> ExecutionResult:
    validate_target(target, scope)
    cmd = build_command(
        image,
        tool_args,
        extra_docker_args=extra_docker_args,
        hardening=hardening,
    )
    run = runner or subprocess.run
    try:
        completed = run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Container timed out after {timeout}s: {' '.join(shlex.quote(c) for c in cmd)}"
        ) from exc
    except FileNotFoundError as exc:
        raise RuntimeError(
            "docker binary not found on PATH — is Docker installed?"
        ) from exc
    return ExecutionResult(
        command=cmd,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        target=target,
        image=image,
    )
