"""
Audit Logger

Simple JSONL audit logging for FRAUDE operations.

This module provides a dumb logger that writes facts to JSONL format.
Phase 4's "Report Synthesis" will read this file and turn it into
human-facing reports. Do not prettify or format - that's out of scope
for Phase 2/3.

Log format:
{
  "timestamp": "2026-07-28T14:30:00Z",
  "event": "scope_decision|execution",
  "data": {...}
}
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class AuditLogger:
    """
    Simple JSONL audit logger.
    
    Writes one JSON object per line with timestamp. No branching logic,
    no formatting, just facts.
    """
    
    def __init__(self, log_path: str = "audit.log.jsonl"):
        """
        Initialize the audit logger.
        
        Args:
            log_path: Path to the JSONL log file
        """
        self.log_path = log_path
    
    def _write_entry(self, event: str, data: Dict[str, Any]) -> None:
        """Write a single log entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data
        }
        
        # Ensure directory exists
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def log_scope_decision(self, target: str, allowed: bool, reason: str) -> None:
        """
        Log a scope validation decision.
        
        Args:
            target: The target that was validated
            allowed: Whether the target was in scope
            reason: The reason for the decision
        """
        self._write_entry("scope_decision", {
            "target": target,
            "allowed": allowed,
            "reason": reason
        })
    
    def log_execution(self, tool_name: str, target: str, success: bool, 
                      duration_ms: int, output_preview: str = "") -> None:
        """
        Log a tool execution.
        
        Args:
            tool_name: Name of the tool that was run
            target: The target that was scanned
            success: Whether the execution succeeded
            duration_ms: Duration in milliseconds
            output_preview: First few lines of output (for debugging)
        """
        self._write_entry("execution", {
            "tool": tool_name,
            "target": target,
            "success": success,
            "duration_ms": duration_ms,
            "output_preview": output_preview[:500] if output_preview else ""  # Truncate
        })


# Global logger instance
_logger: Optional[AuditLogger] = None


def get_logger(log_path: str = "audit.log.jsonl") -> AuditLogger:
    """Get the global audit logger instance."""
    global _logger
    if _logger is None:
        _logger = AuditLogger(log_path)
    return _logger


def log_scope_decision(target: str, allowed: bool, reason: str) -> None:
    """Convenience function to log a scope decision."""
    get_logger().log_scope_decision(target, allowed, reason)


def log_execution(tool_name: str, target: str, success: bool,
                  duration_ms: int, output_preview: str = "") -> None:
    """Convenience function to log an execution."""
    get_logger().log_execution(tool_name, target, success, duration_ms, output_preview)
