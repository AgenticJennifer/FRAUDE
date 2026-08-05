"""Dumb JSONL audit logger.

Phase 4 will turn this stream into human-facing reports.
Do not prettify or summarise here.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional


class AuditLogger:
    def __init__(self, path: str | Path = "fraude-audit.jsonl"):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _write(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", time.time())
        line = json.dumps(event, default=str) + "\n"
        for _ in range(3):
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
                return
            except OSError:
                time.sleep(0.01)

    def log_scope_decision(
        self,
        *,
        target: str,
        allowed: bool,
        reason: str = "",
        engagement: str = "",
    ) -> None:
        self._write(
            {
                "type": "scope_decision",
                "target": target,
                "allowed": allowed,
                "reason": reason,
                "engagement": engagement,
            }
        )

    def log_execution(
        self,
        *,
        target: str,
        image: str,
        command: list[str],
        returncode: int,
        stdout_len: int,
        stderr_len: int,
        duration_s: Optional[float] = None,
    ) -> None:
        self._write(
            {
                "type": "execution",
                "target": target,
                "image": image,
                "command": command,
                "returncode": returncode,
                "stdout_len": stdout_len,
                "stderr_len": stderr_len,
                "duration_s": duration_s,
            }
        )
