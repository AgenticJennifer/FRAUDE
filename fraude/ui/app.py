"""Fraude control panel — FastAPI backend.

Anthropic-inspired UI tokens from docs/font-baseline.html.
All tool calls reuse the same scope + HITL gates as the MCP server.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from fraude.scope.validator import ScopeConfigError, ScopeViolation, load_scope, validate_target
from fraude.audit.logger import AuditLogger

STATIC = Path(__file__).parent / "static"
SCOPE_PATH = Path(os.environ.get("FRAUDE_SCOPE", "scope.yaml"))
AUDIT_PATH = Path(os.environ.get("FRAUDE_AUDIT", "fraude-audit.jsonl"))

app = FastAPI(title="Fraude", version="0.4.0", docs_url="/api/docs")
_audit = AuditLogger(AUDIT_PATH)


class TargetIn(BaseModel):
    target: str = Field(..., min_length=1)


class RunIn(BaseModel):
    tool: str
    target: str = Field(..., min_length=1)
    confirm: bool = False
    flags: str = ""
    severity: str = "medium,high,critical"
    findings_summary: str = ""


def _scope():
    try:
        return load_scope(SCOPE_PATH)
    except ScopeConfigError as exc:
        raise HTTPException(status_code=400, detail=f"Scope error: {exc}") from exc


@app.get("/", response_class=HTMLResponse)
def index():
    path = STATIC / "index.html"
    if not path.exists():
        raise HTTPException(404, "UI not built")
    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.get("/api/health")
def health():
    return {"ok": True, "service": "fraude-ui", "version": "0.4.0"}


@app.get("/api/scope")
def scope_info():
    try:
        scope = load_scope(SCOPE_PATH)
    except ScopeConfigError as exc:
        return {"ok": False, "error": str(exc), "path": str(SCOPE_PATH)}
    return {
        "ok": True,
        "engagement": scope.metadata.engagement_name,
        "authorized_by": scope.metadata.authorized_by,
        "notes": scope.metadata.notes,
        "domains": scope.domains,
        "ip_ranges": scope.ip_ranges,
        "exclude_domains": scope.exclude_domains,
        "exclude_ip_ranges": scope.exclude_ip_ranges,
        "ports": scope.ports,
        "path": str(SCOPE_PATH),
    }


@app.post("/api/validate")
def api_validate(body: TargetIn):
    scope = _scope()
    try:
        validate_target(body.target, scope)
        _audit.log_scope_decision(
            target=body.target,
            allowed=True,
            reason="in_scope",
            engagement=scope.metadata.engagement_name,
        )
        return {
            "allowed": True,
            "target": body.target,
            "reason": "Target is within authorized scope",
            "engagement": scope.metadata.engagement_name,
        }
    except ScopeViolation as exc:
        _audit.log_scope_decision(
            target=body.target,
            allowed=False,
            reason=str(exc),
            engagement=scope.metadata.engagement_name,
        )
        return {"allowed": False, "target": body.target, "reason": str(exc)}


@app.post("/api/run")
def api_run(body: RunIn):
    from fraude import server as srv

    table = {
        "nmap": lambda: srv.run_nmap_scan(body.target, flags=body.flags or "-sV -T4 --open"),
        "sub": lambda: srv.run_subdomain_enum(body.target),
        "httpx": lambda: srv.run_http_probe(body.target),
        "nuclei": lambda: srv.run_nuclei_scan(
            body.target, confirm=body.confirm, severity=body.severity
        ),
        "semgrep": lambda: srv.run_semgrep_scan(body.target, confirm=body.confirm),
        "suggest": lambda: srv.suggest_attack_path(
            body.findings_summary or body.target, confirm=body.confirm
        ),
    }
    if body.tool not in table:
        raise HTTPException(404, f"Unknown tool: {body.tool}")
    try:
        return table[body.tool]()
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc


@app.get("/api/audit")
def api_audit(limit: int = 40):
    if not AUDIT_PATH.exists():
        return {"lines": [], "count": 0}
    lines = [ln for ln in AUDIT_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
    tail = lines[-limit:]
    return {"lines": list(reversed(tail)), "count": len(tail)}


@app.post("/api/report")
def api_report():
    from fraude.server import generate_report
    return generate_report()


def main() -> None:
    import uvicorn

    host = os.environ.get("FRAUDE_UI_HOST", "127.0.0.1")
    port = int(os.environ.get("FRAUDE_UI_PORT", "8787"))
    uvicorn.run("fraude.ui.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
