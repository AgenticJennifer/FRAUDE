# FRAUDE - One Page Summary

## What is FRAUDE?

FRAUDE (Framework for Automated Understanding & Discovery of Exploits) is an MCP server that safely orchestrates pentest tools (nmap, ffuf, nuclei, semgrep, sublist3r, httpx) inside hardened Docker containers, gated by deterministic scope enforcement.

## Current Status: Phase 1 Complete

The scope safety engine is built and tested:
- 28 unit tests all passing
- IP CIDR matching with exclusions
- Domain/wildcard matching (subdomain-only)
- Hard fail-closed on invalid config
- Docker wrapper with hardened defaults

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| Scope Config | `fraude/scope/models.py` | Data models for scope |
| Validator | `fraude/scope/validator.py` | Safety-critical enforcement |
| Docker Wrapper | `fraude/executor/docker_wrapper.py` | Container orchestration |
| Audit Logger | `fraude/audit/logger.py` | JSONL event logging |
| MCP Server | `fraude/server.py` | Tool entrypoint |

## Scope Enforcement Rules

1. **Fail Closed**: Invalid config raises `ScopeConfigError`
2. **Exclusions Win**: If in exclusion list, always denied
3. **Wildcards Subdomain-Only**: `*.example.com` ≠ `example.com`
4. **Single Chokepoint**: All tool execution via `run_containerized_tool()`

## Next Steps (Phase 2)

Register MCP tools:
- `run_nmap_scan` - Network reconnaissance
- `run_subdomain_enum` - Subdomain enumeration  
- `run_http_probe` - HTTP probing

Each calls `run_containerized_tool()` for automatic scope enforcement.