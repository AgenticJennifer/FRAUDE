# FRAUDE

**Framework for Automated Understanding & Discovery of Exploits**

MCP server that lets Claude drive authorized pentest tools (`nmap`, `ffuf`, `nuclei`, `semgrep`, `sublist3r`, `httpx`) inside hardened Docker containers, gated by a deterministic scope-enforcement layer.

## Status

| Phase | Description | State |
|-------|-------------|-------|
| 1 | Core Foundation & Scope Safety Engine | **Done** |
| 2 | Recon & Scan Tooling Integrations | **Done** |
| 3 | Vulnerability Mapping & HITL Control | **Done** |
| 4 | Reporting + constrained path suggestions | **Done** — 47/47 tests (no payload generator) |

## Quick start

```bash
cd fraude
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp scope.yaml.example scope.yaml   # edit with real authorized targets
python -m pytest tests/ -v         # confirm 47/47
```

Run the MCP server (stdio transport for Claude Desktop / Claude Code):

```bash
export FRAUDE_SCOPE=./scope.yaml
python -m fraude.server
```

## Phase 3 tools + HITL

| Tool | Image | HITL |
|------|-------|------|
| `run_nuclei_scan` | `projectdiscovery/nuclei` | **Required** (`confirm=True`) |
| `run_semgrep_scan` | `semgrep/semgrep` | **Required** (`confirm=True`) |

High-risk tools refuse to run unless `confirm=True` is passed. Scope gate still fires first. Findings are severity-grouped / capped before returning to the LLM.

## Phase 2 tools

| Tool | Image (default) | Notes |
|------|-----------------|-------|
| `run_nmap_scan` | `instrumentisto/nmap` | XML → compressed open ports/services |
| `run_subdomain_enum` | `projectdiscovery/subfinder` | JSON → capped subdomain list |
| `run_http_probe` | `projectdiscovery/httpx` | JSONL → live hosts + status/title/tech |

All three go through the single scope choke point. Output is always compressed before returning to the LLM.

**Live smoke test** (requires Docker):

```bash
# after editing scope.yaml to include scanme.nmap.org
python -c "
from fraude.server import run_nmap_scan
print(run_nmap_scan('scanme.nmap.org'))
"
```

## Phase 1 architecture

- **Scope fails closed** on load (missing file, bad YAML, empty scope, missing `authorized_by`, invalid CIDR).
- **Wildcards are subdomain-only** — `*.example.com` never matches the apex.
- **Exclusions always beat inclusions**.
- **Single choke point**: every future tool must call `fraude.executor.run_containerized_tool()`, which itself calls `validate_target()` before any `docker run`.
- Containers default to `--read-only --cap-drop ALL --user 65534 --memory 512m --cpus 1.0 --rm`.

## Phase 4 notes

- `generate_report` builds a markdown report from the JSONL audit log only.
- `suggest_attack_path` returns high-level, non-actionable guidance and requires `confirm=True`.
- **No free-form payload / exploit / WAF-bypass generator is included.** That stays out of scope by design.

## License / Authorization

This software is intended **only** for use against systems you are explicitly authorized to test. The scope engine exists to make accidental off-scope activity hard; it is not a substitute for legal authorization.
