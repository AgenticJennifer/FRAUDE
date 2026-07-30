# FRAUDE - Framework for Automated Understanding & Discovery of Exploits

> MCP server for authorized pentest tool orchestration with deterministic scope enforcement

## Overview

FRAUDE is a Model Context Protocol (MCP) server that enables Claude to safely execute authorized pentest tools inside hardened Docker containers. Every operation is gated by a deterministic scope-enforcement layer that ensures no out-of-bounds scanning occurs.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Claude (via MCP)                          │
│                                                              │
│  ┌─────────────────┐    ┌─────────────────┐               │
│  │ validate_scope  │───▶│ scope.yaml      │               │
│  └─────────────────┘    └─────────────────┘               │
│           │                      │                            │
│           ▼                      ▼                            │
│  ┌─────────────────────────────────────────┐                │
│  │   Scope Validator (safety-critical)   │                │
│  │   - IP CIDR matching                    │                │
│  │   - Domain/wildcard matching            │                │
│  │   - Exclusion beats allow               │                │
│  └─────────────────────────────────────────┘                │
│           │                                              │
│           ▼                                              │
│  ┌─────────────────────────────────────────┐             │
│  │ Docker Wrapper (hardened execution)     │             │
│  │ - Read-only filesystem                   │             │
│  │ - Dropped capabilities                   │             │
│  │ - Non-root user (UID 1000)               │             │
│  │ - Resource limits                        │             │
│  │ - Command allowlisting                   │             │
│  └─────────────────────────────────────────┘             │
│           │                                              │
│           ▼                                              │
│  ┌─────────────────┐    ┌─────────────────┐               │
│  │   audit.log     │    │ Tool Containers │               │
│  │   (JSONL)       │    │ (nmap, etc.)    │               │
│  └─────────────────┘    └─────────────────┘               │
└─────────────────────────────────────────────────────────────┘
```

## Design Philosophy

FRAUDE follows a **fail-closed** security model:

1. **Scope Safety Engine** (Phase 1): Validates every target before execution
2. **Chokepoint Pattern**: All tool execution goes through `run_containerized_tool()`
3. **Audit Trail**: Every decision is logged to JSONL for later analysis
4. **Hardened Containers**: Default security flags prevent privilege escalation

## Installation

```bash
cd fraude
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

```bash
cp scope.yaml.example scope.yaml
# Edit scope.yaml with your authorized targets
```

Example `scope.yaml`:

```yaml
metadata:
  authorized_by: "Your Name <you@example.com>"
  
ip_ranges:
  - "192.168.1.0/24"
  - "10.0.0.50"

domains:
  - "example.com"
  - "*.example.org"

exclusions:
  ip_ranges:
    - "192.168.1.100"  # Never scan this IP
  domains:
    - "internal.example.com"  # Exclude internal subdomains
```

## Usage

### As MCP Server

```python
from fraude import validate_target, get_scope

scope = get_scope()
is_allowed = validate_target('example.com', scope)
```

### Via MCP Tools

The server exposes `validate_scope` tool that returns:

```json
{
  "allowed": true,
  "reason": "Target is in authorized scope",
  "target": "example.com"
}
```

## Development

### Running Tests

```bash
python -m pytest tests/ -v
```

### Project Structure

```
fraude/
├── fraude/
│   ├── server.py              # MCP entrypoint
│   ├── scope/
│   │   ├── models.py        # Data classes
│   │   └── validator.py     # Scope enforcement
│   ├── executor/
│   │   └── docker_wrapper.py # Container orchestration
│   └── audit/
│       └── logger.py        # JSONL audit logging
├── tests/
│   ├── test_scope_validator.py
│   └── test_docker_wrapper.py
├── scope.yaml.example         # Config template
└── requirements.txt
```

## Roadmap

- **Phase 1** ✅: Core Foundation & Scope Safety Engine
- **Phase 2**: Recon & Scan Tooling Integrations (nmap, sublist3r, httpx)
- **Phase 3**: Vulnerability Mapping & HITL Control (nuclei, semgrep)
- **Phase 4**: Exploitation Support & Automated Reporting

## Security Notes

- `--read-only` is on by default (some tools need `--tmpfs /tmp`)
- All capabilities are dropped (`--cap-drop ALL`)
- Non-root execution (UID 1000)
- 5-minute timeout on all operations
- Wildcards are subdomain-only: `*.example.com` ≠ `example.com`

## License

MIT