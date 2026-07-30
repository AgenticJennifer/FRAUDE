# FRAUDE — Handoff Doc

**For:** whichever agent picks this up next (Hermes, Codex, or otherwise)
**From:** Claude, Phase 1 build session
**Date:** 2026-07-28
**Repo state:** Phase 1 complete, 28/28 tests passing, nothing past Phase 1 exists yet

Read this whole file before touching code. It exists so you don't have
to reconstruct context from scratch or re-litigate decisions already
made.

---

## 1. What this project is

FRAUDE (Framework for Automated Understanding & Discovery of Exploits)
is an MCP server that will let Claude drive authorized pentest tools
(nmap, ffuf, nuclei, semgrep, sublist3r, httpx) inside hardened Docker
containers, gated by a deterministic scope-enforcement layer. Full
product spec is the PRD the human originally supplied — ask for it if
it isn't already in your context; the short version is four phases:

1. **Core Foundation & Scope Safety Engine** ← you are here (done)
2. Recon & Scan Tooling Integrations (nmap / subdomain enum / http probe)
3. Vulnerability Mapping & HITL Control (nuclei, semgrep, human-confirm
   middleware for high-risk actions)
4. Exploitation Support & Automated Reporting (dynamic payload
   generation, exploit chaining, report synthesis)

## 2. What actually got built in Phase 1

| Component | File | Status |
|---|---|---|
| Scope config model | `fraude/scope/models.py` | done |
| Scope validator (the safety-critical core) | `fraude/scope/validator.py` | done, 21 unit tests |
| Docker execution wrapper | `fraude/executor/docker_wrapper.py` | done, 7 unit tests |
| Audit logger (JSONL) | `fraude/audit/logger.py` | done, untested (trivial, no branching logic) |
| MCP server | `fraude/server.py` | done — exposes exactly one tool, `validate_scope` |
| Example scope config | `scope.yaml.example` | done, fully commented |

**Nothing else exists.** There is no `run_nmap_scan`, no HITL
middleware, no payload generation. Do not assume any of that is
partially built somewhere — it isn't.

## 3. Verification already performed (don't redo blindly, but don't trust blindly either)

- `pytest tests/ -v` → 28/28 passing, covering: scope.yaml parse edge
  cases (missing file, empty scope, missing `authorized_by`, bad
  CIDR), IP-literal CIDR matching, domain exact/wildcard matching,
  exclusion-beats-allow for both domains and IPs, URL/port
  normalization, DNS-mocked resolution checks including
  `strict_resolution` and `require_dns_match`, and the Docker
  wrapper's command construction + scope gate (via a fake subprocess
  runner, dependency-injected — **no real Docker daemon was available
  in the build sandbox, so the actual `docker run` invocation itself
  has never executed**).
- `fraude/server.py` was imported and `validate_scope()` was called
  live against the real installed `mcp` 2.0.0 SDK — confirmed it
  registers correctly and returns correct allow/deny decisions for
  both an in-scope and out-of-scope domain.
- Re-run the test suite yourself before building on top of this. Don't
  take the above as permanent proof of correctness in your own
  environment.

## 4. Things that will bite you if you don't know them going in

1. **`mcp` SDK 2.0.0 renamed `FastMCP` → `MCPServer`.** The old import
   was `from mcp.server.fastmcp import FastMCP`. As of 2.0.0 it's
   `from mcp.server.mcpserver import MCPServer` — confirmed by direct
   inspection of the installed package, not from training memory.
   There is no backward-compat alias. If you're working against an
   older pinned SDK version for other reasons, you'll need to adjust
   `fraude/server.py`'s import and class name — the decorator API
   (`@server.tool()`) is otherwise unchanged.
2. **`scope.yaml` fails closed on load, not just on evaluation.**
   `load_scope()` raises `ScopeConfigError` if the file is missing,
   isn't valid YAML, defines zero domains AND zero ip_ranges, has a
   bad CIDR string, or is missing `metadata.authorized_by`. This is
   deliberate — don't "fix" it by making these warnings instead of
   hard failures.
3. **Wildcards are subdomain-only.** `*.example.com` does not match
   the bare apex `example.com`. If a future tool needs "domain or any
   subdomain," the scope.yaml author has to list both.
4. **Scope enforcement lives in exactly one choke point.**
   `fraude.executor.run_containerized_tool()` calls
   `validate_target()` before it will build or run any Docker command,
   and raises `ScopeViolation` (not a silently-failed result) if the
   target is out of scope. **Every Phase 2+ tool function must call
   `run_containerized_tool()` rather than shelling out to Docker
   directly.** If you add a tool that bypasses this, you've defeated
   the entire point of Phase 1. This is the one rule that matters more
   than any other in this codebase.
5. **`--read-only` is on by default in the container hardening flags**
   (`DEFAULT_HARDENING_FLAGS` in `docker_wrapper.py`), along with
   `--cap-drop ALL`, non-root UID, and resource ceilings. Some CLI
   tools (nmap with certain scripts, ffuf writing output files) may
   need a `--tmpfs /tmp` mount added — this hasn't been tested against
   a real tool image yet, only against a fake runner. Expect to need
   to loosen this slightly per-tool rather than globally.
6. **The audit logger is intentionally dumb right now** — JSONL, facts
   only, no formatting. Phase 4's "Report Synthesis" is supposed to
   read this file and turn it into the human-facing report. Don't
   start prettifying it in Phase 2/3; that's out of scope for those
   phases per the roadmap.

## 5. Repo / package layout

```
fraude/
├── README.md                 setup + full design rationale
├── SUMMARY.md                one-page plain-language summary
├── HANDOFF.md                this file
├── requirements.txt          mcp>=2.0.0, PyYAML>=6.0, pytest>=8.0
├── scope.yaml.example        copy → scope.yaml, edit before running
├── fraude/
│   ├── __init__.py
│   ├── server.py             MCP entrypoint, exposes validate_scope
│   ├── scope/
│   │   ├── models.py         ScopeConfig dataclass
│   │   └── validator.py      load_scope(), validate_target() — read the
│   │                         module docstring, it documents the 5
│   │                         design invariants this file enforces
│   ├── executor/
│   │   └── docker_wrapper.py build_command(), run_containerized_tool(),
│   │                         ScopeViolation
│   └── audit/
│       └── logger.py         AuditLogger — log_scope_decision(),
│                              log_execution()
└── tests/
    ├── test_scope_validator.py
    └── test_docker_wrapper.py
```

## 6. How to pick this up

```bash
cd fraude
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp scope.yaml.example scope.yaml   # edit with a real test scope
python -m pytest tests/ -v          # confirm 28/28 still pass in your env
```

## 7. Recommended next step (Phase 2)

Register three MCP tools in `fraude/server.py`:
`run_nmap_scan`, `run_subdomain_enum`, `run_http_probe`. Each one
should:

1. Accept a `target` string.
2. Call `fraude.executor.run_containerized_tool(...)` — do not touch
   `subprocess` or `docker` directly.
3. Parse the tool's raw output (nmap XML, httpx JSON, etc.) into a
   compact structured summary *before* returning it — this is the PRD's
   "Context Compressor" requirement (5.3), meant to keep token usage
   down when Claude consumes the result. Nothing for this exists yet;
   you're building it from scratch.
4. Log the execution via `AuditLogger.log_execution()`.

Do a real smoke test against at least one actual tool container
(e.g., an nmap image scanning `scanme.nmap.org`, which is explicitly
provided by the nmap project for testing) before considering Phase 2
done — Phase 1's Docker wrapper has only ever been exercised with a
fake subprocess runner, never a live container.

## 8. One flag for whoever scopes Phase 4

Phase 4 is "dynamic payload generation" / "exploit chaining" / WAF
evasion tooling. That's meaningfully closer to exploit-development
territory than anything in Phases 1–3 (which are recon, known-CVE
detection via nuclei, and static analysis via semgrep — all standard,
low-risk security tooling). Worth a dedicated scoping conversation
with the human before writing code for it, rather than treating it as
"just the next phase on the list." Not a blocker for Phase 2/3 work,
just flagging it so it doesn't get built on autopilot.

---
*End of handoff. Ping the human if anything above is unclear before
making architectural changes to the scope/executor layer — that's the
part everything else depends on being correct.*
