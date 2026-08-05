# Fraude — one-page summary

Fraude is an MCP server that turns Claude into a scope-constrained pentest assistant.

**What it does (Phases 1–4 + UI)**  
- Loads a `scope.yaml` that lists authorized domains, wildcards, and CIDRs.  
- Exposes MCP tools for recon (nmap, subfinder, httpx), vulnerability scanning (nuclei, semgrep), report synthesis, and high-level attack-path suggestions.  
- Provides a Docker runner that refuses to start any container unless the target has already passed validation.  
- Writes every decision and execution to a JSONL audit log; `generate_report` turns that into markdown.
- Ships an Anthropic-inspired web control panel at `:8787`.

**What it deliberately does not do**  
- No free-form payload generation, shellcode, or WAF-bypass strings.  
- No silent bypass of the scope gate.

**Safety rules that will not be relaxed**  
1. Scope file fails closed on any configuration error.  
2. Wildcards never match the apex domain.  
3. Exclusions beat inclusions.  
4. All tool execution goes through one function that re-validates the target.  
5. Containers run non-root, read-only, capability-dropped, resource-limited.  
6. High-risk tools require explicit `confirm=True` (HITL).

**How to extend safely**  
Any new tool must call `run_containerized_tool()`. Anything that bypasses that function has defeated the entire point of Phase 1.
