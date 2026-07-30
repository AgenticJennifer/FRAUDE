"""
FRAUDE MCP Server

MCP 2.0.0 entrypoint that exposes scope validation and pentest tooling.

Phase 1: validate_scope - scope validation tool
Phase 2: run_nmap_scan, run_subdomain_enum, run_http_probe - recon tools
Phase 3: run_nuclei_scan, run_semgrep_analysis, human_confirm - vuln mapping + HITL
"""

import time
import xml.etree.ElementTree as ET
from mcp.server import MCPServer  # MCP SDK 2.0.0

from .scope.validator import load_scope, get_scope, validate_target, ScopeViolation, ScopeConfigError
from .scope.models import ScopeViolation as ScopeViolationModel
from .executor.docker_wrapper import (
    run_containerized_tool, ExecutionResult, ToolConfig, get_tool_configs
)
from .audit.logger import log_scope_decision, log_execution

# Create the MCP server
server = MCPServer("fraude")


# Tool configurations for Phase 2
TOOL_CONFIGS = {
    "nmap": ToolConfig(
        image="instrumentisto/nmap",
        default_args=["-sT", "-sV"],  # `-sT` avoids root-required raw-socket scans in hardened containers
        requires_tmpfs=True,
    ),
    "sublist3r": ToolConfig(
        image="abridges/sublist3r",
        default_args=["-v", "-o", "/dev/stdout"],
        requires_tmpfs=True,
    ),
    "httpx": ToolConfig(
        image="projectdiscovery/httpx",
        default_args=["-silent", "-json"],
        requires_tmpfs=True,
    ),
    "nuclei": ToolConfig(
        image="projectdiscovery/nuclei",
        default_args=["-json"],
        requires_tmpfs=True,
    ),
    "semgrep": ToolConfig(
        image="returntocorp/semgrep",
        default_args=["--json", "--metrics=off"],
        requires_tmpfs=False,
    ),
}
@server.tool()
def validate_scope(target: str) -> dict:
    """
    Validate whether a target is within the authorized scope.

    Returns:
        dict with 'allowed' (bool), 'reason' (str), and 'target' fields
    """
    try:
        scope = get_scope()
        validate_target(target, scope)

        # Log the decision
        log_scope_decision(target, allowed=True, reason="Target is in scope")

        return {
            "allowed": True,
            "reason": "Target is in authorized scope",
            "target": target
        }
    except ScopeViolation as e:
        log_scope_decision(target, allowed=False, reason=str(e.reason))
        return {
            "allowed": False,
            "reason": str(e.reason),
            "target": target
        }
    except ScopeConfigError as e:
        return {
            "allowed": False,
            "reason": f"Scope configuration error: {e}",
            "target": target
        }


@server.tool()
def run_nmap_scan(target: str, args: str = None) -> dict:
    """
    Run an nmap scan against a target.
    
    This tool runs nmap in a hardened Docker container with scope enforcement.
    Output is parsed into a compact structured summary (Context Compressor).
    
    Args:
        target: IP address, domain, or URL to scan
        args: Optional additional nmap arguments (space-separated)
        
    Returns:
        dict with 'success', 'hosts', 'ports', 'services' fields
    """
    start_time = time.time()
    
    # Parse additional args
    additional_args = args.split() if args else []
    
    # Run the scan
    result = run_containerized_tool(
        tool_name="nmap",
        target=target,
        args=additional_args,
        tool_configs=TOOL_CONFIGS
    )
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Log execution
    log_execution("nmap", target, result.success, duration_ms, result.stdout[:200])
    
    # Parse XML output
    hosts = []
    ports = []
    services = []
    
    if result.success and result.stdout:
        try:
            root = ET.fromstring(result.stdout)
            for host in root.findall('.//host'):
                addr = host.find('.//address[@addrtype="ipv4"]')
                if addr is not None:
                    ip = addr.get('addr')
                    hostname = host.find('.//hostnames/hostname')
                    name = hostname.get('name') if hostname is not None else None
                    hosts.append({"ip": ip, "hostname": name})
                    
                    for port in host.findall('.//port'):
                        portid = port.get('portid')
                        state = port.find('state').get('state') if port.find('state') is not None else 'unknown'
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        product = service.get('product') if service is not None else ''
                        version = service.get('version') if service is not None else ''
                        
                        if state == 'open':
                            ports.append({"port": int(portid), "protocol": port.get('protocol')})
                            services.append({
                                "port": int(portid),
                                "name": service_name,
                                "product": product,
                                "version": version
                            })
        except ET.ParseError:
            pass
    
    return {
        "success": result.success,
        "target": target,
        "hosts": hosts,
        "ports": ports,
        "services": services,
        "stdout_preview": result.stdout[:500] if result.stdout else "",
        "stderr": result.stderr[:200] if result.stderr else "",
        "duration_ms": duration_ms
    }


@server.tool()
def run_subdomain_enum(target: str, tool: str = "sublist3r", threads: int = 40) -> dict:
    """
    Enumerate subdomains for a target domain.
    
    This tool runs sublist3r (or other subdomain enumeration tools) in a hardened
    Docker container with scope enforcement.
    
    Args:
        target: Domain to enumerate subdomains for
        tool: Enumeration tool to use (default: sublist3r)
        threads: Number of threads for enumeration (default: 40)
        
    Returns:
        dict with 'success', 'subdomains' list, 'target' fields
    """
    start_time = time.time()
    
    # Build tool-specific args
    if tool == "sublist3r":
        args = ["-d", target, "-t", str(threads), "-o", "/dev/stdout"]
    else:
        args = ["-d", target, "-t", str(threads)]
    
    result = run_containerized_tool(
        tool_name=tool,
        target=target,
        args=args,
        tool_configs=TOOL_CONFIGS
    )
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Log execution
    log_execution(tool, target, result.success, duration_ms, result.stdout[:200])
    
    # Parse subdomains from output
    subdomains = []
    if result.success and result.stdout:
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line and '.' in line and not line.startswith('['):
                # Simple validation - looks like a subdomain
                if line.replace('.', '').replace('_', '').isalnum():
                    subdomains.append(line)
    
    return {
        "success": result.success,
        "target": target,
        "tool": tool,
        "subdomains": subdomains,
        "count": len(subdomains),
        "stdout_preview": result.stdout[:500] if result.stdout else "",
        "stderr": result.stderr[:200] if result.stderr else "",
        "duration_ms": duration_ms
    }


@server.tool()
def run_http_probe(target: str, ports: str = None, tls: bool = True) -> dict:
    """
    Probe HTTP/HTTPS endpoints for a target.
    
    This tool runs httpx in a hardened Docker container with scope enforcement.
    Returns status codes, titles, and other HTTP metadata.
    
    Args:
        target: Domain, IP, or URL to probe
        ports: Comma-separated ports to probe (default: 80,443,8080,8443)
        tls: Whether to enable TLS verification (default: True)
        
    Returns:
        dict with 'success', 'endpoints' list, 'target' fields
    """
    start_time = time.time()
    
    # Build args
    args = []
    if ports:
        args.extend(["-ports", ports])
    else:
        args.extend(["-ports", "80,443,8080,8443"])
    
    if not tls:
        args.append("-disable-https")
    
    result = run_containerized_tool(
        tool_name="httpx",
        target=target,
        args=args,
        tool_configs=TOOL_CONFIGS
    )
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Log execution
    log_execution("httpx", target, result.success, duration_ms, result.stdout[:200])
    
    # Parse JSON output
    endpoints = []
    if result.success and result.stdout:
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = __import__('json').loads(line)
                    endpoints.append({
                        "url": data.get('url'),
                        "status": data.get('status'),
                        "title": data.get('title'),
                        "tech": data.get('tech', {}),
                        "banner": data.get('banner', '')[:100]
                    })
                except:
                    pass
    
    return {
        "success": result.success,
        "target": target,
        "endpoints": endpoints,
        "count": len(endpoints),
        "stdout_preview": result.stdout[:500] if result.stdout else "",
        "stderr": result.stderr[:200] if result.stderr else "",
        "duration_ms": duration_ms
    }


@server.tool()
def human_confirm(action: str, risk: str = "medium", justification: str = "") -> dict:
    """
    Human-in-the-loop confirmation gate for high-risk actions.

    This middleware requires explicit approval before any high-risk tool action
    is executed. Medium and low-risk actions are auto-approved.
    """
    allowed = risk not in ("high",)
    return {
        "allowed": allowed,
        "action": action,
        "risk": risk,
        "justification": justification,
        "reason": "Auto-approved low/medium risk" if allowed else "Requires human approval for high risk"
    }


@server.tool()
def run_nuclei_scan(target: str, templates: str = None, severity: str = None) -> dict:
    """
    Run a nuclei vulnerability scan against a target.

    Returns a compact finding summary: count by severity, affected URLs, and
    top template IDs. Raw JSON is truncated to limit token usage.
    """
    start_time = time.time()
    args = ["-target", target]
    if templates:
        args.extend(["-templates", templates])
    if severity:
        args.extend(["-severity", severity])

    result = run_containerized_tool(tool_name="nuclei", target=target, args=args, tool_configs=TOOL_CONFIGS)
    duration_ms = int((time.time() - start_time) * 1000)
    log_execution("nuclei", target, result.success, duration_ms, result.stdout[:200])

    findings = []
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if result.success and result.stdout:
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = __import__("json").loads(line)
                sev = ((data.get("info") or {}).get("severity") or "info").lower()
                stats[sev] = stats.get(sev, 0) + 1
                findings.append({
                    "template_id": data.get("template_id"),
                    "name": ((data.get("info") or {}).get("name")),
                    "severity": sev,
                    "matched_url": data.get("matched_url") or data.get("url"),
                    "host": data.get("host"),
                })
            except Exception:
                continue

    return {
        "success": result.success,
        "target": target,
        "stats": stats,
        "findings": findings[:50],
        "finding_count": len(findings),
        "stdout_preview": result.stdout[:500] if result.stdout else "",
        "stderr": result.stderr[:200] if result.stderr else "",
        "duration_ms": duration_ms,
    }


@server.tool()
def run_semgrep_analysis(target: str, rules: str = "auto", config: str = "auto") -> dict:
    """
    Run semgrep static analysis against a target path/URL.

    Target must already be in scope. Output is summarized as a compact finding list.
    """
    start_time = time.time()
    args = ["--json", "--metrics=off"]
    if config and config != "auto":
        args.extend(["--config", config])
    if rules and rules != "auto":
        args.extend(["--config", rules])
    args.append(target)

    result = run_containerized_tool(tool_name="semgrep", target=target, args=args, tool_configs=TOOL_CONFIGS)
    duration_ms = int((time.time() - start_time) * 1000)
    log_execution("semgrep", target, result.success, duration_ms, result.stdout[:200])

    findings = []
    if result.success and result.stdout:
        try:
            data = __import__("json").loads(result.stdout)
            for item in (((data.get("results") or [])[:100])):
                finding = {
                    "rule_id": ((item.get("extra") or {}).get("metadata") or {}).get("rule-id"),
                    "message": (item.get("extra") or {}).get("message"),
                    "severity": ((item.get("extra") or {}).get("metadata") or {}).get("severity"),
                    "path": item.get("path"),
                    "start": item.get("start"),
                    "end": item.get("end"),
                }
                findings.append(finding)
        except Exception:
            pass

    return {
        "success": result.success,
        "target": target,
        "findings": findings,
        "finding_count": len(findings),
        "stdout_preview": result.stdout[:500] if result.stdout else "",
        "stderr": result.stderr[:200] if result.stderr else "",
        "duration_ms": duration_ms,
    }


@server.tool()
def run_payload_generator(target: str, scan_result: dict = None, risk: str = "low") -> dict:
    """
    Produce a bounded safe summary from prior scan results.

    No dynamic exploit-generation code is run.
    """
    if risk == "high":
        gate = human_confirm(action="run_payload_generator:" + target, risk=risk, justification="payload generation")
        if not gate.get("allowed"):
            return {"success": False, "target": target, "payload_preview": "", "stdout_preview": "", "stderr": gate.get("reason", "blocked"), "duration_ms": 0}

    start_time = time.time()
    scan_result = scan_result or {}
    lines = ["# Safe summary", f"\nTarget: {target}", f"Risk: {risk}"]
    ports = scan_result.get("ports", [])
    if ports:
        lines.append(f"Open ports: {[p['port'] for p in ports]}")
    findings = scan_result.get("findings") or scan_result.get("services") or []
    if findings:
        lines.append(f"Findings count: {len(findings)}")
    payload_preview = "\n".join(lines)

    duration_ms = int((time.time() - start_time) * 1000)
    log_execution("payload_generator", target, True, duration_ms, payload_preview[:200])
    return {
        "success": True,
        "target": target,
        "payload_preview": payload_preview,
        "stdout_preview": payload_preview,
        "stderr": "",
        "duration_ms": duration_ms,
    }


@server.tool()
def run_exploit_chain(target: str, actions: list = None, risk: str = "medium") -> dict:
    """
    Model an exploit workflow as a bounded audit-only chain.

    Does not execute custom exploit code. High-risk chains are blocked unless human_confirm approves.
    """
    if risk == "high":
        gate = human_confirm(action="run_exploit_chain:" + ",".join(actions or []), risk=risk, justification=target)
        if not gate.get("allowed"):
            return {
                "success": False,
                "blocked": True,
                "risk": risk,
                "reason": gate.get("reason", "blocked"),
                "target": target,
                "actions": actions or [],
                "duration_ms": 0,
            }

    return {
        "success": True,
        "blocked": False,
        "risk": risk,
        "target": target,
        "actions": actions or [],
        "reason": "Recorded for audit only",
        "duration_ms": 0,
    }


@server.tool()
def generate_report(path: str = None, fmt: str = "markdown", direct_outputs: list = None) -> dict:
    """
    Generate a compact report from the JSONL audit log and optional direct tool outputs.

    Writes a Markdown/JSON report to disk and returns a preview string.
    """
    import json
    from collections import Counter

    start_time = time.time()
    path = path or "audit.jsonl"
    direct_outputs = direct_outputs or []
    entries = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue
    except FileNotFoundError:
        if not direct_outputs:
            return {
                "success": False,
                "target": "",
                "report_preview": "",
                "stdout_preview": "",
                "stderr": f"missing {path}",
                "duration_ms": 0,
                "fmt": fmt,
                "entry_count": 0,
            }

    counts = Counter((e.get("tool"), e.get("target"), e.get("success")) for e in entries)
    lines = []
    for item in direct_outputs:
        tool = item.get("tool") or "unknown"
        target = item.get("target") or "unknown"
        p = item.get("path")
        content = ""
        if p:
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as df:
                    content = df.read().strip()
            except Exception:
                content = ""
        snippet = content[:200]
        if snippet:
            lines.append(f"- direct `{tool}` output for `{target}`:\n\n```text\n{snippet}\n```")
        else:
            lines.append(f"- direct `{tool}` output for `{target}`")
    for (tool, target, success), n in counts.items():
        lines.append(f"- `{tool}` for `{target}` success={success} count={n}")

    body = "\n".join(lines) if lines else "No entries found"

    if fmt == "markdown":
        report_preview = "# Audit Report\n\n" + body + "\n"
        file_ext = "md"
    else:
        report_preview = '{"summary":' + json.dumps(dict(counts)) + '}'
        file_ext = "json"

    report_path = f"report.{file_ext}"
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_preview)
    except Exception:
        report_path = ""

    duration_ms = int((time.time() - start_time) * 1000)
    log_execution("generate_report", path, True, duration_ms, report_preview[:200])
    return {
        "success": True,
        "target": "",
        "report_preview": report_preview,
        "stdout_preview": report_preview,
        "stderr": "",
        "duration_ms": duration_ms,
        "fmt": fmt,
        "entry_count": len(entries),
        "report_path": report_path,
    }


# Run the server when executed directly
if __name__ == "__main__":
    server.run()