import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch

from fraude.server import run_nuclei_scan, run_semgrep_analysis, human_confirm
import fraude.server as server_mod

try:
    from fraude.server import run_payload_generator, run_exploit_chain, generate_report
except ImportError:
    pass


class TestRunPayloadGenerator:
    def test_returns_success_structure(self):
        result = server_mod.run_payload_generator(
            target="scanme.nmap.org",
            scan_result={"ports": [{"port": 80, "protocol": "tcp"}]},
            risk="low"
        )
        assert result["success"] is True
        assert "payload_preview" in result
        assert result["payload_preview"].startswith("# Safe summary")


class TestRunExploitChain:
    def test_enforces_hitl_for_high_risk(self):
        with patch('fraude.server.human_confirm', return_value={"allowed": False, "reason": "needs approval"}):
            result = server_mod.run_exploit_chain(
                target="scanme.nmap.org",
                actions=["run_nmap_scan"],
                risk="high"
            )
        assert result["blocked"] is True
        assert "approval" in result["reason"].lower()

    def test_non_high_risk_does_not_block(self):
        with patch('fraude.server.human_confirm', return_value={"allowed": True, "reason": "ok"}):
            result = server_mod.run_exploit_chain(
                target="scanme.nmap.org",
                actions=["run_nmap_scan"],
                risk="medium"
            )
        assert result["blocked"] is False
        assert result["success"] is True


class TestGenerateReport:
    def test_generate_report_markdown_from_jsonl(self, tmp_path):
        audit_path = tmp_path / "audit.jsonl"
        audit_path.write_text(
            json.dumps({"tool": "nmap", "target": "scanme.nmap.org", "success": True, "duration_ms": 10}) + "\n"
        )
        result = server_mod.generate_report(path=str(audit_path), fmt="markdown")
        assert result["success"] is True
        assert "scanme.nmap.org" in result["report_preview"]
        assert result["fmt"] == "markdown"
        assert result["entry_count"] == 1

    def test_generate_report_handles_missing_file(self):
        result = server_mod.generate_report(path="__missing__.jsonl", fmt="markdown")
        assert result["success"] is False
        assert "missing" in result["stderr"].lower()

    def test_generate_report_handles_invalid_json(self, tmp_path):
        audit_path = tmp_path / "bad.jsonl"
        audit_path.write_text("not-json\n")
        result = server_mod.generate_report(path=str(audit_path), fmt="json")
        assert result["success"] is True
        assert result["entry_count"] == 0


class TestGenerateReportInlineOutputs:
    def test_ingests_direct_outputs_markdown(self, tmp_path):
        report_path = tmp_path / "report.md"
        content = "# Direct summary\n## nmap\nPort 80 open on scanme.nmap.org\n"
        report_path.write_text(content, encoding="utf-8")

        out = server_mod.generate_report(
            path=None,
            fmt="markdown",
            direct_outputs=[
                {"tool": "nmap", "target": "scanme.nmap.org", "path": str(report_path)}
            ]
        )
        assert out["success"] is True
        assert "scanme.nmap.org" in out["report_preview"]
        assert "Port 80" in out["report_preview"]

    def test_ingests_malformed_direct_output(self, tmp_path):
        bad = tmp_path / "bad.txt"
        bad.write_text("??? not valid ???\n", encoding="utf-8")
        out = server_mod.generate_report(
            path=None,
            fmt="markdown",
            direct_outputs=[
                {"tool": "nmap", "target": "scanme.nmap.org", "path": str(bad)}
            ]
        )
        assert out["success"] is True
        assert "scanme.nmap.org" in out["report_preview"]
