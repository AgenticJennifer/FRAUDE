"""
Tests for FRAUDE Phase 2 MCP tools: run_nmap_scan, run_subdomain_enum, run_http_probe.

These tests verify:
- Tool registration and callability
- Output parsing for nmap XML, subdomain text, and httpx JSON
- Scope enforcement integration via run_containerized_tool
- Audit logging via log_execution
"""

import pytest
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock

from fraude.server import run_nmap_scan, run_subdomain_enum, run_http_probe
from fraude.executor.docker_wrapper import ExecutionResult, ToolConfig, build_command
from fraude.audit.logger import AuditLogger


class TestRunNmapScan:
    """Tests for run_nmap_scan tool."""

    def test_returns_success_structure_on_success(self):
        """Should return structured dict on successful scan."""
        fake_result = ExecutionResult(
            success=True,
            stdout="<?xml version='1.0'?><nmaprun></nmaprun>",
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nmap_scan("scanme.nmap.org")
        
        assert 'success' in result
        assert 'target' in result
        assert 'hosts' in result
        assert 'ports' in result
        assert 'services' in result
        assert 'duration_ms' in result

    def test_returns_failure_on_docker_failure(self):
        """Should return success=False when docker run fails."""
        fake_result = ExecutionResult(
            success=False,
            stdout="",
            stderr="Connection refused",
            returncode=1
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nmap_scan("scanme.nmap.org")
        
        assert result['success'] is False
        assert result['target'] == 'scanme.nmap.org'
        assert 'stderr' in result

    def test_parses_open_ports_from_xml(self):
        """Should extract open ports from nmap XML output."""
        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" args="...">
            <host>
                <address addr="45.33.32.156" addrtype="ipv4"/>
                <hostnames><hostname name="scanme.nmap.org"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="8.9p1"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="Apache" version="2.4.41"/>
                    </port>
                    <port protocol="tcp" portid="3306">
                        <state state="closed"/>
                        <service name="mysql"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        
        fake_result = ExecutionResult(
            success=True,
            stdout=xml_output,
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nmap_scan("scanme.nmap.org")
        
        assert len(result['hosts']) == 1
        assert result['hosts'][0]['ip'] == '45.33.32.156'
        assert result['hosts'][0]['hostname'] == 'scanme.nmap.org'
        
        # Only open ports should be included
        assert len(result['ports']) == 2
        assert 22 in [p['port'] for p in result['ports']]
        assert 80 in [p['port'] for p in result['ports']]
        assert 3306 not in [p['port'] for p in result['ports']]
        
        assert len(result['services']) == 2
        assert result['services'][0]['name'] == 'ssh'
        assert result['services'][1]['name'] == 'http'

    def test_handles_malformed_xml_gracefully(self):
        """Should not crash on malformed XML."""
        fake_result = ExecutionResult(
            success=True,
            stdout="not valid xml at all",
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nmap_scan("scanme.nmap.org")
        
        assert result['success'] is True
        assert result['hosts'] == []
        assert result['ports'] == []
        assert result['services'] == []

    def test_calls_audit_logger(self):
        """Should log execution via log_execution."""
        fake_result = ExecutionResult(
            success=True,
            stdout="<?xml version='1.0'?><nmaprun></nmaprun>",
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution') as mock_log:
                result = run_nmap_scan("scanme.nmap.org")
        
        mock_log.assert_called_once()
        assert mock_log.call_args[0][0] == 'nmap'
        assert mock_log.call_args[0][1] == 'scanme.nmap.org'


class TestRunSubdomainEnum:
    """Tests for run_subdomain_enum tool."""

    def test_returns_success_structure(self):
        """Should return structured dict."""
        fake_result = ExecutionResult(
            success=True,
            stdout="www.example.com\nmail.example.com\nftp.example.com\n",
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_subdomain_enum("example.com")
        
        assert result['success'] is True
        assert result['target'] == 'example.com'
        assert 'subdomains' in result
        assert 'count' in result

    def test_parses_subdomains_from_output(self):
        """Should extract subdomains from stdout."""
        fake_result = ExecutionResult(
            success=True,
            stdout="www.example.com\napi.example.com\ninternal.example.com\nerror [something]\n",
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_subdomain_enum("example.com")
        
        assert result['count'] == 3
        assert 'www.example.com' in result['subdomains']
        assert 'api.example.com' in result['subdomains']
        assert 'internal.example.com' in result['subdomains']
        # Should skip lines starting with '[' or without dots
        assert not any('error' in s for s in result['subdomains'])

    def test_handles_empty_output(self):
        """Should handle empty stdout gracefully."""
        fake_result = ExecutionResult(
            success=True,
            stdout="",
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_subdomain_enum("example.com")
        
        assert result['subdomains'] == []
        assert result['count'] == 0

    def test_calls_audit_logger_with_tool_name(self):
        """Should log execution with the actual tool name."""
        fake_result = ExecutionResult(
            success=True,
            stdout="www.example.com\n",
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution') as mock_log:
                result = run_subdomain_enum("example.com", tool="sublist3r")
        
        mock_log.assert_called_once()
        assert mock_log.call_args[0][0] == 'sublist3r'


class TestRunHttpProbe:
    """Tests for run_http_probe tool."""

    def test_returns_success_structure(self):
        """Should return structured dict."""
        fake_result = ExecutionResult(
            success=True,
            stdout='{"url":"http://example.com","status":200,"title":"Example"}\n',
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_http_probe("example.com")
        
        assert result['success'] is True
        assert result['target'] == 'example.com'
        assert 'endpoints' in result
        assert 'count' in result

    def test_parses_json_output(self):
        """Should parse JSON lines from httpx output."""
        fake_result = ExecutionResult(
            success=True,
            stdout='{"url":"http://example.com","status":200,"title":"Example Domain"}\n{"url":"https://example.com","status":200,"title":"Example Domain"}\n',
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_http_probe("example.com")
        
        assert result['count'] == 2
        assert result['endpoints'][0]['url'] == 'http://example.com'
        assert result['endpoints'][0]['status'] == 200
        assert result['endpoints'][0]['title'] == 'Example Domain'

    def test_handles_malformed_json_lines(self):
        """Should skip malformed JSON lines without crashing."""
        fake_result = ExecutionResult(
            success=True,
            stdout='{"url":"http://example.com","status":200}\nnot json\n{"url":"https://example.com","status":301}\n',
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_http_probe("example.com")
        
        assert result['count'] == 2
        assert result['endpoints'][0]['url'] == 'http://example.com'
        assert result['endpoints'][1]['url'] == 'https://example.com'

    def test_handles_empty_output(self):
        """Should handle empty stdout."""
        fake_result = ExecutionResult(
            success=True,
            stdout="",
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_http_probe("example.com")
        
        assert result['endpoints'] == []
        assert result['count'] == 0

    def test_calls_audit_logger(self):
        """Should log execution via log_execution."""
        fake_result = ExecutionResult(
            success=True,
            stdout='{"url":"http://example.com","status":200}\n',
            stderr="",
            returncode=0
        )
        
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution') as mock_log:
                result = run_http_probe("example.com")
        
        mock_log.assert_called_once()
        assert mock_log.call_args[0][0] == 'httpx'
        assert mock_log.call_args[0][1] == 'example.com'


class TestToolConfigs:
    """Tests for tool configuration."""

    def test_nmap_config_has_required_fields(self):
        """Should have image and tmpfs flag."""
        from fraude.server import TOOL_CONFIGS
        
        assert 'nmap' in TOOL_CONFIGS
        assert TOOL_CONFIGS['nmap'].image == 'instrumentisto/nmap'
        assert TOOL_CONFIGS['nmap'].requires_tmpfs is True

    def test_sublist3r_config_has_required_fields(self):
        """Should have image and tmpfs flag."""
        from fraude.server import TOOL_CONFIGS
        
        assert 'sublist3r' in TOOL_CONFIGS
        assert TOOL_CONFIGS['sublist3r'].image == 'abridges/sublist3r'
        assert TOOL_CONFIGS['sublist3r'].requires_tmpfs is True

    def test_httpx_config_has_required_fields(self):
        """Should have image and tmpfs flag."""
        from fraude.server import TOOL_CONFIGS
        
        assert 'httpx' in TOOL_CONFIGS
        assert TOOL_CONFIGS['httpx'].image == 'projectdiscovery/httpx'
        assert TOOL_CONFIGS['httpx'].requires_tmpfs is True

    def test_build_command_includes_hardening_flags(self):
        """Should include default hardening flags and tmpfs."""
        from fraude.server import TOOL_CONFIGS
        
        cmd = build_command('nmap', 'scanme.nmap.org', ['-p-'], tool_configs=TOOL_CONFIGS)
        
        assert '--read-only' in cmd
        assert '--cap-drop' in cmd
        assert 'ALL' in cmd
        assert '--user' in cmd
        assert '--memory' in cmd
        assert '--cpus' in cmd
        assert '--pids-limit' in cmd
        assert '--tmpfs' in cmd
        assert '--network' in cmd
        assert '--rm' in cmd
        assert 'instrumentisto/nmap' in cmd
        assert 'scanme.nmap.org' in cmd

    def test_build_command_rejects_unknown_tool(self):
        """Should raise ValueError for non-allowlisted tools."""
        from fraude.server import TOOL_CONFIGS
        
        with pytest.raises(ValueError, match="not in the allowed list"):
            build_command('nonexistent_tool', 'target', tool_configs=TOOL_CONFIGS)
