"""
Tests for Phase 2 MCP tools: run_nmap_scan, run_subdomain_enum, run_http_probe.

Covers:
- Tool registration on the MCP server
- Correct delegation to run_containerized_tool with tool-specific configs
- Output parsing: nmap XML, sublist3r plaintext, httpx JSON lines
- Audit logging via log_execution
- Failure paths: empty output, parse errors, nonzero returncode
"""

import asyncio
import pytest
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock

from fraude.server import TOOL_CONFIGS, server
from fraude.server import run_nmap_scan, run_subdomain_enum, run_http_probe
from fraude.executor.docker_wrapper import ExecutionResult, ToolConfig
from fraude.scope.validator import ScopeConfig


# Fixtures
@pytest.fixture
def scope():
    return ScopeConfig(
        authorized_by='test@example.com',
        ip_ranges=['192.168.1.0/24'],
        domains=['example.com'],
        exclusions={'domains': [], 'ip_ranges': []}
    )


# Tests for tool registration
class TestPhase2ToolRegistration:
    def test_three_tools_registered(self):
        tool_names = [t.name for t in asyncio.run(server.list_tools())]
        assert 'run_nmap_scan' in tool_names
        assert 'run_subdomain_enum' in tool_names
        assert 'run_http_probe' in tool_names

    def test_validate_scope_still_registered(self):
        tool_names = [t.name for t in asyncio.run(server.list_tools())]
        assert 'validate_scope' in tool_names

    def test_tool_configs_include_phase2_tools(self):
        assert 'nmap' in TOOL_CONFIGS
        assert 'sublist3r' in TOOL_CONFIGS
        assert 'httpx' in TOOL_CONFIGS
        assert TOOL_CONFIGS['nmap'].image == 'instrumentisto/nmap'
        assert TOOL_CONFIGS['nmap'].default_args == ['-sT', '-sV']
        assert TOOL_CONFIGS['sublist3r'].image == 'abridges/sublist3r'
        assert TOOL_CONFIGS['httpx'].image == 'projectdiscovery/httpx'


# Tests for run_nmap_scan
class TestRunNmapScan:
    def test_delegates_to_containerized_tool(self, scope):
        fake_result = ExecutionResult(
            success=True,
            stdout='<?xml version="1.0"?><nmaprun></nmaprun>',
            stderr='',
            returncode=0
        )
        with patch('fraude.server.run_containerized_tool', return_value=fake_result) as mock_run:
            result = run_nmap_scan('scanme.nmap.org', args='-sV')
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs['tool_name'] == 'nmap'
            assert call_kwargs['target'] == 'scanme.nmap.org'
            assert '-sV' in call_kwargs['args']
            assert call_kwargs['tool_configs'] is TOOL_CONFIGS

    def test_parses_open_ports_from_xml(self, scope):
        xml_output = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="45.33.32.156" addrtype="ipv4"/>
            <status state="up"/>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="nginx" version="1.18.0"/>
              </port>
              <port protocol="tcp" portid="22">
                <state state="closed"/>
                <service name="ssh"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        fake_result = ExecutionResult(
            success=True,
            stdout=xml_output,
            stderr='',
            returncode=0
        )
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_nmap_scan('scanme.nmap.org')
            assert result['success'] is True
            assert result['target'] == 'scanme.nmap.org'
            assert len(result['hosts']) == 1
            assert result['hosts'][0]['ip'] == '45.33.32.156'
            assert len(result['ports']) == 1
            assert result['ports'][0]['port'] == 80
            assert result['services'][0]['name'] == 'http'
            assert result['services'][0]['product'] == 'nginx'

    def test_ignores_closed_ports(self, scope):
        xml_output = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="45.33.32.156" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="closed"/>
                <service name="ssh"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        fake_result = ExecutionResult(success=True, stdout=xml_output, stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_nmap_scan('scanme.nmap.org')
            assert result['ports'] == []
            assert result['services'] == []

    def test_handles_malformed_xml_gracefully(self, scope):
        fake_result = ExecutionResult(success=True, stdout='not xml', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_nmap_scan('scanme.nmap.org')
            assert result['success'] is True
            assert result['hosts'] == []
            assert result['ports'] == []
            assert 'not xml' in result['stdout_preview']

    def test_returns_failure_when_container_fails(self, scope):
        fake_result = ExecutionResult(
            success=False,
            stdout='',
            stderr='Host seems down',
            returncode=1
        )
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_nmap_scan('scanme.nmap.org')
            assert result['success'] is False
            assert result['stderr'] == 'Host seems down'

    def test_no_args_uses_defaults(self, scope):
        fake_result = ExecutionResult(success=True, stdout='<?xml version="1.0"?><nmaprun></nmaprun>', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result) as mock_run:
            run_nmap_scan('scanme.nmap.org')
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs['args'] == []

    def test_duration_ms_present(self, scope):
        fake_result = ExecutionResult(success=True, stdout='<?xml version="1.0"?><nmaprun></nmaprun>', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_nmap_scan('scanme.nmap.org')
            assert 'duration_ms' in result
            assert isinstance(result['duration_ms'], int)
            assert result['duration_ms'] >= 0

    def test_logs_execution(self, scope):
        fake_result = ExecutionResult(success=True, stdout='<?xml version="1.0"?><nmaprun></nmaprun>', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution') as mock_log:
                run_nmap_scan('scanme.nmap.org')
                mock_log.assert_called_once()
                assert mock_log.call_args[0][0] == 'nmap'
                assert mock_log.call_args[0][1] == 'scanme.nmap.org'
                assert mock_log.call_args[0][2] is True


# Tests for run_subdomain_enum
class TestRunSubdomainEnum:
    def test_delegates_to_containerized_tool(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result) as mock_run:
            run_subdomain_enum('example.com', tool='sublist3r', threads=10)
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs['tool_name'] == 'sublist3r'
            assert call_kwargs['target'] == 'example.com'
            assert '-d' in call_kwargs['args']
            assert '-t' in call_kwargs['args']
            assert '10' in call_kwargs['args']
            assert '-o' in call_kwargs['args']
            assert '/dev/stdout' in call_kwargs['args']

    def test_parses_subdomains_from_output(self, scope):
        fake_result = ExecutionResult(
            success=True,
            stdout='www.example.com\nmail.example.com\nftp.example.com\n',
            stderr='',
            returncode=0
        )
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_subdomain_enum('example.com')
            assert result['success'] is True
            assert result['count'] == 3
            assert 'www.example.com' in result['subdomains']
            assert 'mail.example.com' in result['subdomains']

    def test_filters_non_subdomain_lines(self, scope):
        fake_result = ExecutionResult(
            success=True,
            stdout='[*] Total Unique Subdomains Found: 3\nwww.example.com\nError: something\n',
            stderr='',
            returncode=0
        )
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_subdomain_enum('example.com')
            assert result['count'] == 1
            assert 'www.example.com' in result['subdomains']

    def test_empty_output(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='No subdomains found', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_subdomain_enum('example.com')
            assert result['subdomains'] == []
            assert result['count'] == 0

    def test_failure_result(self, scope):
        fake_result = ExecutionResult(success=False, stdout='', stderr='Tool error', returncode=1)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_subdomain_enum('example.com')
            assert result['success'] is False
            assert result['stderr'] == 'Tool error'

    def test_default_threads(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result) as mock_run:
            run_subdomain_enum('example.com')
            call_kwargs = mock_run.call_args[1]
            assert '40' in call_kwargs['args']

    def test_logs_execution(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution') as mock_log:
                run_subdomain_enum('example.com')
                mock_log.assert_called_once()
                assert mock_log.call_args[0][0] == 'sublist3r'
                assert mock_log.call_args[0][1] == 'example.com'
                assert mock_log.call_args[0][2] is True


# Tests for run_http_probe
class TestRunHttpProbe:
    def test_delegates_to_containerized_tool(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result) as mock_run:
            run_http_probe('example.com', ports='80,443', tls=True)
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs['tool_name'] == 'httpx'
            assert call_kwargs['target'] == 'example.com'
            assert '-ports' in call_kwargs['args']
            assert '80,443' in call_kwargs['args']

    def test_default_ports_when_none_specified(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result) as mock_run:
            run_http_probe('example.com')
            call_kwargs = mock_run.call_args[1]
            assert '80,443,8080,8443' in call_kwargs['args']

    def test_disable_https_flag(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result) as mock_run:
            run_http_probe('example.com', tls=False)
            call_kwargs = mock_run.call_args[1]
            assert '-disable-https' in call_kwargs['args']

    def test_parses_json_lines_output(self, scope):
        json_line = '{"url":"http://example.com","status":200,"title":"Example Domain","tech":{},"banner":""}'
        fake_result = ExecutionResult(success=True, stdout=json_line + '\n', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_http_probe('example.com')
            assert result['success'] is True
            assert result['count'] == 1
            assert result['endpoints'][0]['url'] == 'http://example.com'
            assert result['endpoints'][0]['status'] == 200
            assert result['endpoints'][0]['title'] == 'Example Domain'

    def test_parses_multiple_json_lines(self, scope):
        lines = '\n'.join([
            '{"url":"http://example.com","status":200,"title":"Home","tech":{"nginx":"1.18"},"banner":"nginx"}',
            '{"url":"https://example.com","status":301,"title":"","tech":{},"banner":""}'
        ])
        fake_result = ExecutionResult(success=True, stdout=lines, stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_http_probe('example.com')
            assert result['count'] == 2
            assert result['endpoints'][0]['tech'] == {'nginx': '1.18'}
            assert result['endpoints'][1]['status'] == 301

    def test_skips_malformed_json_lines(self, scope):
        lines = '\n'.join([
            'not json',
            '{"url":"http://example.com","status":200,"title":"Home","tech":{},"banner":""}',
            '{invalid json'
        ])
        fake_result = ExecutionResult(success=True, stdout=lines, stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_http_probe('example.com')
            assert result['count'] == 1
            assert result['endpoints'][0]['status'] == 200

    def test_empty_output(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='No endpoints', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_http_probe('example.com')
            assert result['endpoints'] == []
            assert result['count'] == 0

    def test_failure_result(self, scope):
        fake_result = ExecutionResult(success=False, stdout='', stderr='Connection timeout', returncode=1)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_http_probe('example.com')
            assert result['success'] is False
            assert result['stderr'] == 'Connection timeout'

    def test_duration_ms_present(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            result = run_http_probe('example.com')
            assert 'duration_ms' in result
            assert isinstance(result['duration_ms'], int)
            assert result['duration_ms'] >= 0

    def test_logs_execution(self, scope):
        fake_result = ExecutionResult(success=True, stdout='', stderr='', returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution') as mock_log:
                run_http_probe('example.com')
                mock_log.assert_called_once()
                assert mock_log.call_args[0][0] == 'httpx'
                assert mock_log.call_args[0][1] == 'example.com'
                assert mock_log.call_args[0][2] is True
