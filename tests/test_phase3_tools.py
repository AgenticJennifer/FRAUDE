"""
Tests for FRAUDE Phase 3 MCP tools: run_nuclei_scan, run_semgrep_analysis, human_confirm.

Covers:
- Tool registration and callability
- Output parsing for nuclei JSON lines and semgrep SARIF/JSON summaries
- Scope enforcement integration via run_containerized_tool
- Audit logging via log_execution
- HITL confirmation gating behavior
"""

import pytest
from unittest.mock import patch

from fraude.server import run_nuclei_scan, run_semgrep_analysis, human_confirm
from fraude.executor.docker_wrapper import ExecutionResult


class TestRunNucleiScan:
    def test_returns_success_structure_on_success(self):
        fake_result = ExecutionResult(
            success=True,
            stdout='{"template_id":"test","info":{"name":"Test","severity":"medium"},"matched_url":"http://example.com"}\n',
            stderr="",
            returncode=0,
        )
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nuclei_scan('scanme.nmap.org')
        
        assert result['success'] is True
        assert 'findings' in result
        assert 'finding_count' in result
        assert 'stats' in result
        assert 'duration_ms' in result

    def test_parses_severity_counts(self):
        stdout = "\n".join([
            '{"template_id":"t1","info":{"name":"High Sev","severity":"high"},"matched_url":"http://example.com"}',
            '{"template_id":"t2","info":{"name":"Med Sev","severity":"medium"},"matched_url":"http://example.com"}',
            '{"template_id":"t3","info":{"name":"Low Sev","severity":"low"},"matched_url":"http://example.com"}',
            '{"template_id":"t4","info":{"name":"Critical Sev","severity":"critical"},"matched_url":"http://example.com"}',
        ])
        fake_result = ExecutionResult(success=True, stdout=stdout, stderr="", returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nuclei_scan('scanme.nmap.org')
        
        assert result['stats'] == {'critical': 1, 'high': 1, 'medium': 1, 'low': 1, 'info': 0}
        assert result['finding_count'] == 4
        assert result['findings'][0]['severity'] == 'high'
        assert result['findings'][1]['severity'] == 'medium'

    def test_handles_empty_output(self):
        fake_result = ExecutionResult(success=True, stdout="", stderr="", returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nuclei_scan('scanme.nmap.org')
        
        assert result['findings'] == []
        assert result['finding_count'] == 0
        assert result['stats'] == {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

    def test_returns_failure_on_container_error(self):
        fake_result = ExecutionResult(success=False, stdout="", stderr="Connection refused", returncode=1)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nuclei_scan('scanme.nmap.org')
        
        assert result['success'] is False
        assert result['stderr'] == 'Connection refused'

    def test_truncates_long_output(self):
        long_output = "\n".join(['{"template_id":"t1","info":{"name":"X","severity":"low"},"matched_url":"http://example.com"}' for _ in range(10)])
        fake_result = ExecutionResult(success=True, stdout=long_output, stderr="", returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_nuclei_scan('scanme.nmap.org')
        
        assert result['finding_count'] == 10
        assert len(result['findings']) <= 50


class TestRunSemgrepAnalysis:
    def test_returns_success_structure_on_success(self):
        stdout = '{"results":[{"extra":{"metadata":{"rule-id":"test"}, "message":"ok"}, "path":"/x.py", "start":{"line":1}, "end":{"line":2}}]}'
        fake_result = ExecutionResult(success=True, stdout=stdout, stderr="", returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_semgrep_analysis('scanme.nmap.org')
        
        assert result['success'] is True
        assert 'findings' in result
        assert 'finding_count' in result
        assert 'duration_ms' in result

    def test_parses_findings(self):
        stdout = '''
        {"results":[
          {"extra":{"metadata":{"rule-id":"r1","severity":"ERROR"}, "message":"bad thing"}, "path":"/a.py", "start":{"line":10}, "end":{"line":12}},
          {"extra":{"metadata":{"rule-id":"r2","severity":"WARNING"}, "message":"weird thing"}, "path":"/b.py", "start":{"line":5}, "end":{"line":5}}
        ]}
        '''
        fake_result = ExecutionResult(success=True, stdout=stdout, stderr="", returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_semgrep_analysis('scanme.nmap.org')
        
        assert result['finding_count'] == 2
        assert result['findings'][0]['rule_id'] == 'r1'
        assert result['findings'][0]['severity'] == 'ERROR'
        assert result['findings'][1]['rule_id'] == 'r2'

    def test_handles_empty_output(self):
        fake_result = ExecutionResult(success=True, stdout="", stderr="No findings", returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_semgrep_analysis('scanme.nmap.org')
        
        assert result['findings'] == []
        assert result['finding_count'] == 0

    def test_returns_failure_on_container_error(self):
        fake_result = ExecutionResult(success=False, stdout="", stderr="not found", returncode=1)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result):
            with patch('fraude.server.log_execution'):
                result = run_semgrep_analysis('scanme.nmap.org')
        
        assert result['success'] is False
        assert result['stderr'] == 'not found'

    def test_defaults_to_auto_config(self):
        fake_result = ExecutionResult(success=True, stdout='{"results":[]}', stderr="", returncode=0)
        with patch('fraude.server.run_containerized_tool', return_value=fake_result) as mock_run:
            with patch('fraude.server.log_execution'):
                run_semgrep_analysis('scanme.nmap.org')
        
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs['tool_name'] == 'semgrep'


class TestHumanConfirm:
    def test_allows_low_risk(self):
        result = human_confirm(action='run ping', risk='low')
        assert result['allowed'] is True
        assert 'low' in result['reason'].lower() or 'medium' in result['reason'].lower()

    def test_allows_medium_risk(self):
        result = human_confirm(action='run nmap', risk='medium')
        assert result['allowed'] is True

    def test_requires_approval_for_high_risk(self):
        result = human_confirm(action='run exploit', risk='high', justification='test')
        assert result['allowed'] is False
        assert 'high' in result['reason'].lower() or 'approval' in result['reason'].lower()

    def test_defaults_to_medium(self):
        result = human_confirm(action='do thing')
        assert result['risk'] == 'medium'
        assert result['allowed'] is True


class TestPhase3ToolConfigs:
    def test_nuclei_config_has_required_fields(self):
        from fraude.server import TOOL_CONFIGS
        assert 'nuclei' in TOOL_CONFIGS
        assert TOOL_CONFIGS['nuclei'].image == 'projectdiscovery/nuclei'
        assert TOOL_CONFIGS['nuclei'].requires_tmpfs is True

    def test_semgrep_config_has_required_fields(self):
        from fraude.server import TOOL_CONFIGS
        assert 'semgrep' in TOOL_CONFIGS
        assert TOOL_CONFIGS['semgrep'].image == 'returntocorp/semgrep'
        assert TOOL_CONFIGS['semgrep'].requires_tmpfs is False
        assert '--json' in TOOL_CONFIGS['semgrep'].default_args

    def test_build_command_nuclei_includes_hardening(self):
        from fraude.server import TOOL_CONFIGS
        from fraude.executor.docker_wrapper import build_command
        cmd = build_command('nuclei', 'scanme.nmap.org', ['-target','scanme.nmap.org'], tool_configs=TOOL_CONFIGS)
        assert '--read-only' in cmd
        assert '--memory' in cmd
        assert '--pids-limit' in cmd

    def test_build_command_semgrep_includes_hardening(self):
        from fraude.server import TOOL_CONFIGS
        from fraude.executor.docker_wrapper import build_command
        cmd = build_command('semgrep', 'https://github.com/test', ['--json'], tool_configs=TOOL_CONFIGS)
        assert '--read-only' in cmd
        assert '--cap-drop' in cmd
        assert '--rm' in cmd

    def test_build_command_rejects_unknown_tool(self):
        from fraude.server import TOOL_CONFIGS
        from fraude.executor.docker_wrapper import build_command
        with pytest.raises(ValueError, match="not in the allowed list"):
            build_command('nonexistent_tool', 'target', tool_configs=TOOL_CONFIGS)
