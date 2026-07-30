"""
Tests for Docker execution wrapper.

Covers:
- Command construction for different tools
- Scope gate enforcement
- Hardened flags applied correctly
- Timeout handling
- Error handling
"""

import pytest
import tempfile
import os
from unittest.mock import patch, MagicMock, call

from fraude.executor.docker_wrapper import (
    build_command,
    run_containerized_tool,
    ExecutionResult,
    ToolConfig,
    DEFAULT_HARDENING_FLAGS,
    _get_allowed_tools
)
from fraude.scope.models import ScopeConfig, ScopeViolation
from fraude.scope.validator import load_scope, reset_scope


# Fixtures
@pytest.fixture
def temp_scope_file():
    """Create a temporary scope.yaml file for testing."""
    def _create(content: dict):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(content, f)
            return f.name
    return _create


@pytest.fixture
def valid_scope(temp_scope_file):
    """Return a valid in-scope target."""
    content = {
        'metadata': {'authorized_by': 'test@example.com'},
        'ip_ranges': ['192.168.1.0/24'],
        'domains': ['example.com']
    }
    path = temp_scope_file(content)
    scope = load_scope(path)
    reset_scope()
    yield scope, path
    os.unlink(path)
    reset_scope()


@pytest.fixture
def forbidden_scope(temp_scope_file):
    """Return a scope with a forbidden target."""
    content = {
        'metadata': {'authorized_by': 'test@example.com'},
        'ip_ranges': ['192.168.1.0/24'],
        'domains': ['allowed.com']
    }
    path = temp_scope_file(content)
    scope = load_scope(path)
    reset_scope()
    yield scope, path
    os.unlink(path)
    reset_scope()


# Tests for build_command
class TestBuildCommand:
    def test_build_nmap_command_base(self):
        cmd = build_command('nmap', '192.168.1.1')
        
        assert 'docker' in cmd
        assert 'run' in cmd
        assert '--rm' in cmd
        assert '192.168.1.1' in cmd
        assert 'instrumentisto/nmap' in cmd
    
    def test_hardening_flags_present(self):
        cmd = build_command('nmap', '192.168.1.1')
        
        # Check all hardening flags are present
        assert '--read-only' in cmd
        assert '--cap-drop' in cmd
        assert 'ALL' in cmd
        assert '--user' in cmd
        assert '1000:1000' in cmd
        assert '--memory' in cmd
        assert '512m' in cmd
        assert '--cpus' in cmd
        assert '1.0' in cmd
        assert '--pids-limit' in cmd
        assert '100' in cmd
    
    def test_tmpfs_for_nmap(self):
        cmd = build_command('nmap', '192.168.1.1')
        
        # nmap requires tmpfs
        assert '--tmpfs' in cmd
        # The tmpfs mount is '/tmp:rw,noexec,nosuid,size=100m'
        assert any('/tmp' in arg for arg in cmd)
    
    def test_network_host_flag(self):
        cmd = build_command('nmap', '192.168.1.1')
        
        assert '--network' in cmd
        assert 'host' in cmd
    
    def test_custom_args_appended(self):
        cmd = build_command('nmap', '192.168.1.1', args=['-sS', '-p', '22'])
        
        assert '-sS' in cmd
        assert '-p' in cmd
        assert '22' in cmd
    
    def test_target_at_start_of_tool_args(self):
        cmd = build_command('nmap', '192.168.1.1', args=['-sS'])
        
        # Find position of image and target
        image_idx = cmd.index('instrumentisto/nmap')
        target_idx = cmd.index('192.168.1.1')
        
        # Target should come before the scan args
        assert target_idx < cmd.index('-sS')
    
    def test_unknown_tool_raises_error(self):
        with pytest.raises(ValueError) as exc_info:
            build_command('unknown-tool', '192.168.1.1')
        assert "not in the allowed list" in str(exc_info.value)
    
    def test_custom_tool_configs(self):
        custom_config = {
            'test-tool': ToolConfig(
                image='test/image',
                default_args=['--verbose'],
                requires_tmpfs=False
            )
        }
        
        cmd = build_command('test-tool', '10.0.0.1', tool_configs=custom_config)
        
        assert 'test/image' in cmd
        assert '--verbose' in cmd
        assert '10.0.0.1' in cmd
    
    def test_returns_list(self):
        cmd = build_command('nmap', '192.168.1.1')
        assert isinstance(cmd, list)


# Tests for run_containerized_tool
class TestRunContainerizedTool:
    @pytest.fixture(autouse=True)
    def setup(self, valid_scope):
        self.scope, self.scope_path = valid_scope
    
    def test_validates_scope_first(self):
        """Scope validation should happen before any execution."""
        fake_runner = MagicMock()
        
        with pytest.raises(ScopeViolation):
            run_containerized_tool(
                'nmap',
                '10.0.0.1',  # Out of scope
                scope_config=self.scope,
                subprocess_runner=fake_runner
            )
        
        # Runner should never have been called
        fake_runner.assert_not_called()
    
    def test_calls_docker_with_correct_command(self):
        fake_runner = MagicMock()
        fake_runner.return_value = MagicMock(
            stdout='Nmap done',
            stderr='',
            returncode=0
        )
        
        result = run_containerized_tool(
            'nmap',
            '192.168.1.1',
            scope_config=self.scope,
            subprocess_runner=fake_runner
        )
        
        assert result.success == True
        fake_runner.assert_called_once()
        
        # Check command structure
        call_args = fake_runner.call_args[0][0]
        assert call_args[0] == 'docker'
        assert call_args[1] == 'run'
    
    def test_returns_execution_result(self):
        fake_runner = MagicMock()
        fake_runner.return_value = MagicMock(
            stdout='Scan output',
            stderr='',
            returncode=0
        )
        
        result = run_containerized_tool(
            'nmap',
            '192.168.1.1',
            scope_config=self.scope,
            subprocess_runner=fake_runner
        )
        
        assert isinstance(result, ExecutionResult)
        assert result.success == True
        assert result.stdout == 'Scan output'
        assert result.stderr == ''
        assert result.returncode == 0
    
    def test_handles_nonzero_return_code(self):
        fake_runner = MagicMock()
        fake_runner.return_value = MagicMock(
            stdout='',
            stderr='Host seems down',
            returncode=1
        )
        
        result = run_containerized_tool(
            'nmap',
            '192.168.1.1',
            scope_config=self.scope,
            subprocess_runner=fake_runner
        )
        
        assert result.success == False
        assert result.returncode == 1
    
    def test_handles_timeout(self):
        def timeout_runner(*args, **kwargs):
            raise TimeoutError("Timeout")
        
        result = run_containerized_tool(
            'nmap',
            '192.168.1.1',
            scope_config=self.scope,
            subprocess_runner=timeout_runner
        )
        
        assert result.success == False
        assert result.returncode == -1
        assert "timed out" in result.stderr.lower() or "timeout" in str(result.stderr).lower()
    
    def test_handles_generic_exception(self):
        def error_runner(*args, **kwargs):
            raise RuntimeError("Docker not available")
        
        result = run_containerized_tool(
            'nmap',
            '192.168.1.1',
            scope_config=self.scope,
            subprocess_runner=error_runner
        )
        
        assert result.success == False
        assert result.returncode == -1
        assert "Docker not available" in result.stderr


# Tests for ExecutionResult
class TestExecutionResult:
    def test_success_result(self):
        result = ExecutionResult(
            success=True,
            stdout='output',
            stderr='',
            returncode=0
        )
        assert result.success == True
        assert result.stdout == 'output'
    
    def test_failure_result(self):
        result = ExecutionResult(
            success=False,
            stdout='',
            stderr='error',
            returncode=1
        )
        assert result.success == False
        assert result.stderr == 'error'


# Tests for ToolConfig
class TestToolConfig:
    def test_create_tool_config(self):
        config = ToolConfig(
            image='test/image',
            default_args=['-v'],
            requires_tmpfs=True
        )
        
        assert config.image == 'test/image'
        assert config.default_args == ['-v']
        assert config.requires_tmpfs == True
    
    def test_tool_config_defaults(self):
        config = ToolConfig(image='test/image')
        
        assert config.default_args == []
        assert config.requires_tmpfs == False


# Tests for DEFAULT_HARDENING_FLAGS
class TestDefaultHardeningFlags:
    def test_all_flags_present(self):
        expected_flags = [
            '--read-only',
            '--cap-drop', 'ALL',
            '--user', '1000:1000',
            '--memory', '512m',
            '--cpus', '1.0',
            '--pids-limit', '100'
        ]
        
        for flag in expected_flags:
            assert flag in DEFAULT_HARDENING_FLAGS


# Tests for get_tool_image
class TestGetToolImage:
    def test_get_nmap_image(self):
        image = run_containerized_tool.__globals__['_get_allowed_tools']
        # Get the tools dict
        tools = image()
        
        # This should work after _get_allowed_tools initializes
        from fraude.executor.docker_wrapper import get_tool_image
        img = get_tool_image('nmap')
        assert img == 'instrumentisto/nmap'
    
    def test_unknown_tool_raises_error(self):
        from fraude.executor.docker_wrapper import get_tool_image
        
        with pytest.raises(ValueError):
            get_tool_image('nonexistent-tool')


# Integration test: scope enforcement blocks out-of-scope
class TestScopeEnforcementIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, temp_scope_file):
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': ['10.0.0.0/8'],
            'domains': ['allowed.com']
        }
        path = temp_scope_file(content)
        self.scope = load_scope(path)
        reset_scope()
        yield
        os.unlink(path)
        reset_scope()
    
    def test_scope_violation_raises_exception(self):
        fake_runner = MagicMock()
        
        with pytest.raises(ScopeViolation) as exc_info:
            run_containerized_tool(
                'nmap',
                '192.168.1.1',  # Not in 10.0.0.0/8
                scope_config=self.scope,
                subprocess_runner=fake_runner
            )
        
        assert "not in authorized" in str(exc_info.value.reason).lower()
        fake_runner.assert_not_called()
    
    def test_valid_target_executes(self):
        fake_runner = MagicMock()
        fake_runner.return_value = MagicMock(stdout='result', stderr='', returncode=0)
        
        result = run_containerized_tool(
            'nmap',
            '10.0.0.1',  # In 10.0.0.0/8
            scope_config=self.scope,
            subprocess_runner=fake_runner
        )
        
        assert result.success == True
        fake_runner.assert_called_once()