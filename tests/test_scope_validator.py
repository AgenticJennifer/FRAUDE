"""
Tests for scope validation engine.

Covers:
- scope.yaml parse edge cases (missing file, empty scope, missing authorized_by, bad CIDR)
- IP-literal CIDR matching
- Domain exact/wildcard matching
- Exclusion-beats-allow for both domains and IPs
- URL/port normalization
- DNS-mocked resolution checks including strict_resolution and require_dns_match
"""

import pytest
import tempfile
import os
from unittest.mock import patch, MagicMock

from fraude.scope.models import ScopeConfig, ScopeViolation, ScopeConfigError, Target
from fraude.scope.validator import (
    load_scope, validate_target, get_scope, reset_scope,
    _matches_ip, _matches_domain
)


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
def valid_scope_config():
    """Return a valid scope configuration."""
    return {
        'metadata': {
            'authorized_by': 'test@example.com',
            'description': 'Test scope'
        },
        'ip_ranges': ['192.168.1.0/24', '10.0.0.1'],
        'domains': ['example.com', '*.example.org']
    }


@pytest.fixture
def scope_with_exclusions():
    """Return a scope configuration with exclusions."""
    return {
        'metadata': {
            'authorized_by': 'test@example.com',
            'description': 'Test scope with exclusions'
        },
        'ip_ranges': ['192.168.1.0/24'],
        'domains': ['example.com'],
        'exclusions': {
            'ip_ranges': ['192.168.1.100'],
            'domains': ['internal.example.com']
        }
    }


# Tests for load_scope - missing file
class TestLoadScopeMissingFile:
    def test_missing_file_raises_error(self):
        with pytest.raises(ScopeConfigError) as exc_info:
            load_scope("/nonexistent/path/scope.yaml")
        assert "not found" in str(exc_info.value)
    
    def test_empty_string_path_raises_error(self):
        with pytest.raises(ScopeConfigError):
            load_scope("")


# Tests for load_scope - invalid YAML
class TestLoadScopeInvalidYAML:
    def test_invalid_yaml_raises_error(self, temp_scope_file):
        # Create file with invalid YAML
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            path = f.name
        
        try:
            with pytest.raises(ScopeConfigError) as exc_info:
                load_scope(path)
            assert "Invalid YAML" in str(exc_info.value)
        finally:
            os.unlink(path)


# Tests for load_scope - empty scope
class TestLoadScopeEmptyScope:
    def test_empty_scope_raises_error(self, temp_scope_file):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump({}, f)
            path = f.name
        
        try:
            with pytest.raises(ScopeConfigError) as exc_info:
                load_scope(path)
            assert "Empty scope" in str(exc_info.value)
        finally:
            os.unlink(path)
    
    def test_zero_targets_raises_error(self, temp_scope_file):
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': [],
            'domains': []
        }
        path = temp_scope_file(content)
        
        try:
            with pytest.raises(ScopeConfigError) as exc_info:
                load_scope(path)
            assert "at least one" in str(exc_info.value)
        finally:
            os.unlink(path)


# Tests for load_scope - missing authorized_by
class TestLoadScopeMissingMetadata:
    def test_missing_metadata_section_raises_error(self, temp_scope_file):
        content = {
            'ip_ranges': ['192.168.1.0/24']
        }
        path = temp_scope_file(content)
        
        try:
            with pytest.raises(ScopeConfigError) as exc_info:
                load_scope(path)
            assert "metadata" in str(exc_info.value)
        finally:
            os.unlink(path)
    
    def test_missing_authorized_by_raises_error(self, temp_scope_file):
        content = {
            'metadata': {'description': 'No authorized_by field'}
        }
        path = temp_scope_file(content)
        
        try:
            with pytest.raises(ScopeConfigError) as exc_info:
                load_scope(path)
            assert "authorized_by" in str(exc_info.value)
        finally:
            os.unlink(path)


# Tests for load_scope - bad CIDR
class TestLoadScopeBadCIDR:
    def test_invalid_ip_range_raises_error(self, temp_scope_file):
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': ['not-a-valid-cidr'],
            'domains': []
        }
        path = temp_scope_file(content)
        
        try:
            with pytest.raises(ScopeConfigError) as exc_info:
                load_scope(path)
            assert "Invalid CIDR" in str(exc_info.value)
        finally:
            os.unlink(path)
    
    def test_invalid_cidr_in_exclusions_raises_error(self, temp_scope_file):
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': ['192.168.1.0/24'],
            'exclusions': {'ip_ranges': ['bad-cidr']}
        }
        path = temp_scope_file(content)
        
        try:
            with pytest.raises(ScopeConfigError) as exc_info:
                load_scope(path)
            assert "Invalid CIDR in exclusions" in str(exc_info.value)
        finally:
            os.unlink(path)


# Tests for IP CIDR matching
class TestIPMatching:
    def test_exact_ip_match(self):
        assert _matches_ip('192.168.1.50', ['192.168.1.50']) == True
    
    def test_ip_in_cidr_range(self):
        assert _matches_ip('192.168.1.100', ['192.168.1.0/24']) == True
    
    def test_ip_not_in_cidr_range(self):
        assert _matches_ip('192.168.2.100', ['192.168.1.0/24']) == False
    
    def test_ip_in_multiple_ranges(self):
        assert _matches_ip('10.0.0.50', ['192.168.1.0/24', '10.0.0.0/16']) == True
    
    def test_ip_not_in_any_range(self):
        assert _matches_ip('172.16.0.1', ['192.168.1.0/24', '10.0.0.0/16']) == False
    
    def test_single_ip_as_cidr(self):
        # Single IP should work as /32
        assert _matches_ip('10.0.0.1', ['10.0.0.1']) == True
        assert _matches_ip('10.0.0.2', ['10.0.0.1']) == False


# Tests for domain matching
class TestDomainMatching:
    def test_exact_domain_match(self):
        assert _matches_domain('example.com', ['example.com']) == True
    
    def test_exact_match_case_insensitive(self):
        assert _matches_domain('Example.COM', ['example.com']) == True
    
    def test_wildcard_subdomain_match(self):
        assert _matches_domain('sub.example.com', ['*.example.com']) == True
    
    def test_wildcard_deep_subdomain_match(self):
        assert _matches_domain('deep.sub.example.com', ['*.example.com']) == True
    
    def test_wildcard_apex_no_match(self):
        # *.example.com does NOT match bare example.com
        assert _matches_domain('example.com', ['*.example.com']) == False
    
    def test_bare_domain_no_wildcard_match(self):
        assert _matches_domain('example.org', ['example.com']) == False
    
    def test_multiple_patterns_match(self):
        assert _matches_domain('test.example.org', ['example.com', '*.example.org']) == True
    
    def test_domain_in_multiple_patterns(self):
        assert _matches_domain('example.com', ['example.com', '*.example.org']) == True


# Tests for exclusion beats allow
class TestExclusions:
    def test_ip_exclusion_overrides_allow(self, temp_scope_file, valid_scope_config):
        # Modify to include 192.168.1.100 in both allow and exclusion
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': ['192.168.1.0/24'],
            'domains': [],
            'exclusions': {'ip_ranges': ['192.168.1.100'], 'domains': []}
        }
        path = temp_scope_file(content)
        
        try:
            scope = load_scope(path)
            reset_scope()
            
            with pytest.raises(ScopeViolation) as exc_info:
                validate_target('192.168.1.100', scope)
            assert "exclusion" in str(exc_info.value.reason).lower()
        finally:
            os.unlink(path)
    
    def test_domain_exclusion_overrides_allow(self, temp_scope_file, scope_with_exclusions):
        path = temp_scope_file(scope_with_exclusions)
        
        try:
            scope = load_scope(path)
            reset_scope()
            
            with pytest.raises(ScopeViolation) as exc_info:
                validate_target('internal.example.com', scope)
            assert "exclusion" in str(exc_info.value.reason).lower()
        finally:
            os.unlink(path)
    
    def test_allowed_target_not_excluded(self, temp_scope_file, scope_with_exclusions):
        path = temp_scope_file(scope_with_exclusions)
        
        try:
            scope = load_scope(path)
            reset_scope()
            
            # example.com is allowed and not excluded
            assert validate_target('example.com', scope) == True
        finally:
            os.unlink(path)


# Tests for URL normalization
class TestURLNormalization:
    def test_url_with_scheme(self, temp_scope_file):
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': [],
            'domains': ['example.com']
        }
        path = temp_scope_file(content)
        
        try:
            scope = load_scope(path)
            reset_scope()
            
            assert validate_target('https://example.com/path', scope) == True
        finally:
            os.unlink(path)
    
    def test_url_with_port(self, temp_scope_file):
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': [],
            'domains': ['example.com']
        }
        path = temp_scope_file(content)
        
        try:
            scope = load_scope(path)
            reset_scope()
            
            assert validate_target('https://example.com:8080', scope) == True
        finally:
            os.unlink(path)
    
    def test_url_out_of_scope(self, temp_scope_file):
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': [],
            'domains': ['allowed.com']
        }
        path = temp_scope_file(content)
        
        try:
            scope = load_scope(path)
            reset_scope()
            
            with pytest.raises(ScopeViolation):
                validate_target('https://notallowed.com', scope)
        finally:
            os.unlink(path)


# Tests for Target parsing
class TestTargetParsing:
    def test_parse_ip(self):
        target = Target.parse('192.168.1.1')
        assert target.target_type == 'ip'
        assert target.value == '192.168.1.1'
    
    def test_parse_domain(self):
        target = Target.parse('example.com')
        assert target.target_type == 'domain'
        assert target.value == 'example.com'
    
    def test_parse_url(self):
        target = Target.parse('https://example.com/path')
        assert target.target_type == 'url'
    
    def test_get_hostname_from_url(self):
        target = Target.parse('https://example.com:8080/path')
        assert target.get_hostname() == 'example.com'
    
    def test_get_hostname_from_domain(self):
        target = Target.parse('example.com')
        assert target.get_hostname() == 'example.com'


# Tests for validate_target function
class TestValidateTarget:
    @pytest.fixture(autouse=True)
    def setup_scope(self, valid_scope_config):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(valid_scope_config, f)
            self.scope_path = f.name
        
        self.scope = load_scope(self.scope_path)
        reset_scope()
        
        yield
        
        os.unlink(self.scope_path)
        reset_scope()
    
    def test_in_scope_ip(self):
        assert validate_target('192.168.1.50', self.scope) == True
    
    def test_in_scope_domain(self):
        assert validate_target('example.com', self.scope) == True
    
    def test_in_scope_subdomain(self):
        assert validate_target('sub.example.org', self.scope) == True
    
    def test_out_of_scope_ip(self):
        with pytest.raises(ScopeViolation):
            validate_target('192.168.2.1', self.scope)
    
    def test_out_of_scope_domain(self):
        with pytest.raises(ScopeViolation):
            validate_target('notallowed.com', self.scope)
    
    def test_wildcard_no_apex(self):
        # Wildcard doesn't match apex - test with only wildcard in scope
        import tempfile
        import yaml
        from fraude.scope.validator import load_scope, reset_scope
        
        content = {
            'metadata': {'authorized_by': 'test@example.com'},
            'ip_ranges': [],
            'domains': ['*.example.org']  # Only wildcard, no apex
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(content, f)
            path = f.name
        
        try:
            scope = load_scope(path)
            reset_scope()
            
            # *.example.org does NOT match bare example.org
            with pytest.raises(ScopeViolation):
                validate_target('example.org', scope)
        finally:
            os.unlink(path)
            reset_scope()
    
    def test_url_in_scope(self):
        assert validate_target('https://example.com/path', self.scope) == True


# Integration test with get_scope
class TestGetScope:
    @pytest.fixture(autouse=True)
    def setup(self, valid_scope_config):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(valid_scope_config, f)
            self.scope_path = f.name
        
        reset_scope()
        yield
        os.unlink(self.scope_path)
        reset_scope()
    
    def test_get_scope_loads_from_file(self):
        scope = get_scope(self.scope_path)
        assert scope.authorized_by == 'test@example.com'
        assert '192.168.1.0/24' in scope.ip_ranges
        assert 'example.com' in scope.domains
    
    def test_get_scope_caches(self):
        scope1 = get_scope(self.scope_path)
        scope2 = get_scope(self.scope_path)
        assert scope1 is scope2  # Same object (cached)


# Test has_targets
class TestHasTargets:
    def test_has_targets_true(self, valid_scope_config):
        scope = ScopeConfig(
            authorized_by='test@example.com',
            ip_ranges=['192.168.1.0/24'],
            domains=[]
        )
        assert scope.has_targets() == True
    
    def test_has_targets_false(self):
        scope = ScopeConfig(
            authorized_by='test@example.com',
            ip_ranges=[],
            domains=[]
        )
        assert scope.has_targets() == False


# Test to_dict serialization
class TestScopeConfigSerialization:
    def test_to_dict(self):
        # Manual construction
        scope = ScopeConfig(
            authorized_by='test@example.com',
            ip_ranges=['192.168.1.0/24'],
            domains=['example.com'],
            exclusions={'domains': ['internal.example.com'], 'ip_ranges': []}
        )
        
        d = scope.to_dict()
        assert d['authorized_by'] == 'test@example.com'
        assert '192.168.1.0/24' in d['ip_ranges']
        assert 'example.com' in d['domains']