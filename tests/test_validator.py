"""Tests for the policy validator module."""

import pytest

from socket_firewall_configurator.validator import PolicyValidator


@pytest.fixture
def validator():
    """Create a validator instance."""
    return PolicyValidator()


class TestPolicyValidator:
    """Test cases for PolicyValidator."""

    def test_valid_org_policy(self, validator):
        """Test validation of valid org policy."""
        policies = {
            "org": {
                "name": "Test Org",
                "defaultIssueRules": {
                    "knownMalware": "error",
                    "criticalCVE": "error",
                },
                "bannedPackages": [
                    {"name": "bad-pkg", "reason": "Known bad"}
                ]
            },
            "repositories": {}
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        assert is_valid
        assert len(errors) == 0

    def test_valid_repo_policy(self, validator):
        """Test validation of valid repo policy."""
        policies = {
            "org": {},
            "repositories": {
                "my-repo": {
                    "version": 2,
                    "enabled": True,
                    "issueRules": {
                        "deprecated": "ignore"
                    },
                    "deferredPackageRules": [
                        {"name": "express", "reason": "Core framework"}
                    ]
                }
            }
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        assert is_valid

    def test_invalid_action(self, validator):
        """Test validation fails for invalid action."""
        policies = {
            "org": {
                "defaultIssueRules": {
                    "knownMalware": "block"  # Invalid - should be "error"
                }
            },
            "repositories": {}
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        assert not is_valid
        assert any("Invalid action" in e for e in errors)

    def test_invalid_enabled_type(self, validator):
        """Test validation fails for non-boolean enabled."""
        policies = {
            "org": {},
            "repositories": {
                "my-repo": {
                    "enabled": "yes"  # Should be boolean
                }
            }
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        assert not is_valid
        assert any("enabled" in e and "boolean" in e for e in errors)

    def test_missing_package_name(self, validator):
        """Test validation fails for package rule without name."""
        policies = {
            "org": {
                "bannedPackages": [
                    {"reason": "Some reason"}  # Missing name
                ]
            },
            "repositories": {}
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        assert not is_valid
        assert any("name" in e for e in errors)

    def test_invalid_expires_format(self, validator):
        """Test validation fails for invalid expires date."""
        policies = {
            "org": {},
            "repositories": {
                "my-repo": {
                    "deferredPackageRules": [
                        {
                            "name": "temp-pkg",
                            "reason": "Temporary",
                            "expires": "June 1st, 2025"  # Invalid format
                        }
                    ]
                }
            }
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        assert not is_valid
        assert any("expires" in e for e in errors)

    def test_valid_expires_format(self, validator):
        """Test validation passes for valid expires date."""
        policies = {
            "org": {},
            "repositories": {
                "my-repo": {
                    "deferredPackageRules": [
                        {
                            "name": "temp-pkg",
                            "reason": "Temporary",
                            "expires": "2025-06-01"
                        }
                    ]
                }
            }
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        assert is_valid

    def test_warning_ignoring_critical_issues(self, validator):
        """Test warning when ignoring critical issues."""
        policies = {
            "org": {
                "defaultIssueRules": {
                    "knownMalware": "ignore"  # Bad idea!
                }
            },
            "repositories": {}
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        # Should pass but with warnings
        assert is_valid
        # Warning should be in validator.warnings
        assert any("critical" in w.lower() for w in validator.warnings)

    def test_warning_missing_reason(self, validator):
        """Test warning when package rule has no reason."""
        policies = {
            "org": {},
            "repositories": {
                "my-repo": {
                    "deferredPackageRules": [
                        {"name": "some-pkg"}  # No reason
                    ]
                }
            }
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        # Should pass but with warning
        assert is_valid
        assert any("no reason" in w.lower() for w in validator.warnings)

    def test_unknown_issue_type_warning(self, validator):
        """Test warning for unknown issue types."""
        policies = {
            "org": {
                "defaultIssueRules": {
                    "futureIssueType": "error"  # Unknown type
                }
            },
            "repositories": {}
        }
        
        is_valid, errors = validator.validate_all(policies)
        
        # Should pass (might be a new Socket feature)
        assert is_valid
        assert any("unknown issue type" in w.lower() for w in validator.warnings)

    def test_validate_socket_yml(self, validator):
        """Test validating socket.yml content."""
        content = {
            "version": 2,
            "enabled": True,
            "issueRules": {
                "knownMalware": "error",
                "deprecated": "warn"
            },
            "deferredPackageRules": [
                {"name": "express", "reason": "Core", "action": "ignore"}
            ]
        }
        
        is_valid, errors = validator.validate_socket_yml(content)
        
        assert is_valid
        assert len(errors) == 0

    def test_validate_socket_yml_invalid_version(self, validator):
        """Test validation fails for invalid version."""
        content = {
            "version": 99,
            "enabled": True
        }
        
        is_valid, errors = validator.validate_socket_yml(content)
        
        assert not is_valid
        assert any("version" in e for e in errors)
