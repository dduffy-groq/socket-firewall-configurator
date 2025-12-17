"""Tests for the Socket configurator module."""

import tempfile
from pathlib import Path

import pytest
import yaml

from socket_firewall_configurator.configurator import SocketConfigurator, load_policies


@pytest.fixture
def temp_policy_dir():
    """Create a temporary policy directory with test policies."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_dir = Path(tmpdir)
        repos_dir = policy_dir / "repositories"
        repos_dir.mkdir()
        
        # Create org defaults
        org_policy = {
            "name": "Test Org",
            "defaultIssueRules": {
                "knownMalware": "error",
                "criticalCVE": "error",
                "deprecated": "warn",
            },
            "bannedPackages": [
                {"name": "bad-pkg", "reason": "Known malicious"}
            ],
            "defaultIgnorePaths": ["**/test/**"]
        }
        
        with open(policy_dir / "org-defaults.yml", "w") as f:
            yaml.dump(org_policy, f)
        
        # Create repo-specific policy
        repo_policy = {
            "version": 2,
            "enabled": True,
            "projectName": "api-gateway",
            "issueRules": {
                "deprecated": "error",  # Override org default
            },
            "deferredPackageRules": [
                {"name": "express", "action": "ignore", "reason": "Core framework"}
            ]
        }
        
        with open(repos_dir / "api-gateway.yml", "w") as f:
            yaml.dump(repo_policy, f)
        
        yield policy_dir


class TestLoadPolicies:
    """Test cases for load_policies function."""

    def test_load_org_policy(self, temp_policy_dir):
        """Test loading org policy."""
        policies = load_policies(temp_policy_dir)
        
        assert "org" in policies
        assert policies["org"]["name"] == "Test Org"

    def test_load_repo_policies(self, temp_policy_dir):
        """Test loading repository policies."""
        policies = load_policies(temp_policy_dir)
        
        assert "repositories" in policies
        assert "api-gateway" in policies["repositories"]

    def test_load_empty_dir(self):
        """Test loading from empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policies = load_policies(Path(tmpdir))
            
            assert policies["org"] == {}
            assert policies["repositories"] == {}


class TestSocketConfigurator:
    """Test cases for SocketConfigurator."""

    def test_generate_for_repo_with_policy(self, temp_policy_dir):
        """Test generating config for repo with custom policy."""
        configurator = SocketConfigurator(temp_policy_dir)
        configs = configurator.generate_socket_yml("api-gateway")
        
        assert "api-gateway" in configs
        
        config = yaml.safe_load(configs["api-gateway"])
        assert config["projectName"] == "api-gateway"
        assert config["enabled"] is True

    def test_merge_org_and_repo_policies(self, temp_policy_dir):
        """Test that org and repo policies are merged."""
        configurator = SocketConfigurator(temp_policy_dir)
        configs = configurator.generate_socket_yml("api-gateway")
        
        config = yaml.safe_load(configs["api-gateway"])
        
        # Should have org default for malware
        assert config["issueRules"]["knownMalware"] == "error"
        
        # Should have repo override for deprecated
        assert config["issueRules"]["deprecated"] == "error"

    def test_generate_for_repo_without_policy(self, temp_policy_dir):
        """Test generating config for repo without custom policy."""
        configurator = SocketConfigurator(temp_policy_dir)
        configs = configurator.generate_socket_yml("unknown-repo")
        
        assert "unknown-repo" in configs
        
        config = yaml.safe_load(configs["unknown-repo"])
        
        # Should use org defaults
        assert config["issueRules"]["knownMalware"] == "error"
        assert config["issueRules"]["deprecated"] == "warn"

    def test_generate_all_repos(self, temp_policy_dir):
        """Test generating configs for all repos with policies."""
        configurator = SocketConfigurator(temp_policy_dir)
        configs = configurator.generate_socket_yml()
        
        # Should generate for repos with custom policies
        assert "api-gateway" in configs

    def test_banned_packages_included(self, temp_policy_dir):
        """Test that banned packages are included in output."""
        configurator = SocketConfigurator(temp_policy_dir)
        configs = configurator.generate_socket_yml("api-gateway")
        
        config = yaml.safe_load(configs["api-gateway"])
        
        # Find the banned package rule
        package_names = [r["name"] for r in config.get("deferredPackageRules", [])]
        assert "bad-pkg" in package_names

    def test_ignore_paths_merged(self, temp_policy_dir):
        """Test that ignore paths from org are included."""
        configurator = SocketConfigurator(temp_policy_dir)
        configs = configurator.generate_socket_yml("api-gateway")
        
        config = yaml.safe_load(configs["api-gateway"])
        
        assert "**/test/**" in config.get("ignore", [])

