"""Tests for the Socket policy models."""

import pytest

from socket_firewall_configurator.policy import (
    Action,
    IssuePolicy,
    IssueType,
    OrgPolicy,
    PackageRule,
    SocketPolicy,
)


class TestIssuePolicy:
    """Test cases for IssuePolicy."""

    def test_to_dict(self):
        """Test converting to dict format."""
        policy = IssuePolicy(
            issue_type=IssueType.CRITICAL_CVE,
            action=Action.ERROR
        )
        
        result = policy.to_dict()
        
        assert result == {"criticalCVE": "error"}

    def test_from_dict(self):
        """Test creating from dict."""
        policy = IssuePolicy.from_dict("knownMalware", "error")
        
        assert policy.issue_type == IssueType.KNOWN_MALWARE
        assert policy.action == Action.ERROR


class TestPackageRule:
    """Test cases for PackageRule."""

    def test_to_dict_basic(self):
        """Test basic conversion to dict."""
        rule = PackageRule(
            name="lodash",
            version="*",
            action=Action.IGNORE,
            reason="Widely used"
        )
        
        result = rule.to_dict()
        
        assert result["name"] == "lodash"
        assert result["version"] == "*"
        assert result["action"] == "ignore"
        assert result["reason"] == "Widely used"

    def test_to_dict_with_expires(self):
        """Test conversion with expiration date."""
        rule = PackageRule(
            name="temp-package",
            action=Action.WARN,
            reason="Temporary",
            expires="2025-06-01"
        )
        
        result = rule.to_dict()
        
        assert result["expires"] == "2025-06-01"

    def test_from_dict(self):
        """Test creating from dict."""
        data = {
            "name": "express",
            "version": "4.x",
            "action": "ignore",
            "reason": "Core framework"
        }
        
        rule = PackageRule.from_dict(data)
        
        assert rule.name == "express"
        assert rule.version == "4.x"
        assert rule.action == Action.IGNORE
        assert rule.reason == "Core framework"


class TestSocketPolicy:
    """Test cases for SocketPolicy."""

    def test_to_dict_empty(self):
        """Test converting empty policy."""
        policy = SocketPolicy()
        
        result = policy.to_dict()
        
        assert result["version"] == 2
        assert result["enabled"] is True

    def test_to_dict_full(self):
        """Test converting full policy."""
        policy = SocketPolicy(
            project_name="my-app",
            issue_rules={
                IssueType.KNOWN_MALWARE: Action.ERROR,
                IssueType.DEPRECATED: Action.WARN,
            },
            package_rules=[
                PackageRule(name="lodash", action=Action.IGNORE, reason="OK")
            ],
            ignore_paths=["**/test/**"]
        )
        
        result = policy.to_dict()
        
        assert result["projectName"] == "my-app"
        assert result["issueRules"]["knownMalware"] == "error"
        assert result["issueRules"]["deprecated"] == "warn"
        assert len(result["deferredPackageRules"]) == 1
        assert result["ignore"] == ["**/test/**"]

    def test_from_dict(self):
        """Test creating from dict."""
        data = {
            "version": 2,
            "enabled": True,
            "projectName": "api-gateway",
            "issueRules": {
                "criticalCVE": "error",
                "lowCVE": "ignore"
            },
            "deferredPackageRules": [
                {"name": "express", "action": "ignore", "reason": "Core"}
            ]
        }
        
        policy = SocketPolicy.from_dict(data)
        
        assert policy.project_name == "api-gateway"
        assert policy.issue_rules[IssueType.CRITICAL_CVE] == Action.ERROR
        assert policy.issue_rules[IssueType.LOW_CVE] == Action.IGNORE
        assert len(policy.package_rules) == 1

    def test_merge_policies(self):
        """Test merging two policies."""
        base = SocketPolicy(
            issue_rules={
                IssueType.KNOWN_MALWARE: Action.ERROR,
                IssueType.DEPRECATED: Action.WARN,
            },
            package_rules=[
                PackageRule(name="lodash", action=Action.IGNORE, reason="Base")
            ],
            ignore_paths=["**/test/**"]
        )
        
        override = SocketPolicy(
            project_name="my-app",
            issue_rules={
                IssueType.DEPRECATED: Action.IGNORE,  # Override
            },
            package_rules=[
                PackageRule(name="express", action=Action.IGNORE, reason="Override")
            ],
            ignore_paths=["**/docs/**"]
        )
        
        merged = base.merge(override)
        
        # Check project name from override
        assert merged.project_name == "my-app"
        
        # Check issue rules merged (override wins)
        assert merged.issue_rules[IssueType.KNOWN_MALWARE] == Action.ERROR
        assert merged.issue_rules[IssueType.DEPRECATED] == Action.IGNORE
        
        # Check package rules (both included)
        names = [r.name for r in merged.package_rules]
        assert "lodash" in names
        assert "express" in names
        
        # Check ignore paths merged
        assert "**/test/**" in merged.ignore_paths
        assert "**/docs/**" in merged.ignore_paths


class TestOrgPolicy:
    """Test cases for OrgPolicy."""

    def test_from_dict(self):
        """Test creating from dict."""
        data = {
            "name": "Org Policy",
            "description": "Test org policy",
            "defaultIssueRules": {
                "knownMalware": "error",
                "criticalCVE": "error",
            },
            "bannedPackages": [
                {"name": "bad-pkg", "reason": "Malicious"}
            ],
            "allowedPackages": [
                {"name": "good-pkg", "reason": "Safe"}
            ],
            "defaultIgnorePaths": ["**/vendor/**"]
        }
        
        org = OrgPolicy.from_dict(data)
        
        assert org.name == "Org Policy"
        assert org.default_issue_rules[IssueType.KNOWN_MALWARE] == Action.ERROR
        assert len(org.banned_packages) == 1
        assert org.banned_packages[0].action == Action.ERROR
        assert len(org.allowed_packages) == 1
        assert org.allowed_packages[0].action == Action.IGNORE

    def test_to_socket_policy(self):
        """Test converting to SocketPolicy."""
        org = OrgPolicy(
            default_issue_rules={IssueType.KNOWN_MALWARE: Action.ERROR},
            banned_packages=[PackageRule(name="bad", action=Action.ERROR, reason="Bad")],
            default_ignore_paths=["**/test/**"]
        )
        
        policy = org.to_socket_policy()
        
        assert policy.issue_rules[IssueType.KNOWN_MALWARE] == Action.ERROR
        assert len(policy.package_rules) == 1
        assert "**/test/**" in policy.ignore_paths
