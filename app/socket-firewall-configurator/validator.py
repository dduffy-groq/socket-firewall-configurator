#!/usr/bin/env python3
"""
Policy Validator

Validates Socket security policy definitions for correctness
and organizational compliance.
"""

import logging
from datetime import datetime
from typing import Any

from .policy import Action, IssueType

logger = logging.getLogger(__name__)


class PolicyValidator:
    """Validates Socket policy definitions."""
    
    VALID_ACTIONS = ["error", "warn", "ignore", "defer"]
    
    # Issue types that should typically not be ignored
    CRITICAL_ISSUES = [
        "knownMalware",
        "criticalCVE",
        "protestware",
    ]
    
    def __init__(self):
        """Initialize the validator."""
        self.errors: list[str] = []
        self.warnings: list[str] = []
    
    def validate_all(self, policies: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validate all policies."""
        self.errors = []
        self.warnings = []
        
        # Validate org defaults
        if "org" in policies and policies["org"]:
            self._validate_org_policy(policies["org"])
        
        # Validate repository policies
        for repo_name, repo_policy in policies.get("repositories", {}).items():
            self._validate_repo_policy(repo_policy, repo_name)
        
        # Log warnings
        for warning in self.warnings:
            logger.warning(warning)
        
        return len(self.errors) == 0, self.errors
    
    def _validate_org_policy(self, policy: dict) -> None:
        """Validate organization default policy."""
        source = "org-defaults"
        
        # Validate default issue rules
        for issue_type, action in policy.get("defaultIssueRules", {}).items():
            self._validate_issue_rule(issue_type, action, source)
        
        # Validate banned packages
        for i, pkg in enumerate(policy.get("bannedPackages", [])):
            self._validate_package_rule(pkg, f"{source}:bannedPackages[{i}]")
        
        # Validate allowed packages
        for i, pkg in enumerate(policy.get("allowedPackages", [])):
            self._validate_package_rule(pkg, f"{source}:allowedPackages[{i}]")
            
            # Warn if allowing known malware
            if pkg.get("name") and "malware" in pkg.get("reason", "").lower():
                self.warnings.append(
                    f"{source}: Allowing package '{pkg['name']}' with malware in reason"
                )
    
    def _validate_repo_policy(self, policy: dict, repo_name: str) -> None:
        """Validate a repository-specific policy."""
        source = f"repository:{repo_name}"
        
        # Validate enabled flag
        if "enabled" in policy and not isinstance(policy["enabled"], bool):
            self.errors.append(f"{source}: 'enabled' must be a boolean")
        
        # Validate issue rules
        for issue_type, action in policy.get("issueRules", {}).items():
            self._validate_issue_rule(issue_type, action, source)
        
        # Validate package rules
        for i, pkg in enumerate(policy.get("packageRules", [])):
            self._validate_package_rule(pkg, f"{source}:packageRules[{i}]")
        
        for i, pkg in enumerate(policy.get("deferredPackageRules", [])):
            self._validate_package_rule(pkg, f"{source}:deferredPackageRules[{i}]")
        
        # Validate ignore paths
        for i, path in enumerate(policy.get("ignore", [])):
            if not isinstance(path, str):
                self.errors.append(f"{source}:ignore[{i}]: must be a string")
    
    def _validate_issue_rule(self, issue_type: str, action: str, source: str) -> None:
        """Validate a single issue rule."""
        # Validate action
        if action not in self.VALID_ACTIONS:
            self.errors.append(
                f"{source}: Invalid action '{action}' for issue '{issue_type}'"
            )
        
        # Validate issue type exists
        try:
            IssueType(issue_type)
        except ValueError:
            self.warnings.append(
                f"{source}: Unknown issue type '{issue_type}' - may be a new Socket feature"
            )
        
        # Warn if ignoring critical issues
        if action == "ignore" and issue_type in self.CRITICAL_ISSUES:
            self.warnings.append(
                f"{source}: Ignoring critical issue type '{issue_type}' is not recommended"
            )
    
    def _validate_package_rule(self, rule: dict, source: str) -> None:
        """Validate a package rule."""
        # Required: name
        if not rule.get("name"):
            self.errors.append(f"{source}: Missing required field 'name'")
        
        # Validate action if present
        action = rule.get("action")
        if action and action not in self.VALID_ACTIONS:
            self.errors.append(f"{source}: Invalid action '{action}'")
        
        # Validate version format (basic check)
        version = rule.get("version", "*")
        if not isinstance(version, str):
            self.errors.append(f"{source}: 'version' must be a string")
        
        # Validate expires date format if present
        expires = rule.get("expires")
        if expires:
            try:
                datetime.fromisoformat(expires.replace("Z", "+00:00"))
            except ValueError:
                self.errors.append(
                    f"{source}: Invalid 'expires' date format. Use ISO 8601 (YYYY-MM-DD)"
                )
        
        # Warn if rule has no reason
        if not rule.get("reason"):
            self.warnings.append(
                f"{source}: Package rule for '{rule.get('name', '?')}' has no reason"
            )
    
    def validate_socket_yml(self, content: dict) -> tuple[bool, list[str]]:
        """Validate a socket.yml file content."""
        self.errors = []
        self.warnings = []
        
        source = "socket.yml"
        
        # Validate version
        version = content.get("version")
        if version is not None and version not in [1, 2]:
            self.errors.append(f"{source}: Unsupported version '{version}'")
        
        # Validate enabled
        if "enabled" in content and not isinstance(content["enabled"], bool):
            self.errors.append(f"{source}: 'enabled' must be a boolean")
        
        # Validate issue rules
        for issue_type, action in content.get("issueRules", {}).items():
            self._validate_issue_rule(issue_type, action, source)
        
        # Validate package rules
        for i, pkg in enumerate(content.get("deferredPackageRules", [])):
            self._validate_package_rule(pkg, f"{source}:deferredPackageRules[{i}]")
        
        return len(self.errors) == 0, self.errors
