#!/usr/bin/env python3
"""
Socket Policy Models

Defines data structures for Socket security policies including:
- Issue severity policies (what to warn/error/ignore)
- Package allow/deny rules
- Organization defaults
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(Enum):
    """Action to take when Socket detects an issue."""
    ERROR = "error"      # Fail the check, block the dependency
    WARN = "warn"        # Allow but warn
    IGNORE = "ignore"    # Silently allow
    DEFER = "defer"      # Defer to org/default settings


class IssueType(Enum):
    """Socket issue types for dependency analysis."""
    # Supply Chain Risks
    CRITICAL_CVE = "criticalCVE"
    HIGH_CVE = "highCVE"
    MEDIUM_CVE = "mediumCVE"
    LOW_CVE = "lowCVE"
    KNOWN_MALWARE = "knownMalware"
    PROTESTWARE = "protestware"
    HIGH_ENTROPY_STRINGS = "highEntropyStrings"
    POTENTIAL_TYPOSQUAT = "potentialTyposquat"
    INSTALL_SCRIPTS = "installScripts"
    
    # Quality Issues
    DEPRECATED = "deprecated"
    UNMAINTAINED = "unmaintained"
    NO_LICENSE = "noLicense"
    COPYLEFT_LICENSE = "copyleftLicense"
    NON_OSS_LICENSE = "nonOssLicense"
    UNSTABLE_OWNERSHIP = "unstableOwnership"
    
    # Behavior Risks
    NETWORK_ACCESS = "networkAccess"
    FILESYSTEM_ACCESS = "filesystemAccess"
    SHELL_ACCESS = "shellAccess"
    ENVIRONMENT_ACCESS = "environmentAccess"
    NATIVE_CODE = "nativeCode"
    OBFUSCATED_CODE = "obfuscatedCode"
    MINIFIED_CODE = "minifiedCode"
    
    # Dependency Issues
    TRIVIAL_PACKAGE = "trivialPackage"
    FLOATING_DEPENDENCY = "floatingDependency"
    UNPOPULAR_PACKAGE = "unpopularPackage"
    NEW_AUTHOR = "newAuthor"


@dataclass
class IssuePolicy:
    """Policy for a specific issue type."""
    issue_type: IssueType
    action: Action = Action.DEFER
    
    def to_dict(self) -> dict[str, str]:
        """Convert to Socket config format."""
        return {self.issue_type.value: self.action.value}
    
    @classmethod
    def from_dict(cls, issue_type: str, action: str) -> "IssuePolicy":
        """Create from config dict."""
        return cls(
            issue_type=IssueType(issue_type),
            action=Action(action)
        )


@dataclass
class PackageRule:
    """Rule for a specific package (allow/deny)."""
    name: str
    version: str = "*"          # Version constraint or "*" for all
    action: Action = Action.IGNORE  # Usually IGNORE (allow) or ERROR (deny)
    reason: str = ""            # Why this rule exists
    expires: str | None = None  # Optional expiration date
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to Socket config format."""
        rule = {
            "name": self.name,
            "version": self.version,
            "action": self.action.value,
        }
        if self.reason:
            rule["reason"] = self.reason
        if self.expires:
            rule["expires"] = self.expires
        return rule
    
    @classmethod
    def from_dict(cls, data: dict) -> "PackageRule":
        """Create from config dict."""
        return cls(
            name=data["name"],
            version=data.get("version", "*"),
            action=Action(data.get("action", "ignore")),
            reason=data.get("reason", ""),
            expires=data.get("expires"),
        )


@dataclass
class SocketPolicy:
    """Complete Socket policy configuration."""
    version: int = 2
    enabled: bool = True
    
    # Issue-level policies
    issue_rules: dict[IssueType, Action] = field(default_factory=dict)
    
    # Package-level allow/deny rules
    package_rules: list[PackageRule] = field(default_factory=list)
    
    # Ignored paths (don't scan these)
    ignore_paths: list[str] = field(default_factory=list)
    
    # Project metadata
    project_name: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to socket.yml format."""
        config: dict[str, Any] = {
            "version": self.version,
            "enabled": self.enabled,
        }
        
        if self.project_name:
            config["projectName"] = self.project_name
        
        # Issue rules
        if self.issue_rules:
            config["issueRules"] = {
                issue.value: action.value
                for issue, action in self.issue_rules.items()
            }
        
        # Package rules (deferredPackageRules in Socket format)
        if self.package_rules:
            config["deferredPackageRules"] = [
                rule.to_dict() for rule in self.package_rules
            ]
        
        # Ignore paths
        if self.ignore_paths:
            config["ignore"] = self.ignore_paths
        
        return config
    
    @classmethod
    def from_dict(cls, data: dict) -> "SocketPolicy":
        """Create from config dict."""
        policy = cls(
            version=data.get("version", 2),
            enabled=data.get("enabled", True),
            project_name=data.get("projectName", ""),
        )
        
        # Parse issue rules
        for issue_type, action in data.get("issueRules", {}).items():
            try:
                policy.issue_rules[IssueType(issue_type)] = Action(action)
            except ValueError:
                pass  # Skip unknown issue types
        
        # Parse package rules
        for rule_data in data.get("deferredPackageRules", []):
            policy.package_rules.append(PackageRule.from_dict(rule_data))
        
        # Also support legacy "packageRules" key
        for rule_data in data.get("packageRules", []):
            policy.package_rules.append(PackageRule.from_dict(rule_data))
        
        # Parse ignore paths
        policy.ignore_paths = data.get("ignore", [])
        
        return policy
    
    def merge(self, other: "SocketPolicy") -> "SocketPolicy":
        """Merge another policy into this one (other takes precedence)."""
        merged = SocketPolicy(
            version=max(self.version, other.version),
            enabled=other.enabled if other.enabled is not None else self.enabled,
            project_name=other.project_name or self.project_name,
        )
        
        # Merge issue rules (other overrides self)
        merged.issue_rules = {**self.issue_rules, **other.issue_rules}
        
        # Merge package rules (append, with other taking precedence)
        seen_packages = set()
        merged.package_rules = []
        
        for rule in other.package_rules:
            key = (rule.name, rule.version)
            seen_packages.add(key)
            merged.package_rules.append(rule)
        
        for rule in self.package_rules:
            key = (rule.name, rule.version)
            if key not in seen_packages:
                merged.package_rules.append(rule)
        
        # Merge ignore paths (union)
        merged.ignore_paths = list(set(self.ignore_paths) | set(other.ignore_paths))
        
        return merged


@dataclass
class OrgPolicy:
    """Organization-wide default policy."""
    name: str = "Organization Default"
    description: str = ""
    
    # Default issue rules for all repos
    default_issue_rules: dict[IssueType, Action] = field(default_factory=dict)
    
    # Organization-wide banned packages
    banned_packages: list[PackageRule] = field(default_factory=list)
    
    # Organization-wide allowed packages (exceptions)
    allowed_packages: list[PackageRule] = field(default_factory=list)
    
    # Default ignore paths
    default_ignore_paths: list[str] = field(default_factory=list)
    
    def to_socket_policy(self) -> SocketPolicy:
        """Convert to a SocketPolicy for merging."""
        return SocketPolicy(
            issue_rules=self.default_issue_rules.copy(),
            package_rules=self.banned_packages + self.allowed_packages,
            ignore_paths=self.default_ignore_paths.copy(),
        )
    
    @classmethod
    def from_dict(cls, data: dict) -> "OrgPolicy":
        """Create from config dict."""
        policy = cls(
            name=data.get("name", "Organization Default"),
            description=data.get("description", ""),
        )
        
        # Parse default issue rules
        for issue_type, action in data.get("defaultIssueRules", {}).items():
            try:
                policy.default_issue_rules[IssueType(issue_type)] = Action(action)
            except ValueError:
                pass
        
        # Parse banned packages
        for rule_data in data.get("bannedPackages", []):
            rule = PackageRule.from_dict(rule_data)
            rule.action = Action.ERROR  # Force error for banned
            policy.banned_packages.append(rule)
        
        # Parse allowed packages
        for rule_data in data.get("allowedPackages", []):
            rule = PackageRule.from_dict(rule_data)
            rule.action = Action.IGNORE  # Force ignore for allowed
            policy.allowed_packages.append(rule)
        
        # Parse default ignore paths
        policy.default_ignore_paths = data.get("defaultIgnorePaths", [])
        
        return policy
