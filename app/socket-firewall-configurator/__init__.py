"""
Socket Firewall Configurator

Centralized configuration management for Socket dependency security policies.
Defines accept/reject rules for packages based on Socket's security analysis.
"""

__version__ = "1.0.0"
__author__ = "Infrastructure Team"

from .policy import IssuePolicy, OrgPolicy, PackageRule, SocketPolicy
from .configurator import SocketConfigurator
from .validator import PolicyValidator

__all__ = [
    "IssuePolicy",
    "OrgPolicy", 
    "PackageRule",
    "SocketPolicy",
    "SocketConfigurator",
    "PolicyValidator",
]
