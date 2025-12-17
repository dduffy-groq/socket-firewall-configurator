#!/usr/bin/env python3
"""
Socket Firewall Configurator

Main application for managing and distributing Socket security policies
across repositories.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

from .policy import OrgPolicy, SocketPolicy
from .validator import PolicyValidator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class SocketConfigurator:
    """Manages Socket security configuration generation and distribution."""
    
    def __init__(self, policy_dir: Path):
        """Initialize the configurator."""
        self.policy_dir = policy_dir
        self.org_policy = self._load_org_policy()
        self.repo_policies = self._load_repo_policies()
    
    def _load_org_policy(self) -> OrgPolicy:
        """Load organization-wide default policy."""
        org_file = self.policy_dir / "org-defaults.yml"
        
        if org_file.exists():
            with open(org_file) as f:
                data = yaml.safe_load(f) or {}
            return OrgPolicy.from_dict(data)
        
        return OrgPolicy()
    
    def _load_repo_policies(self) -> dict[str, SocketPolicy]:
        """Load repository-specific policies."""
        policies = {}
        repos_dir = self.policy_dir / "repositories"
        
        if repos_dir.exists():
            for policy_file in repos_dir.glob("*.yml"):
                repo_name = policy_file.stem
                with open(policy_file) as f:
                    data = yaml.safe_load(f) or {}
                policies[repo_name] = SocketPolicy.from_dict(data)
        
        return policies
    
    def generate_socket_yml(self, repo_name: str | None = None) -> dict[str, str]:
        """
        Generate socket.yml configurations.
        
        Returns a dict of repo_name -> socket.yml content.
        """
        configs = {}
        
        if repo_name:
            # Generate for specific repo
            if repo_name in self.repo_policies:
                policy = self._merge_policies(repo_name)
                configs[repo_name] = self._render_socket_yml(policy)
            else:
                # Use org defaults
                configs[repo_name] = self._render_socket_yml(
                    self.org_policy.to_socket_policy()
                )
        else:
            # Generate for all repos with custom policies
            for name in self.repo_policies:
                policy = self._merge_policies(name)
                configs[name] = self._render_socket_yml(policy)
        
        return configs
    
    def _merge_policies(self, repo_name: str) -> SocketPolicy:
        """Merge org defaults with repo-specific overrides."""
        base = self.org_policy.to_socket_policy()
        repo_policy = self.repo_policies.get(repo_name)
        
        if not repo_policy:
            return base
        
        return base.merge(repo_policy)
    
    def _render_socket_yml(self, policy: SocketPolicy) -> str:
        """Render a SocketPolicy to socket.yml format."""
        return yaml.dump(
            policy.to_dict(),
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True
        )


def load_policies(policy_dir: Path) -> dict[str, Any]:
    """Load all policy files from the policy directory."""
    policies = {
        "org": {},
        "repositories": {},
    }
    
    # Load org defaults
    org_file = policy_dir / "org-defaults.yml"
    if org_file.exists():
        with open(org_file) as f:
            policies["org"] = yaml.safe_load(f) or {}
    
    # Load repository-specific policies
    repos_dir = policy_dir / "repositories"
    if repos_dir.exists():
        for policy_file in repos_dir.glob("*.yml"):
            repo_name = policy_file.stem
            with open(policy_file) as f:
                policies["repositories"][repo_name] = yaml.safe_load(f) or {}
    
    return policies


def main() -> int:
    """Main entry point for the Socket configurator."""
    parser = argparse.ArgumentParser(
        description="Generate and distribute Socket security configurations"
    )
    parser.add_argument(
        "--policy-dir",
        type=Path,
        default=Path("policies"),
        help="Directory containing policy definitions (default: policies/)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory for generated socket.yml files (default: output/)"
    )
    parser.add_argument(
        "--repo",
        "-r",
        default=None,
        help="Generate configuration for a specific repository only"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print configurations without writing to disk"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate policy definitions"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    policy_dir = args.policy_dir.resolve()
    
    if not policy_dir.exists():
        logger.error(f"Policy directory does not exist: {policy_dir}")
        return 1
    
    logger.info(f"Loading policies from: {policy_dir}")
    
    # Load and validate policies
    policies = load_policies(policy_dir)
    logger.info(f"Loaded {len(policies['repositories'])} repository policies")
    
    validator = PolicyValidator()
    is_valid, errors = validator.validate_all(policies)
    
    if not is_valid:
        logger.error("Policy validation failed:")
        for error in errors:
            logger.error(f"  - {error}")
        return 1
    
    logger.info("Policy validation passed")
    
    if args.validate_only:
        return 0
    
    # Generate configurations
    configurator = SocketConfigurator(policy_dir)
    configs = configurator.generate_socket_yml(args.repo)
    
    if not configs:
        logger.info("No configurations to generate")
        return 0
    
    # Output configurations
    for repo_name, config in configs.items():
        if args.dry_run:
            print(f"\n--- {repo_name}/socket.yml ---")
            print(config)
        else:
            output_dir = args.output_dir / repo_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            output_file = output_dir / "socket.yml"
            with open(output_file, "w") as f:
                f.write(config)
            
            logger.info(f"Written: {output_file}")
    
    if not args.dry_run:
        logger.info(f"Configurations written to: {args.output_dir}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
