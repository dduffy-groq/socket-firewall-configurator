# Socket Firewall Configurator

Centralized configuration management for [Socket](https://socket.dev) dependency security policies across repositories.

Inspired by [dependabot-configurator](https://github.com/redcanaryco/dependabot-configurator), this tool provides a single source of truth for Socket security configurations that can be distributed to all your repositories.

## What is Socket?

[Socket](https://socket.dev) is a dependency security service that analyzes packages before they're installed, detecting:
- 🔴 **Malware** - Known malicious packages
- 🟠 **Supply chain attacks** - Typosquats, protestware, compromised packages
- 🟡 **Vulnerabilities** - CVEs at all severity levels
- 🔵 **Quality issues** - Unmaintained, deprecated, or risky packages

Socket acts as a "firewall" for your dependencies, checking each package against their cloud service before allowing installation.

## Features

- **Centralized Policies**: Define organization-wide security rules in one place
- **Per-Repository Overrides**: Customize policies for specific repos
- **Package Allow/Deny Lists**: Organization-wide banned packages and exceptions
- **Issue Severity Control**: Configure which issues block vs warn vs ignore
- **Expiring Exceptions**: Temporary allowances with automatic expiration
- **GitHub Integration**: Automated workflows to distribute configurations

## Quick Start

### 1. Define Organization Defaults

Create `policies/org-defaults.yml` with your baseline security policy:

```yaml
name: "Organization Security Policy"

defaultIssueRules:
  knownMalware: error      # Always block malware
  criticalCVE: error       # Block critical CVEs
  highCVE: error           # Block high CVEs
  mediumCVE: warn          # Warn on medium CVEs
  deprecated: warn         # Warn on deprecated packages

bannedPackages:
  - name: "event-stream"
    version: "3.3.6"
    reason: "Contained malicious code"
```

### 2. Add Repository-Specific Policies (Optional)

Create `policies/repositories/<repo-name>.yml` for per-repo overrides:

```yaml
version: 2
enabled: true
projectName: "api-gateway"

issueRules:
  # Stricter for external-facing service
  mediumCVE: error
  installScripts: error

deferredPackageRules:
  - name: "express"
    version: "*"
    action: ignore
    reason: "Core framework"
```

### 3. Generate Configurations

```bash
# Validate all policies
python -m socket_firewall_configurator.configurator --validate-only

# Generate socket.yml for all repos
python -m socket_firewall_configurator.configurator \
    --policy-dir policies/ \
    --output-dir output/

# Generate for a specific repo
python -m socket_firewall_configurator.configurator \
    --repo api-gateway \
    --dry-run
```

### 4. Distribute to Repositories

Copy the generated `socket.yml` files to each repository's root, or use the GitHub workflow for automated distribution.

## Policy Structure

```
policies/
├── org-defaults.yml           # Organization-wide defaults
└── repositories/
    ├── api-gateway.yml        # High-security external service
    ├── internal-tool.yml      # Relaxed internal tooling
    └── ml-pipeline.yml        # ML-specific exceptions
```

## Configuration Reference

### Issue Types

Socket detects many issue types. Configure how to handle each:

| Issue | Description | Recommended |
|-------|-------------|-------------|
| `knownMalware` | Known malicious package | `error` |
| `criticalCVE` | Critical severity CVE | `error` |
| `highCVE` | High severity CVE | `error` |
| `protestware` | Protest/sabotage code | `error` |
| `potentialTyposquat` | Name similar to popular package | `error` |
| `mediumCVE` | Medium severity CVE | `warn` |
| `lowCVE` | Low severity CVE | `warn` |
| `deprecated` | Package marked deprecated | `warn` |
| `unmaintained` | No recent updates | `warn` |
| `installScripts` | Has install/postinstall scripts | `warn` |
| `shellAccess` | Can spawn shell commands | `warn` |
| `networkAccess` | Has network capabilities | `warn` |
| `obfuscatedCode` | Contains obfuscated code | `warn` |
| `nativeCode` | Has native/binary code | `ignore` |
| `filesystemAccess` | Accesses filesystem | `ignore` |
| `minifiedCode` | Contains minified code | `ignore` |

### Actions

| Action | Effect |
|--------|--------|
| `error` | Block the dependency, fail CI |
| `warn` | Allow but show warning |
| `ignore` | Silently allow |
| `defer` | Use organization default |

### Package Rules

```yaml
deferredPackageRules:
  - name: "package-name"
    version: "*"              # or "1.2.x", ">=1.0.0", etc.
    action: ignore            # or error, warn
    reason: "Why this exception exists"
    expires: "2025-06-01"     # Optional expiration
```

## GitHub Workflow

Add automated policy distribution to your organization:

```yaml
name: Distribute Socket Policies

on:
  push:
    paths:
      - 'policies/**'
  workflow_dispatch:

jobs:
  distribute:
    uses: your-org/socket-firewall-configurator/.github/workflows/socket-firewall-configurator-reusable.yml@main
    secrets:
      ORG_CONFIGURATOR_APP_ID: ${{ secrets.ORG_CONFIGURATOR_APP_ID }}
      ORG_CONFIGURATOR_APP_PRIVATE_KEY: ${{ secrets.ORG_CONFIGURATOR_APP_PRIVATE_KEY }}
```

## Example Output

Generated `socket.yml` for a repository:

```yaml
version: 2
enabled: true
projectName: api-gateway

issueRules:
  knownMalware: error
  criticalCVE: error
  highCVE: error
  mediumCVE: error
  protestware: error
  installScripts: error
  shellAccess: error

deferredPackageRules:
  - name: event-stream
    version: 3.3.6
    action: error
    reason: Contained malicious code targeting Bitcoin wallets
  - name: express
    version: "*"
    action: ignore
    reason: Core framework for API gateway

ignore:
  - "**/node_modules/**"
  - "**/test/**"
```

## Security Best Practices

1. **Never ignore malware**: Keep `knownMalware: error` in all policies
2. **Review exceptions**: Regularly audit allowed packages
3. **Use expiration dates**: Set `expires` on temporary exceptions
4. **Document reasons**: Always include `reason` for package rules
5. **Stricter for external**: Use tighter policies for public-facing services

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Validate policies
python -m socket_firewall_configurator.configurator --validate-only

# Dry run
python -m socket_firewall_configurator.configurator --dry-run
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

BSD-3-Clause. See [LICENSE](LICENSE).
