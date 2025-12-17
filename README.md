# Socket Firewall Configurator

Centralized configuration management for [Socket](https://socket.dev) dependency security policies across repositories.

Inspired by [dependabot-configurator](https://github.com/redcanaryco/dependabot-configurator), this tool provides a single source of truth for Socket security configurations.

## Free Tier Usage

This tool works **without API keys** using Socket's free tier:
- Policy-based validation via `socket.yml`
- npm audit integration
- Manual protestware/malware detection
- GitHub Actions for CI/CD integration

For full Socket features (real-time scanning, detailed reports), install the [Socket GitHub App](https://github.com/apps/socket-security).

## What is Socket?

[Socket](https://socket.dev) is a dependency security service that analyzes packages before they're installed:
- 🔴 **Malware** - Known malicious packages
- 🟠 **Supply chain attacks** - Typosquats, protestware, compromised packages
- 🟡 **Vulnerabilities** - CVEs at all severity levels
- 🔵 **Quality issues** - Unmaintained, deprecated, or risky packages

## Quick Start

### 1. Define Organization Defaults

Create `policies/org-defaults.yml`:

```yaml
name: "Organization Security Policy"

defaultIssueRules:
  knownMalware: error      # Block malware
  criticalCVE: error       # Block critical CVEs
  protestware: error       # Block protestware
  highCVE: error           # Block high CVEs
  mediumCVE: warn          # Warn on medium CVEs
  deprecated: warn         # Warn on deprecated

bannedPackages:
  - name: "event-stream"
    version: "3.3.6"
    reason: "Contained malicious code"
  - name: "colors"
    version: ">=1.4.1"
    reason: "Protestware"
```

### 2. Add Repository-Specific Policies (Optional)

Create `policies/repositories/<repo-name>.yml`:

```yaml
version: 2
enabled: true
projectName: "api-gateway"

issueRules:
  mediumCVE: error  # Stricter for this repo

deferredPackageRules:
  - name: "express"
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

# Preview for specific repo
python -m socket_firewall_configurator.configurator \
    --repo api-gateway \
    --dry-run
```

### 4. Apply to Repositories

Copy the generated `socket.yml` to each repository's root directory.

## Policy Structure

```
policies/
├── org-defaults.yml           # Organization-wide defaults
└── repositories/
    ├── api-gateway.yml        # High-security external service
    ├── internal-tool.yml      # Relaxed internal tooling
    └── socket-firewall-test.yml  # Test repo with protestware
```

## Issue Types & Actions

| Issue | Description | Recommended |
|-------|-------------|-------------|
| `knownMalware` | Known malicious package | `error` |
| `protestware` | Protest/sabotage code | `error` |
| `criticalCVE` | Critical severity CVE | `error` |
| `highCVE` | High severity CVE | `error` |
| `mediumCVE` | Medium severity CVE | `warn` |
| `deprecated` | Deprecated package | `warn` |

### Actions

| Action | Effect |
|--------|--------|
| `error` | Block the dependency |
| `warn` | Allow with warning |
| `ignore` | Silently allow |

## GitHub Workflow Integration

Add to your repository:

```yaml
name: Socket Security

on: [push, pull_request]

jobs:
  socket-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Validate socket.yml
        run: |
          # Check for blocked packages
          if grep -q '"colors"' package.json; then
            echo "❌ Blocked: colors (protestware)"
            exit 1
          fi
```

## Local Development

```bash
pip install -r requirements.txt
python -m socket_firewall_configurator.configurator --validate-only
python -m socket_firewall_configurator.configurator --dry-run
```

## Test Repository

See [socket-firewall-test](https://github.com/dduffy-groq/socket-firewall-test) for a working example with intentional protestware to test detection.

## License

BSD-3-Clause
