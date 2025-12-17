# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Socket Firewall Configurator, please report it responsibly.

### How to Report

1. **Do NOT open a public issue** for security vulnerabilities
2. Email security concerns to your security team
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- Acknowledgment within 48 hours
- Status update within 7 days
- Resolution timeline based on severity

## Security Best Practices

When using Socket Firewall Configurator:

1. **Protect GitHub App credentials**: Store `ORG_CONFIGURATOR_APP_ID` and `ORG_CONFIGURATOR_APP_PRIVATE_KEY` as organization secrets
2. **Review generated rules**: Always review pull requests before merging
3. **Enable strict validation**: Use `strict-validation: true` in production
4. **Limit source CIDRs**: Configure `allowed-sources` to restrict inbound traffic
5. **Use default deny**: Never change `default-action` to `allow`

## Security Features

### Authentication

- GitHub App authentication with short-lived tokens
- Minimum required permissions
- All actions logged in audit trail

### Validation

- Automatic security scanning of generated rules
- Detection of dangerous patterns
- CIDR notation validation

### Audit

- Automatic audit workflow for firewall changes
- Security team notification
- Change tracking

