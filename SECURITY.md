# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | Yes       |
| < 1.2   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Twinthos Sentinel, please report it responsibly:

1. **Do NOT open a public issue.** Use GitHub Security Advisories instead.
2. Go to [Security Advisories](https://github.com/twinthos/ai-sec-sentinel/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact

## Response Timeline

- **Acknowledgement:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Within 30 days for critical/high, 90 days for medium/low

## Scope

This policy covers the Twinthos Sentinel codebase. It does NOT cover:
- The managed Twinthos service at twinthos.com
- Third-party dependencies (report to their maintainers)
- Social engineering or physical attacks

## Security Design

- All state writes are atomic (temp + rename)
- Webhook server binds to 127.0.0.1 only
- HTML output is escaped
- No credentials are stored in the repository
- Environment variables are used for secrets

## Contact

For security inquiries: security@twinthos.com
