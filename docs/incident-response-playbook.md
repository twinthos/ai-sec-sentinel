# Incident Response Playbook

## Twinthos Sentinel — Incident Response Procedures

### Severity Classification

| Level | Description | Response Time | Example |
|-------|-------------|---------------|---------|
| P1 | Critical — active breach or exploitation | 1 hour | CISA KEV match on production system |
| P2 | High — unpatched critical CVE | 4 hours | CVSS 9.0+ with no patch available |
| P3 | Medium — vulnerability with patch | 24 hours | CVSS 7.0+ with patch available |
| P4 | Low — informational | 7 days | Supply chain advisory |

### Response Steps

#### 1. Detect
- Sentinel scan identifies finding (CVE, KEV match, EPSS score)
- Alert sent via configured channel (Telegram/Slack/Email)
- Finding recorded in evidence ledger

#### 2. Triage
- Review finding severity and affected systems
- Check if finding is in CISA KEV (known exploitation)
- Check EPSS score (exploitation probability)
- Determine blast radius (affected services, data, users)

#### 3. Contain
- Isolate affected systems if possible
- Disable exposed services temporarily
- Block malicious IPs/domains if identified
- Revoke compromised credentials

#### 4. Remediate
- Apply patches if available
- Update dependencies
- Rotate secrets and credentials
- Reconfigure affected services

#### 5. Verify
- Re-run Sentinel scan to confirm fix
- Check for additional exploitation
- Review logs for lateral movement

#### 6. Report
- Document incident in evidence ledger
- Notify stakeholders
- Update compliance records
- Post-incident review within 7 days

### Escalation

| Condition | Escalate To |
|-----------|-------------|
| P1 unresolved after 1 hour | Security lead |
| Data breach confirmed | Legal + DPO + Executive |
| Supply chain compromise | Vendor + Security lead |
| Compliance gap found | Compliance officer |

### Communication

- Internal: Slack #security channel
- External: Only through approved channels
- Never disclose unpatched vulnerabilities publicly
- Follow responsible disclosure for third-party findings

### Tools

- Sentinel dashboard: http://localhost:8090
- Sentinel CLI: `python3 ai_sec_sentinel.py --health`
- Evidence ledger: `evidence_ledger.py`
- Alert queue: `alert_queue.py`

### Post-Incident Review Template

1. What happened?
2. How was it detected?
3. What was the impact?
4. What was the root cause?
5. What was done to fix it?
6. What will prevent recurrence?
7. Action items with owners and dates