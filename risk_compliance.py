#!/usr/bin/env python3
"""Risk scoring and compliance mapping for Twinthos Sentinel.

Adds:
- Organization risk score (0-100) based on findings
- Compliance mapping (OWASP LLM Top 10, EU AI Act, UK GDPR, FCA, MHRA, SRA)
- GitHub Action workflow for CI/CD integration
"""

import json
from pathlib import Path

# OWASP LLM Top 10 (2025) mapping
OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}

# Compliance framework mapping
COMPLIANCE_FRAMEWORKS = {
    "eu_ai_act": {
        "name": "EU AI Act",
        "deadline": "2 Dec 2027 (high-risk), 2 Aug 2026 (transparency)",
        "requirements": {
            "cybersecurity": ["Art. 15", "Annex III"],
            "robustness": ["Art. 15", "Annex III"],
            "human_oversight": ["Art. 14", "Annex III"],
            "logging": ["Art. 12", "Annex III"],
            "risk_management": ["Art. 9", "Annex III"],
            "data_quality": ["Art. 10", "Annex III"],
        },
    },
    "uk_gdpr": {
        "name": "UK GDPR",
        "deadline": "In force",
        "requirements": {
            "special_category_data": ["Art. 9"],
            "dpia": ["Art. 35"],
            "breach_notification": ["Art. 33 (72 hours)"],
            "security_measures": ["Art. 32"],
        },
    },
    "fca": {
        "name": "FCA AI Guidance",
        "deadline": "In force",
        "requirements": {
            "operational_resilience": ["PRIN", "SYSC"],
            "third_party_risk": ["SYSC 8"],
            "consumer_protection": ["PRIN 6, 7"],
        },
    },
    "mhra": {
        "name": "MHRA Medical Devices",
        "deadline": "Consultation Spring 2027",
        "requirements": {
            "registration": ["UK MDR 2002"],
            "conformity_assessment": ["UK MDR 2002"],
            "risk_management": ["ISO 14971"],
        },
    },
    "sra": {
        "name": "SRA Professional Conduct",
        "deadline": "In force",
        "requirements": {
            "confidentiality": ["SRA Code 6.3"],
            "risk_management": ["SRA Code 2.1"],
            "competence": ["SRA Code 3.1"],
        },
    },
}


def calculate_risk_score(findings: list[dict]) -> dict:
    """Calculate organization risk score from findings.

    Score: 0-100 (0 = no risk, 100 = critical)
    Factors: severity, CISA KEV, EPSS, count, recency
    """
    if not findings:
        return {"score": 0, "level": "LOW", "factors": []}

    score = 0
    factors = []

    # Severity weighting
    sev_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    for f in findings:
        sev = f.get("severity", "LOW")
        weight = sev_weights.get(sev, 3)
        score += weight

    # CISA KEV bonus (actively exploited)
    kev_count = sum(1 for f in findings if f.get("in_kev"))
    if kev_count > 0:
        score += kev_count * 20
        factors.append(f"{kev_count} CISA KEV (actively exploited)")

    # EPSS bonus (high exploit probability)
    high_epss = sum(1 for f in findings if f.get("epss", 0) >= 0.7)
    if high_epss > 0:
        score += high_epss * 10
        factors.append(f"{high_epss} high-EPSS (>=0.7)")

    # Count penalty (more findings = more risk, but diminishing)
    count = len(findings)
    if count > 10:
        score += 10
        factors.append(f"{count} total findings")
    elif count > 5:
        score += 5

    # Cap at 100
    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "factors": factors,
        "finding_count": count,
        "kev_count": kev_count,
        "high_epss_count": high_epss,
    }


def map_to_compliance(finding: dict) -> list[str]:
    """Map a finding to compliance frameworks."""
    mappings = []
    sev = finding.get("severity", "LOW")
    title = (finding.get("title", "") + " " + finding.get("summary", "")).lower()

    # Prompt injection / agent issues → EU AI Act cybersecurity
    if any(kw in title for kw in ["prompt injection", "agent", "mcp", "tool poisoning"]):
        mappings.append("EU AI Act Art. 15 (cybersecurity)")
        mappings.append("OWASP LLM01 (Prompt Injection)")

    # Supply chain → EU AI Act + OWASP LLM05
    if any(kw in title for kw in ["supply chain", "dependency", "package"]):
        mappings.append("EU AI Act Art. 15 (supply chain)")
        mappings.append("OWASP LLM05 (Supply Chain)")

    # Data disclosure → UK GDPR + OWASP LLM06
    if any(kw in title for kw in ["data", "leak", "disclosure", "exfiltration"]):
        mappings.append("UK GDPR Art. 32 (security)")
        mappings.append("OWASP LLM06 (Sensitive Info Disclosure)")

    # Privilege escalation → OWASP LLM08
    if any(kw in title for kw in ["privilege", "escalation", "excessive"]):
        mappings.append("OWASP LLM08 (Excessive Agency)")

    # Insecure plugin → OWASP LLM07
    if any(kw in title for kw in ["plugin", "mcp", "tool"]):
        mappings.append("OWASP LLM07 (Insecure Plugin Design)")

    # Health data → MHRA
    if any(kw in title for kw in ["health", "medical", "patient"]):
        mappings.append("MHRA (medical device boundary)")

    # Financial → FCA
    if any(kw in title for kw in ["financial", "payment", "bank", "money"]):
        mappings.append("FCA (operational resilience)")

    # Legal → SRA
    if any(kw in title for kw in ["legal", "contract", "clause"]):
        mappings.append("SRA (confidentiality)")

    return mappings


def generate_risk_report(findings: list[dict]) -> str:
    """Generate a human-readable risk report."""
    risk = calculate_risk_score(findings)

    report = f"=== Twinthos Sentinel Risk Report ===\n"
    report += f"Risk Score: {risk['score']}/100 ({risk['level']})\n"
    report += f"Findings: {risk['finding_count']}\n"
    report += f"CISA KEV hits: {risk['kev_count']}\n"
    report += f"High-EPSS: {risk['high_epss_count']}\n"
    if risk['factors']:
        report += f"Factors: {', '.join(risk['factors'])}\n"
    report += "\n"

    # Compliance summary
    all_mappings = set()
    for f in findings:
        all_mappings.update(map_to_compliance(f))

    if all_mappings:
        report += "Compliance impact:\n"
        for m in sorted(all_mappings):
            report += f"  - {m}\n"

    return report


# GitHub Action workflow template
GITHUB_ACTION_YML = """name: Twinthos Sentinel Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 6 * * *'  # Daily at 6am UTC

jobs:
  sentinel-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run Sentinel scan
        env:
          TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
          TELEGRAM_CHAT_ID: ${{ secrets.TELEGRAM_CHAT_ID }}
        run: python3 ai_sec_sentinel.py --since-hours 24 --feed-limit 100
      - name: Run tests
        run: python3 -m unittest tests.test_sentinel_core -v
"""


if __name__ == "__main__":
    # Demo with sample findings
    sample_findings = [
        {"title": "LangChain RCE via MCP", "severity": "CRITICAL", "in_kev": True, "epss": 0.95, "summary": "prompt injection in langchain"},
        {"title": "CrewAI tool poisoning", "severity": "HIGH", "in_kev": False, "epss": 0.6, "summary": "mcp tool abuse"},
        {"title": "OpenAI API key leak", "severity": "MEDIUM", "in_kev": False, "epss": 0.3, "summary": "sensitive information disclosure"},
    ]
    print(generate_risk_report(sample_findings))
    print("\n--- GitHub Action Workflow ---")
    print(GITHUB_ACTION_YML)
