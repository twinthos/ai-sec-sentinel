#!/usr/bin/env python3
"""Risk scoring and compliance mapping for Twinthos Sentinel.

Adds:
- Organization risk score (0-100) based on findings
- Compliance mapping (OWASP LLM Top 10, EU AI Act, UK GDPR, FCA, MHRA, SRA)
- GitHub Action workflow for CI/CD integration
"""

import json
from pathlib import Path

# Legacy OWASP LLM category labels (pre-2025). Compatibility/reference only:
# NOT the current 2025 or 2026 OWASP LLM Top 10, and not a compliance assessment.
# See https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
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

# Attack surface / zero-trust (from @patopet insight: abstract services from internet)
# "Why allow an unauthenticated anonymous agent of an attacker to interact with your systems?"
# The sentinel flags systems that expose services to the internet without authentication.
# Zero-trust: every interaction must be authenticated, even internal ones.
ZERO_TRUST_NOTE = (
    "Zero-trust: abstract services from the internet. "
    "No unauthenticated anonymous agent should interact with your systems. "
    "Every interaction requires authentication. Treat 'internet-facing' as 'attack-facing'."
)

# Financial impact varies by system, incident and business. Do not infer sales
# demand, a breach cost or the quality of a deployment from this reference tool.
AI_SECURITY_MARKET_NOTE = (
    "Agent security is a deployment-specific engineering and governance concern. "
    "Assess exposure, business impact and the available evidence for each system. "
    "This project does not estimate breach costs, commercial demand or loss avoided."
)

# Compliance statements need evidence. These functions classify caller-supplied findings;
# they do not independently detect an exploitable vulnerability or certify compliance.
COMPLIANCE_GAP_NOTE = (
    "A certificate is not proof that a system has no vulnerabilities. "
    "This heuristic reviews supplied findings and named certifications; "
    "it does not test the asset or verify any certification."
)

# DEFENSIVE ONLY. Sentinel does NOT provide, install, run, or recommend these tools.
# These tools are listed for THREAT AWARENESS only - so defenders know what attackers
# might use. The purpose of this static catalogue is defensive awareness and exposure triage.
# Using these tools against systems you do not own or have written authorization for
# is illegal in most jurisdictions (Computer Misuse Act 1990, CFAA, etc.).
# Sentinel does not operate offensive tools and this module does not detect their signatures.
DEFENSIVE_ONLY_WARNING = (
    "DEFENSIVE ONLY. Sentinel does NOT provide, install, run, or recommend these tools. "
    "These tools are listed for THREAT AWARENESS - so defenders know what attackers might use. "
    "The purpose of this static catalogue is defensive awareness and exposure triage. "
    "Using these tools against systems you do not own or have written authorization for "
    "is illegal. Sentinel NEVER runs offensive tools. This awareness module does not inspect attack signatures."
)

# AI-powered offensive security tools are becoming mainstream. These tools automate
# vulnerability discovery, penetration testing, and red teaming using LLMs.
# This file lists examples for defensive awareness - knowing what tools
# attackers might use helps defenders prepare. This is defensive awareness only.
# Source: @fr0gger_ (Thomas Roccia) AI security tools compilation, 2026.
# LEGAL WARNING: Using these tools without authorization is illegal.
# Sentinel lists them for awareness only. Sentinel does not provide or run them.
AI_ATTACK_TOOLS = [
    {"name": "HexStrike AI", "type": "AI pentesting", "risk": "Automated vulnerability exploitation", "defensive_only": True},
    {"name": "PentestGPT", "type": "AI pentesting", "risk": "LLM-driven penetration testing", "defensive_only": True},
    {"name": "PentestAgent", "type": "AI pentesting", "risk": "Autonomous security assessment", "defensive_only": True},
    {"name": "Strix", "type": "AI red team", "risk": "Automated red team operations", "defensive_only": True},
    {"name": "Shannon", "type": "AI red team", "risk": "AI-driven attack simulation", "defensive_only": True},
    {"name": "AutoPentester", "type": "AI pentesting", "risk": "Automated penetration testing", "defensive_only": True},
    {"name": "VulnBot", "type": "AI vulnerability scanner", "risk": "Automated vulnerability discovery", "defensive_only": True},
    {"name": "RedAmon", "type": "AI red team", "risk": "AI-powered red team automation", "defensive_only": True},
    {"name": "MAPTA", "type": "AI security testing", "risk": "AI model attack testing", "defensive_only": True},
    {"name": "BugTraceAI", "type": "AI bug hunting", "risk": "Automated bug discovery via AI", "defensive_only": True},
    {"name": "Nebula", "type": "AI security testing", "risk": "AI-driven security assessment", "defensive_only": True},
    {"name": "hackingBuddyGPT", "type": "AI hacking assistant", "risk": "LLM-assisted exploitation", "defensive_only": True},
    {"name": "CyberStrike", "type": "AI cyber operations", "risk": "AI-powered cyber attack automation", "defensive_only": True},
    {"name": "CyberStrikeAI", "type": "AI cyber operations", "risk": "AI-driven attack orchestration", "defensive_only": True},
    {"name": "PentAGI", "type": "AI pentesting", "risk": "Autonomous penetration testing agent", "defensive_only": True},
    {"name": "Cairn", "type": "AI security tool", "risk": "AI-assisted security operations", "defensive_only": True},
    {"name": "CAI", "type": "AI security framework", "risk": "Cybersecurity AI framework (archived)", "defensive_only": True},
]

AI_ATTACK_TOOL_NOTE = (
    "DEFENSIVE AWARENESS ONLY. "
    "AI-powered offensive security tools are becoming mainstream. "
    "These tools automate vulnerability discovery, penetration testing, and red teaming using LLMs. "
    "This module lists static examples for defensive awareness, not a live threat feed. "
    "Sentinel does NOT provide, install, run, or recommend these tools. "
    "This catalogue does not detect their signatures or runtime behaviour. "
    "Using these tools without authorization is illegal."
)

def check_ai_attack_tool_awareness(services: list[dict] = None) -> dict:
    """Check if organization is prepared for AI-powered attacks.

    DEFENSIVE ONLY. Returns awareness status and recommendations.
    Sentinel does NOT run offensive tools. This module does not detect tool signatures.
    """
    if services is None:
        services = []

    # Check if any services are exposed to internet (attack surface)
    exposed = [s for s in services if s.get("internet_facing", False)]
    unauthenticated = [s for s in exposed if not s.get("authenticated", True)]

    result = {
        "defensive_only": True,
        "warning": DEFENSIVE_ONLY_WARNING,
        "ai_attack_tools_tracked": len(AI_ATTACK_TOOLS),  # legacy field: static listed examples, not detections
        "automatic_signature_detection": False,
        "input_type": "caller_supplied_service_metadata",
        "tools": [t["name"] for t in AI_ATTACK_TOOLS],
        "exposed_services": len(exposed),
        "unauthenticated_exposed": len(unauthenticated),
        "risk": "HIGH" if unauthenticated else ("MEDIUM" if exposed else "LOW"),
        "recommendations": [],
    }

    if unauthenticated:
        result["recommendations"].append(
            "Exposed unauthenticated services are primary targets for AI-powered attack tools. "
            "Apply zero-trust: every service must require authentication."
        )
    if exposed:
        result["recommendations"].append(
            "Internet-facing services can be discovered and attacked by AI pentesting tools. "
            "Reduce attack surface: abstract services from the internet."
        )
    result["recommendations"].append(
        "Use appropriate security monitoring to look for suspicious activity. "
        "Potential risk indicators include rapid sequential scanning, "
        "LLM-generated payloads, and automated exploitation attempts."
    )
    result["recommendations"].append(
        "This module lists " + str(len(AI_ATTACK_TOOLS)) + " offensive and dual-use tools as awareness examples. "
        "Update threat intelligence feeds regularly to catch new tools."
    )
    result["recommendations"].append(
        "DEFENSIVE ONLY: Sentinel does not provide, install, or run these tools. "
        "This awareness module does not inspect attack signatures. "
        "Using these tools without authorization is illegal."
    )

    return result


# Email security checks (defensive)
# SPF, DKIM, DMARC are baseline email security. Missing any is a finding.
EMAIL_SECURITY_CHECKS = {
    "spf": {
        "name": "SPF (Sender Policy Framework)",
        "description": "Prevents email spoofing by specifying authorized sending IPs",
        "severity_if_missing": "HIGH",
        "check": "DNS TXT record starting with v=spf1",
    },
    "dkim": {
        "name": "DKIM (DomainKeys Identified Mail)",
        "description": "Cryptographic email authentication via DKIM signature",
        "severity_if_missing": "HIGH",
        "check": "DNS TXT record at selector._domainkey.domain",
    },
    "dmarc": {
        "name": "DMARC (Domain-based Message Authentication)",
        "description": "Policy for handling authentication failures (reject/quarantine/none)",
        "severity_if_missing": "MEDIUM",
        "check": "DNS TXT record at _dmarc.domain",
    },
}


def check_email_security(domain: str) -> dict:
    """Check email security configuration for a domain.

    DEFENSIVE ONLY. Returns findings for missing email security controls.
    Note: This checks configuration, not content. No email is sent or intercepted.
    """
    result = {
        "domain": domain,
        "checks": {},
        "findings": [],
        "score": 100,
    }

    for key, check in EMAIL_SECURITY_CHECKS.items():
        result["checks"][key] = {
            "name": check["name"],
            "description": check["description"],
            "severity_if_missing": check["severity_if_missing"],
            "check_method": check["check"],
            "status": "not_verified",
        }

    result["findings"].append(
        "Verify SPF record: DNS TXT lookup for " + domain + " should return v=spf1"
    )
    result["findings"].append(
        "Verify DKIM: DNS TXT lookup for selector._domainkey." + domain
    )
    result["findings"].append(
        "Verify DMARC: DNS TXT lookup for _dmarc." + domain
    )
    result["findings"].append(
        "DEFENSIVE ONLY: This checks configuration, not email content. "
        "No email is sent or intercepted."
    )

    return result

# Core principle: Twinthos Sentinel exists for the benefit of humanity.
# Security is not about attack. It is about protection.
# This tool must NEVER be used for negative purposes.
# It protects people, systems, and data from harm.
# Every feature, every check, every alert serves one purpose:
# keeping humans safe in a world where AI is becoming powerful.
HUMANITY_PRINCIPLE = (
    "Twinthos Sentinel exists for the benefit of humanity. "
    "Security is not about attack. It is about protection. "
    "This tool must NEVER be used for negative purposes. "
    "It protects people, systems, and data from harm. "
    "Every feature, every check, every alert serves one purpose: "
    "keeping humans safe in a world where AI is becoming powerful. "
    "If a feature cannot be used for good, it does not belong here."
)

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


def check_compliance_gap(findings: list[dict], compliance_certs: list[str] = None) -> dict:
    """Flag high/critical supplied findings alongside claimed certifications.

    Does not verify a certificate, independently discover vulnerabilities or
    establish exploitability. No finding is NOT evidence of a clean system.
    """
    if compliance_certs is None:
        compliance_certs = []
    
    real_vulns = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    has_real_vulns = len(real_vulns) > 0
    has_compliance = len(compliance_certs) > 0
    
    gap_detected = has_compliance and has_real_vulns
    
    result = {
        "compliance_certs": compliance_certs,
        "real_vulnerabilities": len(real_vulns),
        "gap_detected": gap_detected,
        "message": "",
    }
    
    if gap_detected:
        result["message"] = (
            f"COMPLIANCE GAP: System has {', '.join(compliance_certs)} certification "
            f"but {len(real_vulns)} real vulnerabilities found. "
            "Compliance is a baseline, not a guarantee. Investigate immediately."
        )
    elif has_real_vulns:
        result["message"] = (
            f"No compliance certs on file but {len(real_vulns)} real vulnerabilities found. "
            "Consider compliance framework adoption as a baseline."
        )
    else:
        result["message"] = "No high/critical mismatch in the supplied list; the system has NOT been independently verified as clean."
    
    return result


def check_attack_surface(services: list[dict]) -> dict:
    """Check for unauthenticated internet-facing services (zero-trust).
    
    From @patopet insight: "Why allow an unauthenticated anonymous agent 
    of an attacker to interact with your systems?"
    
    Flags services that are exposed to the internet without authentication.
    Zero-trust: every interaction must be authenticated.
    """
    exposed = []
    for svc in services:
        if svc.get("internet_facing") and not svc.get("authenticated"):
            exposed.append(svc.get("name", "unknown"))
    
    result = {
        "total_services": len(services),
        "exposed_unauthenticated": len(exposed),
        "exposed_services": exposed,
        "zero_trust_violation": len(exposed) > 0,
        "message": "",
    }
    
    if exposed:
        result["message"] = (
            f"ZERO-TRUST VIOLATION: {len(exposed)} service(s) exposed to internet "
            f"without authentication: {', '.join(exposed)}. "
            "Abstract services from the internet. Require authentication for all interactions."
        )
    else:
        result["message"] = "No unauthenticated internet-facing services detected. Zero-trust posture maintained."
    
    return result
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
    branches: [main]
  pull_request:
    branches: [main]
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
