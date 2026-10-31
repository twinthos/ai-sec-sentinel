# AI Security Monitor Landscape — October 2026

## Market reality

- **6,855 repos** tagged `ai-security` on GitHub
- **22,400 stars** on NVIDIA's SkillSpector (MCP/agent skill scanner)
- **1,300 stars** on ZeroDayEvil's ai-security-tool (offensive AI pentesting)
- **588 stars** on secureagentics/Adrian (runtime agent security)
- **209 repos** tagged `mcp-security`
- **16 repos** tagged `agentic-security`

## Competitors and their weaknesses

### 1. cve.now
- **What it is:** Free merged feed (CVE List, GitHub Advisory, OSV, NVD, CISA KEV, EPSS, Exploit-DB) + MCP server
- **Pros:** No API key, broad coverage, MCP integration
- **Cons:** Generic — no AI-only filter, no lockfile awareness, no continuous daemon, no feedback learning
- **Our edge:** AI-only keyword filter + CISA KEV enrichment + EPSS per-CVE + lockfile check + daemon mode + feedback learning

### 2. NVIDIA SkillSpector
- **What it is:** Static scanner for Claude Code, Codex, and MCP skills. Detects prompt injection, data exfiltration, supply-chain risks.
- **Pros:** Vendor-backed, 22k stars, skill-specific rules
- **Cons:** Static analysis only, not continuous, no CVE feed integration, no EPSS, no lockfile, no daemon
- **Our edge:** Continuous monitoring + live CVE feed + EPSS + lockfile + feedback

### 3. Lakera Guard
- **What it is:** Cloud SaaS for LLM security. Prompt injection detection, jailbreak prevention, data leakage protection.
- **Pros:** Production-grade, API-based, low latency
- **Cons:** Paid, cloud-only, no offline mode, no CVE monitoring, no lockfile, no open source
- **Our edge:** Free, local-first, no SaaS signup, open source, CVE-aware

### 4. Protect AI
- **What it is:** AI/ML security platform. Supply chain protection, model scanning, agent monitoring.
- **Pros:** Comprehensive ML focus, enterprise features
- **Cons:** Paid, complex setup, cloud-heavy, not focused on CVE alerts, not open source
- **Our edge:** Simple one-script install, free, CVE-focused, lockfile-aware

### 5. Vigil LLM (deadbits)
- **What it is:** Runtime prompt injection and jailbreak detector for LLM inputs.
- **Pros:** Lightweight, regex + LLM judge, 509 stars
- **Cons:** Input-only, no CVE monitoring, no dependency scanning, no daemon mode, no EPSS
- **Our edge:** CVE feed + CISA KEV + EPSS + lockfile + daemon + feedback

### 6. AiSOC (beenuar)
- **What it is:** Open-source AI Security Operations Center. Alert fusion, LLM-agent triage, MITRE ATT&CK investigation, replayable decision ledger.
- **Pros:** SIEM-grade, MITRE ATT&CK mapped, MCP server included, 4.1k stars
- **Cons:** Complex setup, heavy dependencies, requires Elasticsearch/OpenSearch, overkill for small teams
- **Our edge:** Zero-dependency (requests only), one-script install, lockfile-aware, feedback learning

### 7. OWASP MCP Top 10
- **What it is:** Static list/document of top MCP security risks.
- **Pros:** Authoritative, community-driven, 121 stars
- **Cons:** Not a tool, not automated, no alerts, no scanning
- **Our edge:** Automated enforcement, not just documentation

### 8. Adrian (secureagentics)
- **What it is:** Runtime AI agent security tool. Monitors and controls AI agents, catching malicious tool use, prompt injection, policy drift in real time.
- **Pros:** Real-time monitoring, agent-specific, 588 stars
- **Cons:** Agent-runtime only, no CVE feed, no EPSS, no lockfile, Python-only, no web UI
- **Our edge:** CVE feed + CISA KEV + EPSS + multi-ecosystem lockfile + Docker + web UI roadmap

### 9. agent-audit (HeadyZhang)
- **What it is:** Static security scanner for LLM agents. Prompt injection, MCP config auditing, taint analysis. 51 rules mapped to OWASP Agentic Top 10.
- **Pros:** Static analysis, OWASP-mapped, 243 stars
- **Cons:** Static only, not continuous, no CVE integration, no EPSS, no daemon
- **Our edge:** Continuous daemon + live CVE feed + EPSS + lockfile + feedback

### 10. HexStrike AI / CyberStrikeAI
- **What it is:** Offensive AI pentesting tools. Autonomous agents running 150+ cybersecurity tools.
- **Pros:** Powerful offensive capability, 12.8k/7.8k stars
- **Cons:** Offensive only, not defensive monitoring, no CISA KEV, no EPSS, no lockfile
- **Our edge:** Defensive monitoring, CISA KEV + EPSS, lockfile-aware, local-first

## The gap we own

| Dimension | Others | This |
|-----------|--------|------|
| CVE coverage | Generic or offensive | AI-only filtered |
| CISA KEV | Rare | Built-in |
| EPSS | Rare | Built-in |
| Lockfile | Rare | Built-in |
| Continuous daemon | Rare | Built-in |
| Feedback learning | None | Built-in |
| Local-first | Mixed | Yes |
| No API key | Mixed | Yes |
| Install complexity | High | One script |
| Docker | Some | Yes |

**The winning position:** The only local-first, continuous, AI-only vulnerability monitor that combines CISA KEV + EPSS + lockfile + feedback learning with zero API keys and one-script install.
