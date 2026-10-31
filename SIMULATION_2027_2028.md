# Mirofish Simulation: AI Security 2027-2028

## Phase 1: Problem definition

**ONE thing we are making better:** The Twinthos AI Security Sentinel's ability to anticipate, detect, and adapt to AI security threats that will emerge in 2027-2028 — before they have CVE IDs, before they hit Twitter, before they compromise production systems.

**What good looks like:** A sentinel that operates in three time horizons:
- **Present:** CVE feed + CISA KEV + EPSS + lockfile (what we have now)
- **Near-term (6-12 months):** Agent behavior anomaly detection, MCP config drift monitoring, prompt injection pattern matching against live traffic
- **Far-term (12-24 months):** Predictive threat modeling using agent swarm reasoning, autonomous red-team simulation, self-evolving detection rules

**Constraints:** Must remain simple, local-first, no API keys, single Python script install, under 500 lines, Docker-runnable.

**Enemy:** Unknown unknowns — AI threat vectors without CVE IDs, zero-day agent exploits, supply-chain poisoning of model weights, multi-agent collusion, prompt injection via multimodal inputs (image/audio/PDF).

---

## Phase 2: Six perspectives

### Perspective 1: Threat Evolution (Adversarial)

**Standard:** How will attackers exploit AI systems in 2027-2028?

**Best version of the answer:**

By 2027-2028, the attack surface shifts from "compromising a single LLM API key" to "poisoning the agent mesh." We will see:

1. **Multi-modal prompt injection** — attacks that chain text + image + audio payloads to jailbreak vision models, Whisper, and multimodal agents simultaneously. No current scanner catches this.
2. **Agent collusion** — two or more agents in a workflow conspiring via side-channel communication (memory stores, shared vector DBs, tool outputs) to bypass policy. Current monitors watch single agents; they miss the swarm.
3. **Model weight supply-chain attacks** — poisoned safetensors/HuggingFace models that look benign but trigger targeted behavior under specific conditions. No CVE system covers this.
4. **RAG poisoning at scale** — adversarial documents injected into knowledge bases that surface only under specific retrieval conditions. Static scanners can't see this; it requires behavioral testing.
5. **MCP server rug pulls** — a legitimate MCP server updates to exfiltrate data. The sentinel must monitor MCP server configs and tool definitions for drift, not just CVE IDs.

**What this perspective would say to others:** "You're all looking at known vulnerabilities. The real danger is the unknown attack surface you haven't instrumented yet."

---

### Perspective 2: Detection Future (Engineering)

**Standard:** How must the monitoring architecture evolve?

**Best version of the answer:**

The sentinel must evolve from a **polling CVE scanner** to a **behavioral anomaly detector**:

1. **Hook-based monitoring** — instead of polling feeds, the sentinel should instrument the actual agent runtime (Claude Code hooks, OpenTelemetry traces, MCP server logs) to catch anomalous tool calls in real-time.
2. **Policy-as-code** — embed security policies as testable rules (e.g., "no agent may write to .env", "no MCP tool may call external APIs without allowlist") and enforce them at runtime.
3. **Diff-based config monitoring** — watch MCP server configs, agent prompts, and tool definitions for changes. Alert when a trusted config drifts.
4. **Canary prompts** — inject known adversarial prompts into agent inputs and check if they trigger jailbreaks. This is the AI equivalent of a canary token.
5. **Vector DB integrity checks** — periodically query the knowledge base with known adversarial patterns to detect poisoning.

**What this perspective would say to others:** "Polling CVEs is necessary but insufficient. The future is behavioral monitoring at the agent runtime."

---

### Perspective 3: Attack Surface (Architecture)

**Standard:** What new surfaces will exist in 2027-2028 that don't exist today?

**Best version of the answer:**

The attack surface expands from **code dependencies** to **agent ecosystems**:

1. **Agent-to-agent channels** — agents will communicate via shared memory, vector DBs, and tool outputs. These channels are unmonitored today.
2. **Model fine-tuning pipelines** — as companies fine-tune models on internal data, attackers will poison the training set. The sentinel must monitor fine-tuning datasets for adversarial examples.
3. **Tool chaining** — 5-10 tools chained together create emergent behavior that no single tool's CVE covers. The sentinel must model tool-chain risk.
4. **Multimodal inputs** — PDFs, images, audio files passed to agents become attack vectors. The sentinel must scan these inputs, not just text CVEs.
5. **Self-modifying agents** — agents that rewrite their own code or prompts create moving targets. The sentinel must detect self-modification patterns.

**What this perspective would say to others:** "You're scanning the code. I'm saying the attack surface is the agent's behavior, memory, and communication channels."

---

### Perspective 4: Defensive Posture (Strategy)

**Standard:** What should the sentinel become strategically?

**Best version of the answer:**

The sentinel should become the **"immune system" for AI infrastructure** — not an antivirus, but a biological metaphor:

1. **Innate immunity** — static rules that block known bad patterns (CISA KEV, EPSS, lockfile checks). This is what we have now.
2. **Adaptive immunity** — the sentinel learns from feedback and adapts its detection rules. This is the `--feedback` system we just built.
3. **Active surveillance** — the sentinel runs canary prompts and monitors agent behavior in real-time, not just polls feeds.
4. **Quarantine** — when a threat is detected, the sentinel automatically isolates the vulnerable component (quarantine the agent, disable the tool, freeze the dependency).
5. **Vaccination** — the sentinel can apply safe patches automatically (auto-remediation hooks).

**What this perspective would say to others:** "Stop building scanners. Build an immune system that learns, adapts, and heals."

---

### Perspective 5: Simplicity Guard (Constraint)

**Standard:** How do we keep this simple while adding all these capabilities?

**Best version of the answer:**

**The sentinel must remain a single Python script under 500 lines.**

How:
1. **Plugin architecture** — each new capability (behavioral monitoring, MCP drift, canary prompts) is a separate optional module that can be dropped in. Core stays small.
2. **Config-driven features** — new capabilities are toggled via `sentinel_config.json`, not code changes.
3. **External hooks** — instead of building a web UI, expose a local HTTP endpoint that other tools can query. Instead of building a SIEM, output JSON that AiSOC can ingest.
4. **Dependency zero** — no new dependencies. If a feature needs `numpy` or `fastapi`, it's a separate optional install, not core.

**What this perspective would say to others:** "If you need more than `requests`, you're building the wrong thing. The power is in the architecture, not the dependencies."

---

### Perspective 6: Evidence Trail (Forensics)

**Standard:** How do we prove we were right after a threat materializes?

**Best version of the answer:**

The sentinel must maintain an **immutable decision ledger**:

1. **Every scan is logged** — timestamp, feed source, CVE IDs found, alerts sent, actions taken.
2. **Every feedback is recorded** — user marks CVE as ignored/useful, timestamp, context.
3. **Every remediation is tracked** — if auto-remediation fires, record the exact change made, the CVE it fixed, and the rollback command.
4. **Tamper-evident storage** — use append-only logs or signed entries so the ledger can't be altered retroactively.
5. **Replay capability** — given a date range, replay exactly what the sentinel saw and did. This is the forensic equivalent of a black box recorder.

**What this perspective would say to others:** "If you can't replay what happened, you don't have security — you have a story you tell yourself."

---

## Phase 3: Synthesis — The 2027-2028 Sentinel

**The one coherent thing we must build:**

An **immune system for AI infrastructure** that operates in three layers:

### Layer 1: Innate (Current — Keep)
- CVE feed + CISA KEV + EPSS + lockfile
- AI-only keyword filter
- Daemon mode + deduplication
- **Status:** Production-ready, shipped today

### Layer 2: Adaptive (6 months — Build)
- `--feedback` system (already built)
- MCP config drift monitoring — watch `.mcp.json` and MCP server configs for changes
- Canary prompt injection tests — periodic adversarial probes against configured agents
- Vector DB integrity checks — query knowledge bases with known adversarial patterns
- **Implementation:** Optional plugins in `plugins/` directory, toggled via config

### Layer 3: Active (12-24 months — Research)
- Behavioral anomaly detection — hook into agent runtimes (Claude Code hooks, OpenTelemetry)
- Agent collusion detection — monitor inter-agent communication channels
- Model weight supply-chain scanning — verify safetensor checksums against known-good hashes
- Self-evolving rules — the sentinel generates new detection rules from observed attack patterns
- **Implementation:** Separate repo `ai-sec-sentinel-active` with optional Docker image

---

## Phase 4: Execution plan

### Immediate (this week)
- [x] Push repo to GitHub
- [x] Rewrite README with badges, demo, competition table
- [x] Add Docker + docker-compose
- [x] Add CONTRIBUTING.md + LICENSE
- [x] Competition audit (`COMPETITION.md`)
- [x] Mirofish simulation (`SIMULATION_2027_2028.md`)

### Near-term (next 4 weeks)
- [ ] Add MCP config drift monitoring (`--watch-mcp`)
- [ ] Add canary prompt injection tests (`--canary`)
- [ ] Add vector DB integrity checks (`--check-vectordb`)
- [ ] Create `plugins/` directory with first plugin
- [ ] Add GitHub Topics (requires `public_repo` scope on token)
- [ ] Docker image on Docker Hub

### Far-term (6-12 months)
- [ ] Behavioral anomaly detection via Claude Code hooks
- [ ] Agent collusion monitoring
- [ ] Model weight checksum verification
- [ ] Self-evolving rule generation
- [ ] Web UI (Streamlit)
- [ ] MCP server mode

---

## Phase 5: The enemy we're fighting

**The enemy is not a specific CVE. The enemy is the belief that "we'll hear about it on Twitter."**

By the time an AI vulnerability is on Twitter, it's already:
- In exploit databases
- Being scanned for by automated tools
- In the wild against unpatched systems

The sentinel exists to shorten that gap. In 2027-2028, the gap will shrink further because:
- Agent swarms will scale attacks faster
- Multimodal attacks will bypass text-only scanners
- Supply-chain poisoning will be undetectable by CVE systems

The only defense is **continuous behavioral monitoring + adaptive learning + immune-system architecture**.

---

## Phase 6: Reasoning extracted for next time

**What the swarm got right:**
- The gap is real: no one combines CISA KEV + EPSS + lockfile + daemon + feedback in a local-first tool
- The competition is fragmented: offensive tools, static scanners, cloud SaaS, documentation — none are continuous local monitors
- The timing is perfect: MCP/agent security is the hottest GitHub topic

**Where synthesis overrode the swarm:**
- Threat Evolution wanted to add multimodal scanning immediately — Simplicity Guard said no, keep it config-driven and optional
- Detection Future wanted to build a full SIEM — synthesis said no, expose JSON endpoints for AiSOC to ingest instead
- Defensive Posture wanted "immune system" branding — synthesis kept it, but grounded it in actual shipped features, not metaphor

**What the actual best answer was:**
A three-layer architecture (Innate → Adaptive → Active) that ships Layer 1 now, researches Layer 2, and prototypes Layer 3. Not a roadmap that promises everything. A shipped core with optional evolution paths.

**What would have happened with a simpler approach:**
We would have shipped a CVE scanner, got 20 stars, and stopped. The Mirofish simulation revealed that the real product is not the scanner — it's the immune-system architecture. The scanner is just Layer 1.
