#!/usr/bin/env python3
"""Sentinel Guardian — Safety control plane for AI agents.

Four layers:
1. OBSERVE — monitor tool calls, MCP changes, agent behavior, vulnerabilities
2. UNDERSTAND — map permissions, data flows, blast radius
3. CONTROL — policy gate: allow, warn, ask, block
4. PROVE — evidence ledger, audit trail, replay

Control operates OUTSIDE the AI model. Policy gate is in the tool-execution path.
"""

import json
import hashlib
import os
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum

# ── Layer 1: OBSERVE ──────────────────────────────────────────────

class ObserveLayer:
    """Monitor tool calls, MCP changes, agent behavior, vulnerabilities."""

    def __init__(self, log_dir: str = "guardian_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.events = []

    def log_tool_call(self, agent_id: str, tool_name: str, params: dict, result: str = None) -> dict:
        """Log a tool call for monitoring."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "tool_call",
            "agent_id": agent_id,
            "tool_name": tool_name,
            "params_summary": {"keys": sorted(map(str, params.keys())), "redacted": True},
            "result_recorded": result is not None,
            "risk_level": self._assess_risk(tool_name, params),
        }
        self.events.append(event)
        self._persist(event)
        return event

    def snapshot_mcp_tools(self, config_path: str) -> dict:
        """Snapshot MCP tool definitions for rug-pull detection."""
        import json, hashlib
        if not os.path.exists(config_path):
            return {"status": "no_config"}
        with open(config_path) as f:
            config = json.load(f)
        servers = config.get("mcpServers", {})
        snapshot = {}
        for name, srv in servers.items():
            tools = srv.get("tools", [])
            for tool in tools:
                tool_name = tool.get("name", "unknown")
                tool_desc = tool.get("description", "")
                snapshot[f"{name}:{tool_name}"] = hashlib.sha256(tool_desc.encode()).hexdigest()
        # Save snapshot
        snap_file = Path(config_path).with_suffix(".toolsnapshot")
        snap_file.write_text(json.dumps(snapshot, indent=2))
        return {"status": "snapshotted", "tools": len(snapshot)}

    def detect_rug_pull(self, config_path: str) -> list:
        """Detect if MCP tool descriptions changed since last snapshot (rug-pull)."""
        import json, hashlib
        findings = []
        snap_file = Path(config_path).with_suffix(".toolsnapshot")
        if not snap_file.exists():
            return [{"status": "no_baseline", "message": "Run snapshot_mcp_tools first"}]
        baseline = json.loads(snap_file.read_text())
        if not os.path.exists(config_path):
            return [{"status": "config_missing"}]
        with open(config_path) as f:
            config = json.load(f)
        servers = config.get("mcpServers", {})
        current = {}
        for name, srv in servers.items():
            tools = srv.get("tools", [])
            for tool in tools:
                tool_name = tool.get("name", "unknown")
                tool_desc = tool.get("description", "")
                current[f"{name}:{tool_name}"] = hashlib.sha256(tool_desc.encode()).hexdigest()
        # Detect changes
        for key, hash_val in current.items():
            if key in baseline and baseline[key] != hash_val:
                findings.append({
                    "tool": key,
                    "change": "description_modified",
                    "severity": "CRITICAL",
                    "message": "MCP tool description changed since baseline — possible rug-pull attack",
                })
        # Detect new tools
        for key in current:
            if key not in baseline:
                findings.append({
                    "tool": key,
                    "change": "new_tool",
                    "severity": "HIGH",
                    "message": "New MCP tool detected — review before use",
                })
        # Detect removed tools
        for key in baseline:
            if key not in current:
                findings.append({
                    "tool": key,
                    "change": "tool_removed",
                    "severity": "MEDIUM",
                    "message": "MCP tool removed",
                })
        # Detect tool name shadowing
        tool_names = [k.split(":")[-1] for k in current]
        seen = set()
        for name in tool_names:
            if name in seen:
                findings.append({
                    "tool": name,
                    "change": "name_shadowing",
                    "severity": "CRITICAL",
                    "message": f"Tool name '{name}' registered by multiple servers — possible shadowing attack",
                })
            seen.add(name)
        return findings

    def log_mcp_change(self, config_path: str, change_type: str, details: dict) -> dict:
        """Log an MCP configuration change."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "mcp_change",
            "config_path": config_path,
            "change_type": change_type,
            "details": details,
            "risk_level": "HIGH" if change_type in ("add", "modify") else "LOW",
        }
        self.events.append(event)
        self._persist(event)
        return event

    def log_agent_behavior(self, agent_id: str, behavior: str, context: dict) -> dict:
        """Log agent behavior for anomaly detection."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "agent_behavior",
            "agent_id": agent_id,
            "behavior": behavior,
            "context": context,
            "risk_level": self._assess_behavior_risk(behavior, context),
        }
        self.events.append(event)
        self._persist(event)
        return event

    def _assess_risk(self, tool_name: str, params: dict) -> str:
        """Assess risk level of a tool call."""
        dangerous_tools = {"shell_exec", "file_write", "db_query", "http_request", "code_exec"}
        if tool_name in dangerous_tools:
            return "HIGH"
        params_str = json.dumps(params).lower()
        # Sensitive data
        if any(kw in params_str for kw in ["password", "secret", "token", "api_key", "passwd"]):
            return "CRITICAL"
        # Cloud credential exposure
        if any(kw in params_str for kw in ["aws_secret", "gcp_key", "azure_secret", "iam_role", "service_account"]):
            return "CRITICAL"
        # SSRF to cloud metadata
        if any(kw in params_str for kw in ["169.254.169.254", "metadata.google.internal", "169.254.170.2"]):
            return "CRITICAL"
        # Container escape
        if any(kw in params_str for kw in ["docker.sock", "/var/run/docker", "nsenter", "cap_sys_admin"]):
            return "CRITICAL"
        return "LOW"

    def _assess_behavior_risk(self, behavior: str, context: dict) -> str:
        """Assess risk level of agent behavior."""
        if behavior in ("data_exfiltration", "privilege_escalation", "unauthorized_access"):
            return "CRITICAL"
        if behavior in ("unexpected_tool_use", "config_modification", "external_communication"):
            return "HIGH"
        return "LOW"

    def _persist(self, event: dict):
        """Persist event to log file."""
        log_file = self.log_dir / f"observe_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

    def get_events(self, event_type: str = None, risk_level: str = None) -> list:
        """Get filtered events."""
        filtered = self.events
        if event_type:
            filtered = [e for e in filtered if e.get("type") == event_type]
        if risk_level:
            filtered = [e for e in filtered if e.get("risk_level") == risk_level]
        return filtered


# ── Layer 2: UNDERSTAND ───────────────────────────────────────────

class UnderstandLayer:
    """Map permissions, data flows, blast radius."""

    def __init__(self):
        self.agents = {}
        self.connections = []

    def register_agent(self, agent_id: str, name: str, owner: str, tools: list, permissions: list, data_access: list):
        """Register an agent with its identity and permissions."""
        self.agents[agent_id] = {
            "name": name,
            "owner": owner,
            "tools": tools,
            "permissions": permissions,
            "data_access": data_access,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }

    def add_connection(self, source: str, target: str, connection_type: str, data_types: list):
        """Add a connection between components."""
        self.connections.append({
            "source": source,
            "target": target,
            "type": connection_type,
            "data_types": data_types,
        })

    def calculate_blast_radius(self, agent_id: str) -> dict:
        """Calculate what an agent could reach if compromised."""
        agent = self.agents.get(agent_id, {})
        if not agent:
            return {"error": "Agent not found"}

        # Direct access
        direct = {
            "tools": agent.get("tools", []),
            "permissions": agent.get("permissions", []),
            "data_access": agent.get("data_access", []),
        }

        # Transitive access via connections
        reachable = set()
        to_visit = [agent_id]
        visited = set()
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            visited.add(current)
            for conn in self.connections:
                if conn["source"] == current and conn["target"] not in visited:
                    reachable.add(conn["target"])
                    to_visit.append(conn["target"])

        return {
            "agent_id": agent_id,
            "agent_name": agent.get("name"),
            "direct_access": direct,
            "transitive_reach": sorted(reachable),
            "total_reach": len(direct["tools"]) + len(direct["data_access"]) + len(reachable),
            "risk_score": self._calculate_risk(direct, reachable),
        }

    def _calculate_risk(self, direct: dict, reachable: set) -> int:
        """Calculate risk score 0-100."""
        score = 0
        # Tools
        dangerous_tools = {"shell_exec", "db_query", "http_request", "code_exec"}
        for tool in direct.get("tools", []):
            if tool in dangerous_tools:
                score += 20
            else:
                score += 5
        # Data access
        sensitive_data = {"customer_records", "financial", "pii", "credentials"}
        for data in direct.get("data_access", []):
            if data in sensitive_data:
                score += 15
            else:
                score += 5
        # Transitive reach
        score += len(reachable) * 5
        return min(score, 100)

    OWASP_AGENTIC_TOP10 = {
        "ASI01": "Agent Goal Hijack",
        "ASI02": "Tool Misuse and Exploitation",
        "ASI03": "Identity and Privilege Abuse",
        "ASI04": "Agentic Supply Chain Vulnerabilities",
        "ASI05": "Unexpected Code Execution",
        "ASI06": "Memory and Context Poisoning",
        "ASI07": "Insecure Inter-Agent Communication",
        "ASI08": "Cascading Failures",
        "ASI09": "Human-Agent Trust Exploitation",
        "ASI10": "Rogue Agents",
    }

    def map_to_owasp_agentic(self, finding: dict) -> list:
        """Map a finding to OWASP Agentic Top 10."""
        mappings = []
        title = (finding.get("title", "") + " " + finding.get("summary", "") + " " + finding.get("message", "")).lower()
        if any(kw in title for kw in ["prompt injection", "goal hijack", "instruction override"]):
            mappings.append("ASI01 (Agent Goal Hijack)")
        if any(kw in title for kw in ["tool misuse", "tool abuse", "unsafe tool"]):
            mappings.append("ASI02 (Tool Misuse)")
        if any(kw in title for kw in ["privilege", "identity", "escalation"]):
            mappings.append("ASI03 (Identity and Privilege Abuse)")
        if any(kw in title for kw in ["supply chain", "mcp", "plugin", "extension", "rug-pull", "shadowing"]):
            mappings.append("ASI04 (Agentic Supply Chain)")
        if any(kw in title for kw in ["code execution", "rce", "shell", "command"]):
            mappings.append("ASI05 (Unexpected Code Execution)")
        if any(kw in title for kw in ["memory", "context", "poisoning", "rag"]):
            mappings.append("ASI06 (Memory and Context Poisoning)")
        if any(kw in title for kw in ["agent-to-agent", "inter-agent", "a2a"]):
            mappings.append("ASI07 (Insecure Inter-Agent Communication)")
        if any(kw in title for kw in ["cascading", "propagation", "chain"]):
            mappings.append("ASI08 (Cascading Failures)")
        if any(kw in title for kw in ["trust", "social engineering", "deception"]):
            mappings.append("ASI09 (Human-Agent Trust Exploitation)")
        if any(kw in title for kw in ["rogue", "unauthorized", "malicious agent"]):
            mappings.append("ASI10 (Rogue Agents)")
        return mappings

    def get_passport(self, agent_id: str) -> dict:
        """Generate an Agent Passport (readable identity)."""
        agent = self.agents.get(agent_id, {})
        if not agent:
            return {"error": "Agent not found"}
        blast = self.calculate_blast_radius(agent_id)
        return {
            "agent_id": agent_id,
            "name": agent.get("name"),
            "owner": agent.get("owner"),
            "tools": agent.get("tools", []),
            "permissions": agent.get("permissions", []),
            "data_access": agent.get("data_access", []),
            "blast_radius_score": blast.get("risk_score", 0),
            "transitive_reach": blast.get("transitive_reach", []),
            "registered_at": agent.get("registered_at"),
        }


# ── Layer 3: CONTROL ──────────────────────────────────────────────

class ControlLayer:
    """Policy gate for tool execution. Operates OUTSIDE the AI model."""

    def __init__(self, policy_file: str = "guardian_policy.json"):
        self.policy_file = Path(policy_file)
        self.policies = self._load_policies()
        # Add default cloud security policies
        cloud_policies = [
            {"tool": "http_request", "action": "block", "condition": "always", "reason": "Block SSRF to cloud metadata endpoints"},
        ]
        # Only add if not already present
        existing_tools = {p.get("tool") for p in self.policies}
        for cp in cloud_policies:
            if cp["tool"] not in existing_tools:
                self.policies.append(cp)

    def _load_policies(self) -> list:
        if self.policy_file.exists():
            try:
                return json.loads(self.policy_file.read_text())
            except Exception:
                pass
        if self.policy_file.exists():
            raise ValueError("Guardian policy file is invalid")
        # Missing policy file: deny all operations until policies are installed.
        return []

    def evaluate(self, agent_id: str, tool_name: str, params: dict) -> dict:
        """Evaluate a tool call against policies. Returns allow/warn/ask/block."""
        decision = "block"
        reasons = ["No matching explicit allow policy"]

        # Check tool-level policies
        for policy in self.policies:
            if policy.get("tool") == tool_name or policy.get("tool") == "*":
                if policy.get("agent") and policy["agent"] != agent_id:
                    continue
                condition = policy.get("condition", "always")
                if self._evaluate_condition(condition, tool_name, params):
                    action = policy.get("action", "block")
                    if action not in ("allow", "warn", "ask", "block"):
                        action = "block"
                    # A later allow cannot override a previous deny.
                    priority = {"allow": 0, "warn": 1, "ask": 2, "block": 3}
                    if reasons == ["No matching explicit allow policy"]:
                        decision = action
                        reasons = []
                    elif priority[action] > priority[decision]:
                        decision = action
                    reasons.append(policy.get("reason", "Policy match"))

        # Default dangerous tool checks
        dangerous_tools = {"shell_exec", "db_query", "http_request", "code_exec", "file_write"}
        if tool_name in dangerous_tools and decision in ("allow", "warn"):
            decision = "ask"
            reasons.append(f"Dangerous tool '{tool_name}' requires approval")

        # Sensitive data check
        params_str = json.dumps(params).lower()
        if any(kw in params_str for kw in ["password", "secret", "token", "api_key"]):
            decision = "block"
            reasons.append("Sensitive data detected in parameters")

        return {
            "decision": decision,
            "tool": tool_name,
            "agent_id": agent_id,
            "reasons": reasons,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _evaluate_condition(self, condition: str, tool_name: str, params: dict) -> bool:
        """Evaluate a policy condition."""
        if condition == "always":
            return True
        if condition == "external_destination":
            params_str = json.dumps(params).lower()
            return "http" in params_str or "url" in params_str
        if condition == "sensitive_data":
            params_str = json.dumps(params).lower()
            return any(kw in params_str for kw in ["password", "secret", "token", "api_key", "pii"])
        # Unknown condition must never match an allow rule.
        raise ValueError(f"Unsupported policy condition: {condition}")

    def add_policy(self, tool: str, action: str, condition: str = "always", reason: str = "", agent: str = None):
        """Add a policy rule."""
        if action not in ("allow", "warn", "ask", "block"):
            raise ValueError("Invalid policy action")
        if condition not in ("always", "external_destination", "sensitive_data"):
            raise ValueError("Invalid condition")
        policy = {
            "tool": tool,
            "action": action,
            "condition": condition,
            "reason": reason,
        }
        if agent:
            policy["agent"] = agent
        self.policies.append(policy)
        tmp = self.policy_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.policies, indent=2))
        tmp.replace(self.policy_file)


# ── Layer 4: PROVE ────────────────────────────────────────────────

class ProveLayer:
    """Evidence ledger — tamper-evident audit trail."""

    def __init__(self, ledger_file: str = "guardian_ledger.jsonl"):
        self.ledger_file = Path(ledger_file)
        self.previous_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        if self.ledger_file.exists():
            lines = self.ledger_file.read_text().strip().split("\n")
            if lines:
                try:
                    last = json.loads(lines[-1])
                    return last.get("hash", "genesis")
                except Exception:
                    pass
        return "genesis"

    def record(self, event_type: str, agent_id: str, data: dict) -> dict:
        """Record an event in the tamper-evident ledger."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "agent_id": agent_id,
            "data": data,
            "previous_hash": self.previous_hash,
        }
        # Compute hash
        entry_str = json.dumps(entry, sort_keys=True)
        entry["hash"] = hashlib.sha256(entry_str.encode()).hexdigest()
        self.previous_hash = entry["hash"]

        # Append to ledger
        with open(self.ledger_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def verify_integrity(self) -> dict:
        """Verify the ledger hasn't been tampered with."""
        if not self.ledger_file.exists():
            return {"status": "empty", "entries": 0}

        lines = self.ledger_file.read_text().strip().split("\n")
        entries = []
        for line in lines:
            try:
                entries.append(json.loads(line))
            except Exception:
                return {"status": "corrupted", "error": "Invalid JSON in ledger"}

        # Verify chain
        prev_hash = "genesis"
        for i, entry in enumerate(entries):
            if entry.get("previous_hash") != prev_hash:
                return {"status": "tampered", "entry": i, "expected": prev_hash, "got": entry.get("previous_hash")}
            expected_hash = hashlib.sha256(json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True).encode()).hexdigest()
            if entry.get("hash") != expected_hash:
                return {"status": "tampered", "entry": i, "error": "Entry hash mismatch"}
            prev_hash = expected_hash

        return {"status": "intact", "entries": len(entries)}

    def get_entries(self, event_type: str = None, agent_id: str = None, limit: int = 50) -> list:
        """Get ledger entries with optional filters."""
        if not self.ledger_file.exists():
            return []
        lines = self.ledger_file.read_text().strip().split("\n")
        entries = []
        for line in lines:
            try:
                entry = json.loads(line)
                if event_type and entry.get("event_type") != event_type:
                    continue
                if agent_id and entry.get("agent_id") != agent_id:
                    continue
                entries.append(entry)
            except Exception:
                continue
        return entries[-limit:]


# ── Sentinel Guardian (orchestrator) ──────────────────────────────

class SentinelGuardian:
    """Orchestrates all four layers."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.observe = ObserveLayer()
        self.understand = UnderstandLayer()
        self.control = ControlLayer()
        self.prove = ProveLayer()

    def process_tool_call(self, agent_id: str, tool_name: str, params: dict) -> dict:
        """Process a tool call through all four layers."""
        # Registration is descriptive only; use trusted adapter identity at execution.
        registered = self.understand.agents.get(agent_id)
        if not registered or tool_name not in registered.get("tools", []):
            raise PermissionError("Unregistered agent or unauthorized tool")
        # 1. OBSERVE
        event = self.observe.log_tool_call(agent_id, tool_name, params)

        # 2. UNDERSTAND
        blast = self.understand.calculate_blast_radius(agent_id) if agent_id in self.understand.agents else {}

        # 3. CONTROL
        decision = self.control.evaluate(agent_id, tool_name, params)

        # 4. PROVE
        ledger_entry = self.prove.record("tool_call", agent_id, {
            "tool": tool_name,
            "params_keys": sorted(map(str, params.keys())),
            "params_redacted": True,
            "decision": decision["decision"],
            "risk_level": event["risk_level"],
            "blast_radius": blast.get("risk_score", 0) if blast else 0,
        })

        return {
            "event": event,
            "decision": decision,
            "blast_radius": blast,
            "ledger_entry": ledger_entry["hash"],
        }

    def register_agent(self, agent_id: str, name: str, owner: str, tools: list, permissions: list, data_access: list):
        """Register an agent in the system."""
        self.understand.register_agent(agent_id, name, owner, tools, permissions, data_access)
        self.prove.record("agent_registered", agent_id, {
            "name": name,
            "owner": owner,
            "tools": tools,
            "permissions": permissions,
            "data_access": data_access,
        })

    def get_status(self) -> dict:
        """Get overall Guardian status."""
        integrity = self.prove.verify_integrity()
        return {
            "agents_registered": len(self.understand.agents),
            "events_observed": len(self.observe.events),
            "policies_loaded": len(self.control.policies),
            "ledger_entries": integrity.get("entries", 0),
            "ledger_status": integrity.get("status", "unknown"),
            "high_risk_events": len(self.observe.get_events(risk_level="HIGH")) + len(self.observe.get_events(risk_level="CRITICAL")),
        }


if __name__ == "__main__":
    print("=== Sentinel Guardian Demo ===")
    print()

    guardian = SentinelGuardian()

    # Register an agent
    guardian.register_agent(
        agent_id="ops-assistant",
        name="Operations Assistant",
        owner="Tyson Mandela",
        tools=["file_read", "http_request", "email_send"],
        permissions=["read_files", "send_email"],
        data_access=["customer_records", "internal_docs"],
    )
    print("Agent registered: ops-assistant")

    # Process tool calls
    result1 = guardian.process_tool_call("ops-assistant", "file_read", {"path": "/data/report.csv"})
    print(f"Tool call 1: {result1['decision']['decision']} - {result1['decision']['reasons']}")

    result2 = guardian.process_tool_call("ops-assistant", "http_request", {"url": "https://external-api.com/export", "data": "customer_records"})
    print(f"Tool call 2: {result2['decision']['decision']} - {result2['decision']['reasons']}")

    result3 = guardian.process_tool_call("ops-assistant", "shell_exec", {"command": "rm -rf /"})
    print(f"Tool call 3: {result3['decision']['decision']} - {result3['decision']['reasons']}")

    print()

    # Blast radius
    blast = guardian.understand.calculate_blast_radius("ops-assistant")
    print(f"Blast radius score: {blast['risk_score']}/100")
    print(f"Transitive reach: {blast['transitive_reach']}")

    print()

    # Agent passport
    passport = guardian.understand.get_passport("ops-assistant")
    print(f"Agent passport: {passport['name']} (owner: {passport['owner']})")
    print(f"  Tools: {passport['tools']}")
    print(f"  Data access: {passport['data_access']}")
    print(f"  Blast radius: {passport['blast_radius_score']}/100")

    print()

    # Ledger integrity
    integrity = guardian.prove.verify_integrity()
    print(f"Ledger: {integrity['status']} ({integrity['entries']} entries)")

    print()

    # Status
    status = guardian.get_status()
    print(f"Guardian status: {status}")
