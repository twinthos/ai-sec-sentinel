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
            "params": params,
            "result": result,
            "risk_level": self._assess_risk(tool_name, params),
        }
        self.events.append(event)
        self._persist(event)
        return event

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
        return []

    def evaluate(self, agent_id: str, tool_name: str, params: dict) -> dict:
        """Evaluate a tool call against policies. Returns allow/warn/ask/block."""
        decision = "allow"
        reasons = []

        # Check tool-level policies
        for policy in self.policies:
            if policy.get("tool") == tool_name or policy.get("tool") == "*":
                if policy.get("agent") and policy["agent"] != agent_id:
                    continue
                condition = policy.get("condition", "always")
                if self._evaluate_condition(condition, tool_name, params):
                    decision = policy.get("action", "allow")
                    reasons.append(policy.get("reason", "Policy match"))

        # Default dangerous tool checks
        dangerous_tools = {"shell_exec", "db_query", "http_request", "code_exec", "file_write"}
        if tool_name in dangerous_tools and decision == "allow":
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
        return False

    def add_policy(self, tool: str, action: str, condition: str = "always", reason: str = "", agent: str = None):
        """Add a policy rule."""
        policy = {
            "tool": tool,
            "action": action,
            "condition": condition,
            "reason": reason,
        }
        if agent:
            policy["agent"] = agent
        self.policies.append(policy)
        self.policy_file.write_text(json.dumps(self.policies, indent=2))


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
            prev_hash = entry.get("hash", "")

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
        # 1. OBSERVE
        event = self.observe.log_tool_call(agent_id, tool_name, params)

        # 2. UNDERSTAND
        blast = self.understand.calculate_blast_radius(agent_id) if agent_id in self.understand.agents else {}

        # 3. CONTROL
        decision = self.control.evaluate(agent_id, tool_name, params)

        # 4. PROVE
        ledger_entry = self.prove.record("tool_call", agent_id, {
            "tool": tool_name,
            "params": params,
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
