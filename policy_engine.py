#!/usr/bin/env python3
"""Policy engine for Sentinel Guardian — enforceable at tool-execution boundary.

Four layers: OBSERVE, UNDERSTAND, CONTROL, PROVE.
Deny-by-default. Priority-ordered rules. No override of higher-priority deny.
"""

import time
import hashlib
import json
from enum import Enum
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta


class Decision(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"  # Requires explicit approval
    WARN = "warn"


@dataclass
class PolicyRule:
    rule_id: str
    tool: str  # tool name or "*" for all
    action: Decision
    condition: str  # "always", "destination", "resource", "time"
    condition_params: dict = field(default_factory=dict)
    priority: int = 0  # Higher = more important
    reason: str = ""
    expires: Optional[str] = None


@dataclass
class ApprovalToken:
    token_id: str
    agent_id: str
    tool: str
    params_hash: str
    approved_by: str
    created_at: str
    expires_at: str
    used: bool = False


class PolicyEngine:
    def __init__(self):
        self.rules: List[PolicyRule] = []
        self.approvals: Dict[str, ApprovalToken] = {}
        self.blocked_destinations = set()
        self.allowed_destinations = set()
    
    def add_rule(self, rule: PolicyRule):
        # Reject unknown conditions
        valid_conditions = {"always", "destination", "resource", "time", "agent"}
        if rule.condition not in valid_conditions:
            raise ValueError(f"Unknown condition: {rule.condition}")
        self.rules.append(rule)
        # Sort by priority descending
        self.rules.sort(key=lambda r: r.priority, reverse=True)
    
    def remove_rule(self, rule_id: str):
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
    
    def evaluate(self, agent_id: str, tool: str, params: dict) -> dict:
        """Evaluate a tool call against all policies. Returns decision dict."""
        # Check rules in priority order
        # Higher priority deny CANNOT be overridden by lower priority allow
        deny_found = None
        ask_found = None
        allow_found = None
        
        for rule in self.rules:
            if rule.tool != tool and rule.tool != "*":
                continue
            
            # Check expiry
            if rule.expires:
                if datetime.now(timezone.utc).isoformat() > rule.expires:
                    continue  # Expired rule
            
            # Check condition
            if not self._check_condition(rule, agent_id, tool, params):
                continue
            
            if rule.action == Decision.BLOCK:
                if deny_found is None or rule.priority >= deny_found.priority:
                    deny_found = rule
            elif rule.action == Decision.ASK:
                if ask_found is None:
                    ask_found = rule
            elif rule.action == Decision.ALLOW:
                if allow_found is None:
                    allow_found = rule
        
        # Deny takes precedence over everything
        if deny_found:
            return {
                "decision": Decision.BLOCK,
                "rule_id": deny_found.rule_id,
                "reason": deny_found.reason,
                "requires_approval": False,
            }
        
        # Ask requires approval
        if ask_found:
            return {
                "decision": Decision.ASK,
                "rule_id": ask_found.rule_id,
                "reason": ask_found.reason,
                "requires_approval": True,
            }
        
        # Allow if explicit allow rule found
        if allow_found:
            return {
                "decision": Decision.ALLOW,
                "rule_id": allow_found.rule_id,
                "reason": allow_found.reason,
                "requires_approval": False,
            }
        
        # Default: deny unknown actions
        return {
            "decision": Decision.BLOCK,
            "rule_id": "default-deny",
            "reason": "No matching allow rule — default deny",
            "requires_approval": False,
        }
    
    def _check_condition(self, rule: PolicyRule, agent_id: str, tool: str, params: dict) -> bool:
        """Check if a rule's condition matches."""
        if rule.condition == "always":
            return True
        if rule.condition == "destination":
            dest = params.get("url", params.get("destination", ""))
            if rule.action == Decision.BLOCK:
                # Block if destination matches blocked pattern
                for blocked in self.blocked_destinations:
                    if blocked in dest:
                        return True
                # Also check condition_params
                blocked_patterns = rule.condition_params.get("blocked", [])
                for bp in blocked_patterns:
                    if bp in dest:
                        return True
                return False
            elif rule.action == Decision.ALLOW:
                # Allow if destination is in allowed list
                for allowed in self.allowed_destinations:
                    if allowed in dest:
                        return True
                allowed_patterns = rule.condition_params.get("allowed", [])
                for ap in allowed_patterns:
                    if ap in dest:
                        return True
                return False if self.allowed_destinations else True
        if rule.condition == "resource":
            resource = params.get("path", params.get("resource", ""))
            blocked_resources = rule.condition_params.get("blocked", [])
            for br in blocked_resources:
                if br in resource:
                    return True
            return False
        if rule.condition == "agent":
            target_agents = rule.condition_params.get("agents", [])
            return agent_id in target_agents
        if rule.condition == "time":
            # Time-based conditions
            return True  # Simplified
        return False  # Unknown condition — reject
    
    def create_approval(self, agent_id: str, tool: str, params: dict, approved_by: str, expiry_minutes: int = 5) -> str:
        """Create a time-limited approval token tied to exact action."""
        params_hash = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()
        token_id = hashlib.sha256(f"{agent_id}:{tool}:{params_hash}:{time.time()}".encode()).hexdigest()[:16]
        now = datetime.now(timezone.utc)
        token = ApprovalToken(
            token_id=token_id,
            agent_id=agent_id,
            tool=tool,
            params_hash=params_hash,
            approved_by=approved_by,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=expiry_minutes)).isoformat(),
        )
        self.approvals[token_id] = token
        return token_id
    
    def use_approval(self, token_id: str, agent_id: str, tool: str, params: dict) -> Tuple[bool, str]:
        """Use an approval token. Prevents replay. Returns (valid, reason)."""
        token = self.approvals.get(token_id)
        if not token:
            return False, "Token not found"
        if token.used:
            return False, "Token already used (replay prevented)"
        if token.agent_id != agent_id:
            return False, "Token agent mismatch"
        if token.tool != tool:
            return False, "Token tool mismatch"
        params_hash = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()
        if token.params_hash != params_hash:
            return False, "Token params mismatch (exact action required)"
        if datetime.now(timezone.utc).isoformat() > token.expires_at:
            return False, "Token expired"
        token.used = True
        return True, "OK"
    
    def check_ssrf(self, url: str) -> Tuple[bool, str]:
        """Check URL for SSRF risks. Returns (safe, reason)."""
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False, "Invalid URL"
        
        hostname = parsed.hostname or ""
        
        # Block loopback
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False, "Loopback blocked"
        
        # Block private IPs
        import ipaddress
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, f"Private/reserved IP blocked: {hostname}"
            # Block metadata endpoints
            if str(ip) in ("169.254.169.254", "fd00:ec2::254"):
                return False, "Cloud metadata endpoint blocked"
        except ValueError:
            pass  # Not an IP, it's a hostname
        
        # Block metadata hostnames
        if "metadata" in hostname.lower() or "169.254" in hostname:
            return False, "Metadata endpoint blocked"
        
        return True, "OK"


def run_policy_tests():
    print("=== Policy Engine Tests ===")
    
    pe = PolicyEngine()
    
    # Test 1: Default deny
    print("\n1. Default deny (unknown action):")
    r = pe.evaluate("agent1", "unknown_tool", {})
    assert r["decision"] == Decision.BLOCK
    print("   PASS: unknown action blocked")
    
    # Test 2: Allow rule
    print("\n2. Allow rule:")
    pe.add_rule(PolicyRule("allow-read", "file_read", Decision.ALLOW, "always", reason="Read allowed"))
    r = pe.evaluate("agent1", "file_read", {})
    assert r["decision"] == Decision.ALLOW
    print("   PASS: file_read allowed")
    
    # Test 3: Block overrides allow
    print("\n3. Block overrides allow (priority):")
    pe.add_rule(PolicyRule("block-shell", "shell_exec", Decision.BLOCK, "always", priority=10, reason="No shell"))
    pe.add_rule(PolicyRule("allow-shell", "shell_exec", Decision.ALLOW, "always", priority=1, reason="Shell allowed"))
    r = pe.evaluate("agent1", "shell_exec", {})
    assert r["decision"] == Decision.BLOCK
    print("   PASS: higher-priority block wins")
    
    # Test 4: Ask requires approval, not permission
    print("\n4. Ask is not permission:")
    pe.add_rule(PolicyRule("ask-http", "http_request", Decision.ASK, "always", reason="Approve HTTP"))
    r = pe.evaluate("agent1", "http_request", {"url": "http://example.com"})
    assert r["decision"] == Decision.ASK
    assert r["requires_approval"] == True
    print("   PASS: ask requires approval, not auto-allow")
    
    # Test 5: Unknown condition rejected
    print("\n5. Unknown condition rejected:")
    try:
        pe.add_rule(PolicyRule("bad", "tool", Decision.ALLOW, "nonexistent_condition"))
        print("   FAIL: should have raised ValueError")
    except ValueError:
        print("   PASS: unknown condition rejected")
    
    # Test 6: Approval token prevents replay
    print("\n6. Approval token replay prevention:")
    token = pe.create_approval("agent1", "http_request", {"url": "http://x.com"}, "admin", 5)
    valid, reason = pe.use_approval(token, "agent1", "http_request", {"url": "http://x.com"})
    assert valid == True
    valid2, reason2 = pe.use_approval(token, "agent1", "http_request", {"url": "http://x.com"})
    assert valid2 == False and "replay" in reason2.lower()
    print("   PASS: replay prevented")
    
    # Test 7: Approval token params mismatch
    print("\n7. Approval token params mismatch:")
    token2 = pe.create_approval("agent1", "http_request", {"url": "http://x.com"}, "admin", 5)
    valid, reason = pe.use_approval(token2, "agent1", "http_request", {"url": "http://y.com"})
    assert valid == False
    print("   PASS: params mismatch rejected")
    
    # Test 8: SSRF protection
    print("\n8. SSRF protection:")
    safe, reason = pe.check_ssrf("http://169.254.169.254/latest/meta-data/")
    assert safe == False
    safe2, reason2 = pe.check_ssrf("http://example.com/api")
    assert safe2 == True
    safe3, _ = pe.check_ssrf("http://127.0.0.1:8080/")
    assert safe3 == False
    print("   PASS: SSRF blocked, normal allowed")
    
    # Test 9: Destination restrictions
    print("\n9. Destination restrictions:")
    pe2 = PolicyEngine()
    pe2.blocked_destinations.add("evil.com")
    pe2.add_rule(PolicyRule("block-evil", "http_request", Decision.BLOCK, "destination", reason="Blocked dest"))
    r = pe2.evaluate("agent1", "http_request", {"url": "http://evil.com/data"})
    assert r["decision"] == Decision.BLOCK
    r2 = pe2.evaluate("agent1", "http_request", {"url": "http://good.com/data"})
    assert r2["decision"] != Decision.BLOCK or r2["rule_id"] != "block-evil"
    print("   PASS: destination restrictions enforced")
    
    # Test 10: Harmless HTTP not globally blocked
    print("\n10. Harmless HTTP not blocked:")
    pe3 = PolicyEngine()
    pe3.add_rule(PolicyRule("allow-http", "http_request", Decision.ALLOW, "always", reason="HTTP allowed"))
    r = pe3.evaluate("agent1", "http_request", {"url": "http://example.com"})
    assert r["decision"] == Decision.ALLOW
    print("   PASS: harmless HTTP allowed")
    
    print("\n=== All policy engine tests passed ===")


if __name__ == "__main__":
    run_policy_tests()
