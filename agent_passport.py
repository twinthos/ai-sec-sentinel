#!/usr/bin/env python3
"""Agent Passport — readable security identity for registered agents.

Starts with explicit config files, not automatic discovery.
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import List, Optional, Dict
from dataclasses import dataclass, field, asdict


@dataclass
class AgentPassport:
    agent_id: str
    owner: str
    purpose: str
    approved_tools: List[str] = field(default_factory=list)
    approved_data_sources: List[str] = field(default_factory=list)
    external_destinations: List[str] = field(default_factory=list)
    sensitive_actions: List[str] = field(default_factory=list)
    permission_expiry: Optional[str] = None
    human_approval_required: List[str] = field(default_factory=list)
    last_config_change: Optional[str] = None
    last_verified_security_test: Optional[str] = None
    unknown_permissions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def to_readable(self) -> str:
        """Human-readable passport."""
        lines = [
            f"=== Agent Passport: {self.agent_id} ===",
            f"Owner: {self.owner}",
            f"Purpose: {self.purpose}",
            f"Approved tools: {', '.join(self.approved_tools) or 'none'}",
            f"Data sources: {', '.join(self.approved_data_sources) or 'none'}",
            f"External destinations: {', '.join(self.external_destinations) or 'none'}",
            f"Sensitive actions: {', '.join(self.sensitive_actions) or 'none'}",
            f"Permission expiry: {self.permission_expiry or 'none'}",
            f"Human approval required for: {', '.join(self.human_approval_required) or 'none'}",
            f"Last config change: {self.last_config_change or 'never'}",
            f"Last verified security test: {self.last_verified_security_test or 'never'}",
        ]
        if self.unknown_permissions:
            lines.append(f"⚠ UNKNOWN PERMISSIONS: {', '.join(self.unknown_permissions)}")
        return "\n".join(lines)
    
    def is_expired(self) -> bool:
        if not self.permission_expiry:
            return False
        return datetime.now(timezone.utc).isoformat() > self.permission_expiry
    
    def validate(self) -> List[str]:
        """Validate passport. Returns list of issues."""
        issues = []
        if not self.agent_id:
            issues.append("Missing agent_id")
        if not self.owner:
            issues.append("Missing owner")
        if not self.purpose:
            issues.append("Missing purpose")
        if self.is_expired():
            issues.append("Permissions expired")
        if self.unknown_permissions:
            issues.append(f"Unknown permissions: {self.unknown_permissions}")
        return issues


class PassportRegistry:
    def __init__(self, config_dir: str = "passports"):
        self.config_dir = config_dir
        self.passports: Dict[str, AgentPassport] = {}
    
    def load_from_config(self, path: str):
        """Load passports from a JSON config file."""
        with open(path, 'r') as f:
            data = json.load(f)
        for agent_data in data.get("agents", []):
            passport = AgentPassport(**agent_data)
            self.passports[passport.agent_id] = passport
    
    def register(self, passport: AgentPassport):
        self.passports[passport.agent_id] = passport
    
    def get(self, agent_id: str) -> Optional[AgentPassport]:
        return self.passports.get(agent_id)
    
    def save_to_config(self, path: str):
        """Save all passports to config file."""
        data = {"agents": [p.to_dict() for p in self.passports.values()]}
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_all(self) -> List[AgentPassport]:
        return list(self.passports.values())


def run_passport_tests():
    print("=== Agent Passport Tests ===")
    
    import tempfile, os
    
    # Test 1: Create and read passport
    print("\n1. Create and read:")
    p = AgentPassport(
        agent_id="agent-1",
        owner="tyson",
        purpose="Process customer emails",
        approved_tools=["email_read", "email_send"],
        approved_data_sources=["customer_db"],
        external_destinations=["smtp.example.com"],
        sensitive_actions=["email_send"],
        human_approval_required=["email_send"],
    )
    readable = p.to_readable()
    assert "agent-1" in readable
    assert "tyson" in readable
    print("   PASS: readable passport generated")
    
    # Test 2: Expiry
    print("\n2. Expiry:")
    p2 = AgentPassport(agent_id="a2", owner="x", purpose="y", permission_expiry="2020-01-01T00:00:00+00:00")
    assert p2.is_expired() == True
    p3 = AgentPassport(agent_id="a3", owner="x", purpose="y", permission_expiry="2099-01-01T00:00:00+00:00")
    assert p3.is_expired() == False
    print("   PASS: expiry checked")
    
    # Test 3: Validation
    print("\n3. Validation:")
    p4 = AgentPassport(agent_id="", owner="", purpose="")
    issues = p4.validate()
    assert len(issues) >= 2
    print(f"   PASS: {len(issues)} issues found")
    
    # Test 4: Unknown permissions visible
    print("\n4. Unknown permissions:")
    p5 = AgentPassport(agent_id="a5", owner="x", purpose="y", unknown_permissions=["admin_access"])
    assert "admin_access" in p5.to_readable()
    print("   PASS: unknown permissions visible")
    
    # Test 5: Config round-trip
    print("\n5. Config round-trip:")
    reg = PassportRegistry()
    reg.register(p)
    path = tempfile.mktemp(suffix=".json")
    reg.save_to_config(path)
    reg2 = PassportRegistry()
    reg2.load_from_config(path)
    assert reg2.get("agent-1") is not None
    assert reg2.get("agent-1").owner == "tyson"
    os.unlink(path)
    print("   PASS: config round-trip works")
    
    print("\n=== All passport tests passed ===")


if __name__ == "__main__":
    run_passport_tests()
