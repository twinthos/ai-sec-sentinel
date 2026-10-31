"""MCP config drift monitoring plugin."""
import hashlib
from pathlib import Path

def scan_mcp_drift(config_path: str) -> list:
    p = Path(config_path)
    if not p.exists():
        return []
    content = p.read_text(encoding="utf-8")
    current_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
    state_file = p.parent / ".mcp_drift_state"
    findings = []
    if state_file.exists():
        prev_hash = state_file.read_text().strip()
        if prev_hash != current_hash:
            findings.append(f"MCP config drift detected: {p.name} changed")
    state_file.write_text(current_hash)
    return findings
