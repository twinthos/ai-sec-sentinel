#!/usr/bin/env python3
"""Verifiable evidence ledger for Twinthos Sentinel Guardian.

Canonical serialisation, hash chain verification, tamper detection.
Documents limitations (not tamper-proof against storage controller).
"""

import json
import hashlib
import os
import time
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime, timezone

LEDGER_PATH = Path(os.getenv("SENTINEL_LEDGER_PATH", "guardian_ledger.jsonl"))


def canonical_serialize(entry: dict) -> str:
    """Canonical JSON serialisation for hashing. Sorted keys, no whitespace."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(entry: dict, prev_hash: str) -> str:
    """Compute SHA-256 hash of entry with previous hash chained."""
    canonical = canonical_serialize(entry)
    chained = f"{prev_hash}:{canonical}"
    return hashlib.sha256(chained.encode()).hexdigest()


class EvidenceLedger:
    def __init__(self, path: str = None):
        self.path = Path(path) if path else LEDGER_PATH
        self.entries = []
        self._load()
    
    def _load(self):
        """Load existing ledger from file."""
        if self.path.exists():
            with open(self.path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            self.entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            # Corrupt entry — record as gap
                            self.entries.append({"_corrupt": True, "_raw": line})
    
    def append(self, event_type: str, data: dict, redact: bool = True) -> str:
        """Append an entry to the ledger. Returns entry hash."""
        from privacy import redact_dict
        if redact:
            data = redact_dict(data)
        
        prev_hash = self.entries[-1]["hash"] if self.entries and "hash" in self.entries[-1] else "GENESIS"
        
        entry = {
            "seq": len(self.entries) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "data": data,
            "prev_hash": prev_hash,
        }
        entry["hash"] = compute_hash(entry, prev_hash)
        
        # Write to file (append mode)
        with open(self.path, 'a') as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        
        self.entries.append(entry)
        return entry["hash"]
    
    def verify_integrity(self) -> dict:
        """Verify full chain integrity. Returns status dict."""
        if not self.entries:
            return {"status": "empty", "entries": 0, "valid": True, "errors": []}
        
        errors = []
        prev_hash = "GENESIS"
        
        for i, entry in enumerate(self.entries):
            if entry.get("_corrupt"):
                errors.append(f"Entry {i+1}: corrupt/unparseable")
                continue
            
            # Check sequence
            if entry.get("seq") != i + 1:
                errors.append(f"Entry {i+1}: sequence mismatch (expected {i+1}, got {entry.get('seq')})")
            
            # Check prev_hash chain
            if entry.get("prev_hash") != prev_hash:
                errors.append(f"Entry {i+1}: prev_hash mismatch (chain broken)")
            
            # Recompute hash
            entry_copy = {k: v for k, v in entry.items() if k != "hash"}
            recomputed = compute_hash(entry_copy, entry.get("prev_hash", ""))
            if recomputed != entry.get("hash"):
                errors.append(f"Entry {i+1}: hash mismatch (tampered)")
            
            prev_hash = entry.get("hash", "")
        
        # Check for gaps (missing entries)
        seqs = [e.get("seq", 0) for e in self.entries if not e.get("_corrupt")]
        if seqs and seqs != list(range(1, len(seqs) + 1)):
            errors.append("Sequence gap detected — entries may have been deleted")
        
        status = "valid" if not errors else "corrupted"
        return {
            "status": status,
            "entries": len(self.entries),
            "valid": len(errors) == 0,
            "errors": errors,
        }
    
    def verify_entry(self, seq: int) -> dict:
        """Verify a single entry by sequence number."""
        if seq < 1 or seq > len(self.entries):
            return {"valid": False, "error": "Entry not found"}
        entry = self.entries[seq - 1]
        if entry.get("_corrupt"):
            return {"valid": False, "error": "Entry is corrupt"}
        entry_copy = {k: v for k, v in entry.items() if k != "hash"}
        recomputed = compute_hash(entry_copy, entry.get("prev_hash", ""))
        return {
            "valid": recomputed == entry.get("hash"),
            "seq": seq,
            "recomputed": recomputed,
            "stored": entry.get("hash"),
        }
    
    def get_entries(self, event_type: str = None, limit: int = 50) -> List[Dict]:
        """Get entries, optionally filtered by type."""
        entries = self.entries
        if event_type:
            entries = [e for e in entries if e.get("event_type") == event_type]
        return entries[-limit:]
    
    def document_limitations(self) -> str:
        return """
EVIDENCE LEDGER LIMITATIONS:
1. Hash chaining detects tampering with individual entries or reordering.
2. If an attacker controls the ENTIRE storage environment (file system, database),
   they can rewrite the entire chain and recompute all hashes.
3. For independently trustworthy audit evidence, use:
   - HMAC with a key stored in a separate system (e.g., HSM, KMS)
   - External timestamping (RFC 3161)
   - Write-once storage (WORM)
   - Replication to an independent system
4. Hash chaining alone is NOT tamper-proof. It is tamper-EVIDENT against
   partial modifications only.
"""


def run_ledger_tests():
    print("=== Evidence Ledger Tests ===")
    
    import tempfile, os
    db = tempfile.mktemp(suffix=".jsonl")
    
    # Test 1: Append and verify
    print("\n1. Append and verify:")
    ledger = EvidenceLedger(db)
    h1 = ledger.append("test_event", {"key": "value", "secret": "password123"})
    h2 = ledger.append("test_event2", {"key": "value2"})
    result = ledger.verify_integrity()
    assert result["valid"] == True
    assert result["entries"] == 2
    print("   PASS: chain valid")
    
    # Test 2: Tamper detection (modify entry)
    print("\n2. Tamper detection:")
    # Modify file
    with open(db, 'r') as f:
        lines = f.readlines()
    lines[0] = lines[0].replace("test_event", "TAMPERED_EVENT")
    with open(db, 'w') as f:
        f.writelines(lines)
    ledger2 = EvidenceLedger(db)
    result2 = ledger2.verify_integrity()
    assert result2["valid"] == False
    assert len(result2["errors"]) > 0
    print(f"   PASS: tamper detected — {result2['errors'][0]}")
    
    # Test 3: Deletion detection
    print("\n3. Deletion detection:")
    with open(db, 'w') as f:
        f.write(lines[1])  # Delete first entry
    ledger3 = EvidenceLedger(db)
    result3 = ledger3.verify_integrity()
    assert result3["valid"] == False
    print(f"   PASS: deletion detected — {result3['errors']}")
    
    # Test 4: Redaction in ledger
    print("\n4. Redaction:")
    db2 = tempfile.mktemp(suffix=".jsonl")
    ledger4 = EvidenceLedger(db2)
    ledger4.append("secret_event", {"api_key": "sk-abc123def456", "data": "normal"})
    with open(db2, 'r') as f:
        content = f.read()
    assert "sk-abc" not in content
    assert "[REDACTED" in content
    print("   PASS: secrets redacted in ledger")
    
    os.unlink(db)
    os.unlink(db2)
    print("\n=== All ledger tests passed ===")


if __name__ == "__main__":
    run_ledger_tests()
