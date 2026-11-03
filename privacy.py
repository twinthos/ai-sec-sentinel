#!/usr/bin/env python3
"""Privacy and secret protection for Twinthos Sentinel.

Local-first: no raw lockfile upload without explicit consent.
Redact secrets, credentials, PII before logging/reporting/alerting.
Restricted file permissions. Configurable retention/deletion.
"""

import os
import re
import stat
import hashlib
from pathlib import Path

# Patterns for secrets/credentials/PII
SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*["\']?([A-Za-z0-9_\-./+=]{8,})', '[REDACTED]'),
    (r'(?:Bearer|Basic)\s+[A-Za-z0-9._\-+/=]+', '[REDACTED]'),
    (r'ghp_[A-Za-z0-9]{36,}', '[REDACTED_GITHUB_TOKEN]'),
    (r'sk-[A-Za-z0-9]{20,}', '[REDACTED_API_KEY]'),
    (r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_KEY]'),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]'),
    (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]'),
    (r'\b\d{16}\b', '[REDACTED_CARD]'),
]

# Files that should never be transmitted
SENSITIVE_FILES = {
    ".env", ".env.*",
    "id_rsa", "id_ed25519", "id_ecdsa",
    "credentials.json", "service-account.json",
    "*.pem", "*.key", "*.p12", "*.pfx",
}


def redact_text(text: str) -> str:
    """Redact secrets, credentials and PII from text."""
    if not text:
        return text
    result = text
    for pattern, replacement in SECRET_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def redact_dict(d: dict, depth: int = 0) -> dict:
    """Recursively mask sensitive values, including lists within lists.

    A depth limit or cyclic container is replaced with an explicit marker, not
    returned unchanged. This is best-effort privacy hygiene, not DLP assurance.
    """
    active = set()

    def scrub(value, level):
        if level > 10:
            return "[REDACTED: nesting limit]"
        if isinstance(value, (dict, list, tuple)):
            identity = id(value)
            if identity in active:
                return "[REDACTED: cyclic container]"
            active.add(identity)
            try:
                if isinstance(value, dict):
                    cleaned = {}
                    for k, v in value.items():
                        key_lower = str(k).lower()
                        if any(word in key_lower for word in ("password", "secret", "token", "key", "credential", "auth")):
                            cleaned[k] = "[REDACTED]"
                        else:
                            cleaned[k] = scrub(v, level + 1)
                    return cleaned
                return [scrub(item, level + 1) for item in value]
            finally:
                active.remove(identity)
        if isinstance(value, str):
            return redact_text(value)
        return value

    return scrub(d, depth)


def is_sensitive_file(path: str) -> bool:
    """Check if a file path points to a sensitive file."""
    name = Path(path).name.lower()
    for pattern in SENSITIVE_FILES:
        if "*" in pattern:
            import fnmatch
            if fnmatch.fnmatch(name, pattern):
                return True
        elif name == pattern:
            return True
    return False


def set_restricted_permissions(path: str):
    """Set file permissions to owner-only (0600)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def secure_write(path: str, content: str):
    """Write file with restricted permissions."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    set_restricted_permissions(path)


def secure_read(path: str) -> str:
    """Read file, verify permissions."""
    p = Path(path)
    if not p.exists():
        return ""
    # Check permissions
    mode = p.stat().st_mode
    if mode & stat.S_IROTH or mode & stat.S_IWOTH:
        # World-readable/writable — warn
        pass
    return p.read_text()


def can_upload_lockfile(consent: bool, local_only: bool) -> bool:
    """Determine if lockfile upload is permitted."""
    if local_only:
        return False
    if not consent:
        return False
    return True


def explain_external_services() -> str:
    """Explain which external services receive data."""
    return """
Quickstart and synthetic demonstrations run offline. Live feed scanning needs Internet access.
Services that may receive data:
1. cve.now: feed requests, and full raw lockfile content only if deliberately enabled.
2. OSV.dev: package names, pinned versions and ecosystems for dependency lookups.
3. CISA and FIRST EPSS: feed requests or CVE identifiers.
4. Telegram, Slack and Discord: configured notification messages, descriptions and links.
5. Configured RSS sites: feed requests.
Network providers can also observe request metadata. A dry-run disables notifications,
not external feed or OSV requests. Redaction is best effort, not comprehensive DLP.
No general offline-only flag exists for the live scanner. Review destinations and data first.
"""


def cleanup_old_state(state_dir: str, retention_days: int = 30):
    """Delete state files older than retention period."""
    import time
    cutoff = time.time() - (retention_days * 86400)
    for p in Path(state_dir).glob("*.json"):
        if p.stat().st_mtime < cutoff:
            p.unlink()
    for p in Path(state_dir).glob("*.db"):
        if p.stat().st_mtime < cutoff:
            p.unlink()


def run_privacy_tests():
    print("=== Privacy Tests ===")
    
    # Test 1: Redaction
    print("\n1. Secret redaction:")
    text = "api_key=sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
    redacted = redact_text(text)
    assert "sk-abc" not in redacted
    assert "[REDACTED" in redacted
    print(f"   PASS: {redacted}")
    
    # Test 2: Email redaction
    print("\n2. Email redaction:")
    text = "Contact user@example.com for details"
    redacted = redact_text(text)
    assert "user@example.com" not in redacted
    print(f"   PASS: {redacted}")
    
    # Test 3: Dict redaction
    print("\n3. Dict redaction:")
    d = {"api_key": "secret123", "name": "test", "nested": {"password": "pass456"}}
    rd = redact_dict(d)
    assert rd["api_key"] == "[REDACTED]"
    assert rd["nested"]["password"] == "[REDACTED]"
    assert rd["name"] == "test"
    print("   PASS: nested secrets redacted")
    
    # Test 4: Local-only mode blocks upload
    print("\n4. Local-only mode:")
    assert can_upload_lockfile(True, True) == False
    assert can_upload_lockfile(True, False) == True
    assert can_upload_lockfile(False, False) == False
    print("   PASS: local-only blocks all uploads")
    
    # Test 5: Sensitive file detection
    print("\n5. Sensitive file detection:")
    assert is_sensitive_file(".env") == True
    assert is_sensitive_file("id_rsa") == True
    assert is_sensitive_file("requirements.txt") == False
    print("   PASS: sensitive files detected")
    
    # Test 6: File permissions
    print("\n6. File permissions:")
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
    secure_write(path, "test")
    mode = os.stat(path).st_mode
    assert not (mode & stat.S_IROTH)
    assert not (mode & stat.S_IWOTH)
    os.unlink(path)
    print("   PASS: restricted permissions set")
    
    print("\n=== All privacy tests passed ===")


if __name__ == "__main__":
    run_privacy_tests()
