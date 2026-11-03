"""Fail-closed task-context precheck for a trusted agent host.

This module authenticates a *host-provided* per-task capability and constrains
one of two named tool operations. It does not intercept tools, issue credentials,
verify DNS, enforce redirects, detect shadow AI or attest to external runtimes.
Untrusted model text must never obtain the task capability or choose host policy.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


class ContextConfigurationError(RuntimeError):
    """Required policy cannot be loaded or validated: deny all evaluations."""


IDENTITY = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
MAX_POLICY_BYTES = 65_536
MAX_TASKS = 128
SUPPORTED_TOOLS = {"file_read", "http_request"}


def _safe_path(value: object, directory: bool = False) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        return False
    if "\\" in value or "%" in value or value.startswith("/") or "\x00" in value:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return False
    raw = value[:-1] if directory and value.endswith("/") else value
    if not raw or any(p in ("", ".", "..") or p.startswith(".") for p in raw.split("/")):
        return False
    return True


def _host(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 2048:
        return None
    if any(ord(c) < 33 or ord(c) > 126 for c in value) or "\\" in value:
        return None
    try:
        url = urlsplit(value)
        host = url.hostname
        if (url.scheme != "https" or not host or not url.netloc or
                url.username is not None or url.password is not None or
                url.fragment or url.port not in (None, 443)):
            return None
        if host.endswith(".") or len(host) > 253:
            return None
        if not all(DNS_LABEL.fullmatch(part) for part in host.split(".")):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            return host
    except (ValueError, TypeError):
        return None


def _date(value: object) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 50:
        raise ValueError("Invalid timestamp")
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ValueError("Timestamps must have time zone")
    return ts.astimezone(timezone.utc)


def _validate_policy(policy: object) -> list[dict]:
    if not isinstance(policy, dict) or set(policy) != {"version", "tasks"}:
        raise ContextConfigurationError("Invalid task policy root")
    if type(policy["version"]) is not int or policy["version"] != 1:
        raise ContextConfigurationError("Unsupported policy version")
    tasks = policy["tasks"]
    if not isinstance(tasks, list) or len(tasks) > MAX_TASKS:
        raise ContextConfigurationError("Invalid task count")
    seen = set()
    try:
        for task in tasks:
            if not isinstance(task, dict) or set(task) != {
                "task_id", "agent_id", "capability_sha256", "not_before",
                "expires_at", "tools"
            }:
                raise ValueError("Invalid task fields")
            tid, aid = task["task_id"], task["agent_id"]
            if not isinstance(tid, str) or not IDENTITY.fullmatch(tid):
                raise ValueError("Invalid task id")
            if not isinstance(aid, str) or not IDENTITY.fullmatch(aid):
                raise ValueError("Invalid agent id")
            if tid in seen:
                raise ValueError("Duplicate task id")
            seen.add(tid)
            if not isinstance(task["capability_sha256"], str) or not SHA256.fullmatch(task["capability_sha256"]):
                raise ValueError("Invalid capability digest")
            if _date(task["not_before"]) >= _date(task["expires_at"]):
                raise ValueError("Invalid task lifetime")
            tools = task["tools"]
            if not isinstance(tools, dict) or not tools or not set(tools).issubset(SUPPORTED_TOOLS):
                raise ValueError("Unsupported tool policy")
            for tool, scope in tools.items():
                if not isinstance(scope, dict):
                    raise ValueError("Invalid scope")
                key = "path_prefixes" if tool == "file_read" else "hosts"
                if set(scope) != {key} or not isinstance(scope[key], list) or not 0 < len(scope[key]) <= 32:
                    raise ValueError("Missing explicit scope")
                for item in scope[key]:
                    if tool == "file_read":
                        if not _safe_path(item, directory=True) or not item.endswith("/"):
                            raise ValueError("Invalid read prefix")
                    elif (not isinstance(item, str) or not item.isascii() or
                          len(item) > 253 or item.lower() != item or
                          not all(DNS_LABEL.fullmatch(part) for part in item.split(".")) or
                          _is_ip(item)):
                        raise ValueError("Invalid hostname")
    except (ValueError, TypeError, OverflowError) as error:
        raise ContextConfigurationError("Invalid task policy") from error
    return tasks


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _load_policy(path: Path) -> list[dict]:
    # Protect against a replaced symlink and excessive data before parsing.
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ContextConfigurationError("No safe no-follow open available")
    try:
        fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_size > MAX_POLICY_BYTES or
                    st.st_mode & 0o077):
                raise ContextConfigurationError("Unsafe task policy file permissions or size")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_POLICY_BYTES + 1)
            if len(raw) > MAX_POLICY_BYTES:
                raise ContextConfigurationError("Task policy too large")
        finally:
            os.close(fd)
        return _validate_policy(json.loads(raw.decode("utf-8")))
    except ContextConfigurationError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContextConfigurationError("Could not load task policy") from error


class TaskContextFirewall:
    """Evaluate one proposed action against current host-owned task policy."""

    def __init__(self, policy_file: str | Path):
        self.policy_file = Path(policy_file)

    def evaluate(self, agent_id: object, task_id: object, capability: object,
                 tool: object, params: object, now: datetime | None = None) -> dict:
        tasks = _load_policy(self.policy_file)  # Live reload enables revocation.
        deny = lambda reason: {"decision": "block", "reason_code": reason}
        if (not isinstance(agent_id, str) or not IDENTITY.fullmatch(agent_id) or
                not isinstance(task_id, str) or not IDENTITY.fullmatch(task_id) or
                not isinstance(tool, str) or tool not in SUPPORTED_TOOLS or
                not isinstance(params, dict)):
            return deny("invalid_context")
        if (not isinstance(capability, str) or not 24 <= len(capability) <= 256 or
                not capability.isascii() or any(ord(ch) <= 32 or ord(ch) == 127 for ch in capability)):
            return deny("capability_required")
        task = next((item for item in tasks if item["task_id"] == task_id), None)
        if task is None or task["agent_id"] != agent_id:
            return deny("task_not_authorized")
        digest = hashlib.sha256(capability.encode("ascii")).hexdigest()
        if not hmac.compare_digest(digest, task["capability_sha256"]):
            return deny("capability_invalid")
        clock = now or datetime.now(timezone.utc)
        if clock.tzinfo is None or clock.utcoffset() is None:
            return deny("invalid_clock")
        utc_now = clock.astimezone(timezone.utc)
        if utc_now < _date(task["not_before"]) or utc_now >= _date(task["expires_at"]):
            return deny("task_inactive")
        scope = task["tools"].get(tool)
        if scope is None:
            return deny("tool_not_granted")
        if tool == "file_read":
            if set(params) != {"path"} or not _safe_path(params.get("path")):
                return deny("invalid_resource")
            if not any(params["path"].startswith(prefix) for prefix in scope["path_prefixes"]):
                return deny("path_out_of_scope")
        elif tool == "http_request":
            if set(params) != {"url"}:
                return deny("invalid_destination")
            host = _host(params["url"])
            if host is None or host not in scope["hosts"]:
                return deny("destination_out_of_scope")
        return {"decision": "allow", "reason_code": "task_scope_authorized"}
