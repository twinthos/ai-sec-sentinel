#!/usr/bin/env python3
"""Authenticated policy-evaluation API for Sentinel Guardian.

IMPORTANT: /evaluate returns a decision; it does not execute or intercept tools.
The agent's tool-execution adapter must enforce this decision and must have no
alternative path to the protected tools. 'ask' is NOT an approval.
"""

import hmac
import json
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from sentinel_guardian import SentinelGuardian

PORT = int(os.getenv("GUARDIAN_PORT", "8098"))
HOST = os.getenv("GUARDIAN_HOST", "127.0.0.1")
GATE_API_KEY = os.getenv("GUARDIAN_API_KEY", "")
ADMIN_API_KEY = os.getenv("GUARDIAN_ADMIN_API_KEY", "")
MAX_BODY_BYTES = 64 * 1024

guardian = SentinelGuardian()


class GateHandler(BaseHTTPRequestHandler):
    def _check_auth(self, admin=False):
        auth = self.headers.get("Authorization", "")
        key = ADMIN_API_KEY if admin else GATE_API_KEY
        expected = "Bearer " + key
        return bool(key) and hmac.compare_digest(auth, expected)

    def _read_json(self):
        raw_length = self.headers.get("Content-Length", "")
        try:
            length = int(raw_length)
        except (ValueError, TypeError):
            self._respond(411, {"error": "Content-Length required"})
            return None
        if length < 1 or length > MAX_BODY_BYTES:
            self._respond(413, {"error": "Invalid or oversized request"})
            return None
        try:
            data = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._respond(400, {"error": "Invalid JSON"})
            return None
        if not isinstance(data, dict):
            self._respond(400, {"error": "Expected JSON object"})
            return None
        return data

    def _authorized(self, admin=False):
        if not self._check_auth(admin=admin):
            self._respond(401, {"error": "Unauthorized"})
            return False
        return True

    def do_POST(self):
        path = urlparse(self.path).path
        if not self._authorized(admin=(path == "/register")):
            return
        if path not in ("/evaluate", "/register", "/passport"):
            self._respond(404, {"error": "Not found"})
            return
        data = self._read_json()
        if data is None:
            return

        agent_id = data.get("agent_id", "")
        if not isinstance(agent_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", agent_id):
            self._respond(400, {"error": "Invalid agent_id"})
            return

        if path == "/evaluate":
            tool_name = data.get("tool")
            params = data.get("params", {})
            if not isinstance(tool_name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", tool_name):
                self._respond(400, {"error": "Invalid tool"})
                return
            if not isinstance(params, dict):
                self._respond(400, {"error": "params must be an object"})
                return
            try:
                result = guardian.process_tool_call(agent_id, tool_name, params)
            except Exception:
                # Do not return an allow decision if policy/audit persistence fails.
                self._respond(503, {"error": "Policy evaluation unavailable"})
                return
            decision = result["decision"]
            if decision["decision"] in ("block", "ask"):
                self._send_alert(agent_id, tool_name, decision)
            self._respond(200, {
                "decision": decision["decision"],
                "reasons": decision["reasons"],
                "risk_level": result["event"]["risk_level"],
                "ledger_hash": result["ledger_entry"],
                "blast_radius": result["blast_radius"].get("risk_score", 0) if result["blast_radius"] else 0,
            })
            return

        if path == "/register":
            for key in ("tools", "permissions", "data_access"):
                if not isinstance(data.get(key, []), list) or not all(isinstance(v, str) for v in data.get(key, [])):
                    self._respond(400, {"error": f"{key} must be a string list"})
                    return
            try:
                guardian.register_agent(
                    agent_id=agent_id,
                    name=str(data.get("name", agent_id))[:128],
                    owner=str(data.get("owner", "Unknown"))[:128],
                    tools=data.get("tools", []),
                    permissions=data.get("permissions", []),
                    data_access=data.get("data_access", []),
                )
            except Exception:
                self._respond(503, {"error": "Registration unavailable"})
                return
            self._respond(200, {"status": "registered", "agent_id": agent_id})
            return

        self._respond(200, guardian.understand.get_passport(agent_id))

    def do_GET(self):
        if not self._authorized():
            return
        path = urlparse(self.path).path
        if path == "/health":
            integrity = guardian.prove.verify_integrity()
            self._respond(200 if integrity.get("status") in ("intact", "empty") else 503, {
                "status": "ok" if integrity.get("status") in ("intact", "empty") else "degraded",
                "ledger": integrity,
            })
        elif path == "/status":
            self._respond(200, guardian.get_status())
        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code, data):
        output = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(output)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(output)

    def _send_alert(self, agent_id, tool_name, decision):
        try:
            import requests
            token = os.getenv("TELEGRAM_BOT_TOKEN", "")
            chat = os.getenv("TELEGRAM_CHAT_ID", "")
            if token and chat:
                msg = f"GUARDIAN ALERT: {decision['decision'].upper()} - {tool_name} by {agent_id}\nReasons: {', '.join(decision['reasons'])}"
                requests.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": chat, "text": msg}, timeout=10,
                )
        except Exception:
            pass

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    if not GATE_API_KEY or len(GATE_API_KEY) < 24:
        raise SystemExit("Set GUARDIAN_API_KEY (at least 24 characters) before starting Guardian Gate")
    if ADMIN_API_KEY and (len(ADMIN_API_KEY) < 24 or hmac.compare_digest(ADMIN_API_KEY, GATE_API_KEY)):
        raise SystemExit("GUARDIAN_ADMIN_API_KEY must be distinct from GUARDIAN_API_KEY and at least 24 characters")
    server = HTTPServer((HOST, PORT), GateHandler)
    print(f"Guardian policy API listening on {HOST}:{PORT} (authenticated)")
    server.serve_forever()
