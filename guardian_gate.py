#!/usr/bin/env python3
"""Sentinel Guardian Gate — out-of-process policy enforcement service.

Agents must call this service before executing any tool. The gate evaluates
the request against policies and returns allow/warn/ask/block.

This runs as a SEPARATE process from the agent, so a compromised agent cannot
bypass the policy check by calling tools directly.

Run: python3 guardian_gate.py
Port: 8098 (configurable via GUARDIAN_PORT env var)
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from sentinel_guardian import SentinelGuardian

PORT = int(os.getenv("GUARDIAN_PORT", "8098"))
GATE_API_KEY = os.getenv("GUARDIAN_API_KEY", "")

guardian = SentinelGuardian()


class GateHandler(BaseHTTPRequestHandler):
    def _check_auth(self):
        if not GATE_API_KEY:
            return True
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {GATE_API_KEY}":
            return True
        return False

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/evaluate":
            if not self._check_auth():
                self._respond(401, {"error": "Unauthorized"})
                return

            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._respond(400, {"error": "Invalid JSON"})
                return

            agent_id = data.get("agent_id", "unknown")
            tool_name = data.get("tool", "")
            params = data.get("params", {})

            if not tool_name:
                self._respond(400, {"error": "Missing 'tool' field"})
                return

            # Process through Guardian
            result = guardian.process_tool_call(agent_id, tool_name, params)

            # Send alert if blocked
            if result["decision"]["decision"] in ("block", "ask"):
                self._send_alert(agent_id, tool_name, result["decision"])

            self._respond(200, {
                "decision": result["decision"]["decision"],
                "reasons": result["decision"]["reasons"],
                "risk_level": result["event"]["risk_level"],
                "ledger_hash": result["ledger_entry"],
                "blast_radius": result["blast_radius"].get("risk_score", 0) if result["blast_radius"] else 0,
            })

        elif path == "/register":
            if not self._check_auth():
                self._respond(401, {"error": "Unauthorized"})
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._respond(400, {"error": "Invalid JSON"})
                return

            guardian.register_agent(
                agent_id=data.get("agent_id", "unknown"),
                name=data.get("name", "Unknown"),
                owner=data.get("owner", "Unknown"),
                tools=data.get("tools", []),
                permissions=data.get("permissions", []),
                data_access=data.get("data_access", []),
            )
            self._respond(200, {"status": "registered", "agent_id": data.get("agent_id")})

        elif path == "/passport":
            if not self._check_auth():
                self._respond(401, {"error": "Unauthorized"})
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._respond(400, {"error": "Invalid JSON"})
                return
            passport = guardian.understand.get_passport(data.get("agent_id", ""))
            self._respond(200, passport)

        else:
            self._respond(404, {"error": "Not found"})

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            integrity = guardian.prove.verify_integrity()
            # Watchdog: check scanner health
            scanner_health = "unknown"
            try:
                import json as _json
                from pathlib import Path as _Path
                state_file = _Path("sentinel_state.json")
                if state_file.exists():
                    state = _json.loads(state_file.read_text())
                    last_run = state.get("last_run", "")
                    if last_run:
                        from datetime import datetime, timezone
                        try:
                            lr = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                            age = (datetime.now(timezone.utc) - lr).total_seconds()
                            if age < 3600:
                                scanner_health = "healthy"
                            elif age < 86400:
                                scanner_health = "stale"
                            else:
                                scanner_health = "dead"
                        except ValueError:
                            scanner_health = "unknown"
                    else:
                        scanner_health = "never_run"
                else:
                    scanner_health = "no_state_file"
            except Exception:
                scanner_health = "error"
            self._respond(200, {
                "status": "ok",
                "agents": len(guardian.understand.agents),
                "events": len(guardian.observe.events),
                "ledger": integrity,
                "scanner_health": scanner_health,
            })
        elif path == "/status":
            self._respond(200, guardian.get_status())
        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_alert(self, agent_id, tool_name, decision):
        """Send alert for blocked/asked actions."""
        try:
            import requests
            token = os.getenv("TELEGRAM_BOT_TOKEN", "")
            chat = os.getenv("TELEGRAM_CHAT_ID", "")
            if token and chat:
                msg = f"GUARDIAN ALERT: {decision['decision'].upper()} — {tool_name} by {agent_id}\nReasons: {', '.join(decision['reasons'])}"
                requests.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": chat, "text": msg},
                    timeout=10, verify=True,
                )
        except Exception:
            pass

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), GateHandler)
    print(f"Guardian Gate running on http://0.0.0.0:{PORT}")
    print(f"Endpoints: POST /evaluate, /register, /passport | GET /health, /status")
    server.serve_forever()
