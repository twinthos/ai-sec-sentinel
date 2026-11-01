#!/usr/bin/env python3
"""Twinthos Sentinel — Web Dashboard.

Stdlib-only HTTP server. No external dependencies.
Run: python3 dashboard.py
Open: http://localhost:8080
"""

import json
import os
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

STATE_FILE = Path("sentinel_state.json")
CONFIG_FILE = Path("sentinel_config.json")
FEEDBACK_FILE = Path("sentinel_feedback.json")


def load_json(path):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {}


def render_dashboard():
    state = load_json(STATE_FILE)
    config = load_json(CONFIG_FILE)
    feedback = load_json(FEEDBACK_FILE)

    seen_count = len(state.get("seen", []))
    risk_history = state.get("risk_history", [])
    last_run = state.get("last_run", "Never")
    ignored = sum(1 for v in feedback.values() if v.get("action") == "ignored")
    useful = sum(1 for v in feedback.values() if v.get("action") == "useful")

    risk_rows = "".join(
        f"<tr><td>{r.get('timestamp', '?')[:19]}</td><td>{r.get('score', '?')}/100</td><td>{r.get('level', '?')}</td></tr>"
        for r in risk_history[-10:]
    ) or "<tr><td colspan='3'>No risk history yet. Run a scan with --risk-report.</td></tr>"

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Twinthos Sentinel Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 20px; }}
        .card {{ background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; margin: 10px 0; }}
        .metric {{ display: inline-block; margin: 10px 20px; text-align: center; }}
        .metric .value {{ font-size: 2em; font-weight: bold; color: #00ff88; }}
        .metric .label {{ font-size: 0.8em; color: #888; }}
        h1 {{ color: #00ff88; margin: 0; }}
        h2 {{ color: #ccc; border-bottom: 1px solid #333; padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        td, th {{ padding: 8px; text-align: left; border-bottom: 1px solid #222; }}
        a {{ color: #00ff88; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
        .badge.ok {{ background: #003322; color: #00ff88; }}
        .badge.warn {{ background: #332200; color: #ffaa00; }}
    </style>
</head>
<body>
    <h1>Twinthos Sentinel</h1>
    <p>Continuous threat intelligence for organizations &mdash; v{config.get('version', 'unknown')}</p>

    <div class="card">
        <h2>Status</h2>
        <div class="metric"><div class="value">{seen_count}</div><div class="label">Threats Seen</div></div>
        <div class="metric"><div class="value">{useful}</div><div class="label">Marked Useful</div></div>
        <div class="metric"><div class="value">{ignored}</div><div class="label">Marked Ignored</div></div>
        <div class="metric"><div class="value">{last_run[:19] if last_run != 'Never' else 'Never'}</div><div class="label">Last Run</div></div>
    </div>

    <div class="card">
        <h2>Configuration</h2>
        <p>Alert min severity: {config.get('alert_min_severity', 1)}</p>
        <p>Lockfile upload: {'Enabled' if config.get('allow_lockfile_upload') else 'Disabled (consent required)'}</p>
        <p>Auto-remediate: {'Enabled' if config.get('auto_remediate') else 'Disabled'}</p>
        <p>Webhook: {'Configured' if config.get('webhook_url') else 'Not configured'}</p>
    </div>

    <div class="card">
        <h2>Risk History</h2>
        <table>
            <tr><th>Time</th><th>Score</th><th>Level</th></tr>
            {risk_rows}
        </table>
    </div>

    <div class="card">
        <h2>Quick Actions</h2>
        <p><a href="/api/scan">Run Scan (dry)</a> | <a href="/api/status">API Status</a></p>
    </div>
</body>
</html>"""


DASHBOARD_API_KEY = os.getenv("DASHBOARD_API_KEY", "")

class Handler(BaseHTTPRequestHandler):
    def _check_auth(self):
        if not DASHBOARD_API_KEY:
            return True  # No key configured = open (dev mode)
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {DASHBOARD_API_KEY}":
            return True
        # Also check query param for browser access
        from urllib.parse import parse_qs
        qs = parse_qs(urlparse(self.path).query)
        if qs.get("key", [""])[0] == DASHBOARD_API_KEY:
            return True
        return False

    def do_GET(self):
        path = urlparse(self.path).path
        if path not in ("/",) and not self._check_auth():
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized. Set DASHBOARD_API_KEY or pass ?key=YOUR_KEY"}')
            return
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(render_dashboard().encode())
        elif path == "/api/status":
            state = load_json(STATE_FILE)
            config = load_json(CONFIG_FILE)
            import json as _j
            data = _j.dumps({
                "status": "ok",
                "version": config.get("version", "unknown"),
                "threats_seen": len(state.get("seen", [])),
                "last_run": state.get("last_run"),
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data.encode())
        elif path == "/api/scan":
            result = subprocess.run(
                ["python3", "ai_sec_sentinel.py", "--dry-run", "--since-hours", "24", "--feed-limit", "20"],
                capture_output=True, text=True, timeout=120,
            )
            import json as _j
            data = _j.dumps({
                "exit_code": result.returncode,
                "output": result.stdout[-2000:],
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress request logging


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"Dashboard running on http://0.0.0.0:{port}")
    server.serve_forever()
