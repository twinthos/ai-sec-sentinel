#!/usr/bin/env python3
"""Read-only local dashboard for Sentinel scan state.

Never offers a scan-triggering HTTP endpoint. Use the CLI to run scans.
Do not expose this stdlib HTTP server directly to the Internet.
"""
import hmac
import html
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

DATA_DIR = Path(os.getenv("SENTINEL_DATA_DIR") or (Path.home() / ".local" / "share" / "twinthos-sentinel"))
STATE_FILE = DATA_DIR / "sentinel_state.json"
CONFIG_FILE = Path(__file__).with_name("sentinel_config.json")
FEEDBACK_FILE = DATA_DIR / "sentinel_feedback.json"
API_KEY = os.getenv("DASHBOARD_API_KEY", "")
HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8080"))


def load_json(path):
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        return result if isinstance(result, dict) else {}
    except (OSError, ValueError):
        return {}


def get_status():
    state, config = load_json(STATE_FILE), load_json(CONFIG_FILE)
    stamp = state.get("last_successful_run")
    age = None
    if isinstance(stamp, str):
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(stamp.replace("Z", "+00:00"))).total_seconds()
        except (ValueError, TypeError):
            pass
    max_age = max(300, int(config.get("scan_interval_minutes", 60)) * 180)
    healthy = age is not None and 0 <= age <= max_age
    return {
        "status": "healthy" if healthy else "degraded",
        "version": str(config.get("version", "unknown")),
        "last_successful_scan": stamp,
        "age_seconds": int(age) if age is not None else None,
        "seen_threats": len(state.get("seen", [])),
        "seen_news": len(state.get("seen_news", [])),
        "last_scan_stats": state.get("last_scan_stats", {}),
    }


def render_dashboard():
    data = get_status()
    esc = lambda x: html.escape(str(x), quote=True)
    status = esc(data["status"])
    stats = data.get("last_scan_stats", {})
    rows = "".join(
        f"<tr><th>{esc(key)}</th><td>{esc(value)}</td></tr>"
        for key, value in sorted(stats.items()) if isinstance(value, (str, int, float, bool))
    ) if isinstance(stats, dict) else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Twinthos Sentinel — Local status</title>
<style>
:root{{color-scheme:dark}}body{{font:16px system-ui,sans-serif;background:#111;color:#eee;max-width:780px;margin:auto;padding:3rem 1.5rem;line-height:1.6}}
h1{{font-size:2rem}}p,small{{color:#aaa}}.panel{{background:#1b1b1b;border:1px solid #444;border-radius:10px;padding:1.5rem;margin:1rem 0}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:.6rem;border-bottom:1px solid #444;word-break:break-word}}
a{{color:#ddd}}
</style></head><body>
<h1>Twinthos Sentinel</h1>
<p>Read-only status. This page does not run scans or prove end-to-end alert delivery.</p>
<div class="panel"><strong>Status: {status}</strong>
<p>Last completed live scan: {esc(data["last_successful_scan"] or "Never")}</p>
<p>Tracked CVEs: {esc(data["seen_threats"])} · Tracked news: {esc(data["seen_news"])}</p></div>
<div class="panel"><h2>Last scan</h2><table>{rows or "<tr><td>No scan statistics yet</td></tr>"}</table></div>
<small>v{esc(data["version"])} · API: /api/status · CLI: python3 ai_sec_sentinel.py --health</small>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _respond(self, status, payload, content_type):
        data = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        expected = "Bearer " + API_KEY
        provided = self.headers.get("Authorization", "")
        if not API_KEY or not hmac.compare_digest(provided, expected):
            self._respond(401, '{"error":"Unauthorized"}', "application/json")
            return
        path = urlparse(self.path).path
        if path == "/api/status":
            self._respond(200, json.dumps(get_status()), "application/json")
        elif path == "/":
            self._respond(200, render_dashboard(), "text/html; charset=utf-8")
        else:
            self._respond(404, '{"error":"Not found"}', "application/json")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    if len(API_KEY) < 24:
        raise SystemExit("DASHBOARD_API_KEY must be configured (at least 24 characters)")
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Read-only dashboard listening on {HOST}:{PORT}")
    server.serve_forever()
