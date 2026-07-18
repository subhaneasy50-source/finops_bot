# relay_server.py — Flask version for PythonAnywhere (free tier, no credit card,
# no sleep/spin-down). Functionally identical to the FastAPI version, just
# rewritten as WSGI since PythonAnywhere's free tier only supports Flask/Django.
#
# WHAT IT DOES
#   - Your bot (master_bot.py + relay_sync.py) PUSHES its status here every ~15s.
#   - The dashboard reads status from HERE, not from your laptop directly.
#   - Stays reachable 24/7 even when your laptop is off — shows "Bot Offline"
#     plus the last data it received.
#   - Never logs into managment.io itself, so there's no geo-IP concern there.
#
# SET THESE (edit directly in this file, or in your PythonAnywhere WSGI config
# file before importing this module — free tier doesn't have an env-var UI):
#   FINOPS_PASSWORD   -> dashboard/operator login password
#   RELAY_BOT_SECRET  -> long random secret ONLY your bot knows

import os
import json
import time
import secrets
import threading
from flask import Flask, request, jsonify

OPERATOR_PASSWORD = os.environ.get("FINOPS_PASSWORD", "Easylife786")
BOT_PUSH_SECRET = os.environ.get("RELAY_BOT_SECRET", "CHANGE-THIS-TO-A-LONG-RANDOM-SECRET")

BOT_ONLINE_THRESHOLD_SECONDS = 90

# State persists to a JSON file on PythonAnywhere's disk (which is NOT wiped
# between requests, unlike Render/Koyeb free tiers) so last-known data
# survives even long laptop-off periods.
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay_state.json")

app = Flask(__name__)

_lock = threading.Lock()
_commands: list = []


def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "*"
    return resp


@app.after_request
def add_cors(resp):
    return _cors(resp)


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return _cors(app.make_default_options_response())


def save_snapshot(snapshot: dict):
    with _lock:
        payload = {"snapshot": snapshot, "last_seen": time.time()}
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f)


def load_snapshot():
    with _lock:
        if not os.path.exists(STATE_FILE):
            return {}, 0.0
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                payload = json.load(f)
            return payload.get("snapshot", {}), payload.get("last_seen", 0.0)
        except Exception:
            return {}, 0.0


# ---- auth ----
TOKENS: dict = {}
TOKEN_TTL_SECONDS = 12 * 60 * 60
_FAILED_ATTEMPTS: dict = {}
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 300


def _check_throttle():
    now = time.time()
    count, first_ts = _FAILED_ATTEMPTS.get("global", (0, now))
    if now - first_ts > _WINDOW_SECONDS:
        count, first_ts = 0, now
    return count < _MAX_ATTEMPTS


def _record_failure():
    count, first_ts = _FAILED_ATTEMPTS.get("global", (0, time.time()))
    _FAILED_ATTEMPTS["global"] = (count + 1, first_ts)


def _clear_failures():
    _FAILED_ATTEMPTS.pop("global", None)


def _operator_ok() -> bool:
    tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    expiry = TOKENS.get(tok)
    if expiry is None or expiry < time.time():
        TOKENS.pop(tok, None)
        return False
    return True


def _bot_ok() -> bool:
    secret = request.headers.get("X-Bot-Secret", "")
    return bool(BOT_PUSH_SECRET) and secrets.compare_digest(secret, BOT_PUSH_SECRET)


# ---- dashboard endpoints ----
@app.route("/api/login", methods=["POST"])
def login():
    if not _check_throttle():
        return jsonify({"detail": "Too many failed attempts. Try again later."}), 429
    body = request.get_json(force=True, silent=True) or {}
    password = body.get("password", "")
    if not secrets.compare_digest(password, OPERATOR_PASSWORD):
        _record_failure()
        return jsonify({"detail": "Invalid password"}), 401
    _clear_failures()
    tok = secrets.token_urlsafe(24)
    TOKENS[tok] = time.time() + TOKEN_TTL_SECONDS
    return jsonify({"token": tok})


@app.route("/api/status", methods=["GET"])
def status():
    if not _operator_ok():
        return jsonify({"detail": "Unauthorized"}), 401
    snap, last_seen = load_snapshot()
    online = (time.time() - last_seen) < BOT_ONLINE_THRESHOLD_SECONDS if last_seen else False
    return jsonify({
        "bot_online": online,
        "last_seen_seconds_ago": int(time.time() - last_seen) if last_seen else None,
        "internet_online": snap.get("internet_online", False),
        "balance": snap.get("balance", 0.0),
        "approved_today": snap.get("approved_today", 0),
        "pending_withdrawals_total": snap.get("pending_withdrawals_total", "0k"),
        "success_rate": snap.get("success_rate", 0.0),
    })


@app.route("/api/logs", methods=["GET"])
def logs():
    if not _operator_ok():
        return jsonify({"detail": "Unauthorized"}), 401
    snap, _ = load_snapshot()
    return jsonify({"logs": snap.get("logs", [])})


@app.route("/api/pending", methods=["GET"])
def pending():
    if not _operator_ok():
        return jsonify({"detail": "Unauthorized"}), 401
    snap, _ = load_snapshot()
    now = time.time()
    items = []
    for tid, r in snap.get("pending", {}).items():
        age_s = int(now - r.get("ts", now))
        age = f"{age_s // 60}m {age_s % 60:02d}s" if age_s >= 60 else f"{age_s}s"
        items.append({"tid": tid, "amount": r.get("amount"), "status": r.get("status"), "age": age})
    return jsonify({"items": items})


@app.route("/api/approve", methods=["POST"])
def approve():
    if not _operator_ok():
        return jsonify({"detail": "Unauthorized"}), 401
    body = request.get_json(force=True, silent=True) or {}
    tid = (body.get("tid") or "").strip()
    with _lock:
        _commands.append({"cmd": "approve", "arg": tid})
    return jsonify({"ok": True})


@app.route("/api/refresh-pending", methods=["POST"])
def refresh():
    if not _operator_ok():
        return jsonify({"detail": "Unauthorized"}), 401
    with _lock:
        _commands.append({"cmd": "refresh", "arg": None})
    return jsonify({"ok": True})


@app.route("/api/ticket-check", methods=["POST"])
def ticket():
    if not _operator_ok():
        return jsonify({"detail": "Unauthorized"}), 401
    with _lock:
        _commands.append({"cmd": "ticket_check", "arg": None})
    return jsonify({"ok": True})


# ---- bot endpoints ----
@app.route("/api/bot/push", methods=["POST"])
def bot_push():
    if not _bot_ok():
        return jsonify({"detail": "Unauthorized bot"}), 401
    snapshot = request.get_json(force=True, silent=True) or {}
    save_snapshot(snapshot)
    return jsonify({"ok": True})


@app.route("/api/bot/commands", methods=["GET"])
def bot_pull_commands():
    if not _bot_ok():
        return jsonify({"detail": "Unauthorized bot"}), 401
    with _lock:
        drained, _commands[:] = list(_commands), []
    return jsonify({"commands": drained})


@app.route("/", methods=["GET"])
def root():
    return jsonify({"ok": True, "service": "finops-relay"})


# PythonAnywhere's WSGI config file expects a module-level `application`.
application = app

if __name__ == "__main__":
    app.run(port=9000, debug=True)
