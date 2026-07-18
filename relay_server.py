# relay_server.py — 24/7 relay between your bot (laptop) and the dashboard.
# Deploy this on Render (or Railway) as a free Web Service.
#
# WHAT IT DOES
#   - Your bot (master_bot.py + relay_sync.py) PUSHES its status here every ~15s.
#   - The dashboard reads status from HERE, not from your laptop directly.
#   - So the dashboard stays reachable 24/7 even when your laptop is off —
#     it will just show "Bot Offline" plus the last data it received.
#   - This server never logs into managment.io itself, so there's no geo-IP
#     concern with the management portal at all.
#
# ENV VARS TO SET ON RENDER
#   FINOPS_PASSWORD   -> dashboard/operator login password (team uses this)
#   RELAY_BOT_SECRET  -> a long random secret ONLY your bot knows (not the
#                        same as the dashboard password!)
#   DATABASE_URL      -> (optional but recommended) attach a free Render
#                        Postgres and Render will inject this automatically.
#                        Without it, state is kept in memory only and will
#                        reset if this service sleeps/restarts.
#
# RUN LOCALLY (for testing): uvicorn relay_server:app --port 9000

import os
import json
import time
import secrets
import threading
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

OPERATOR_PASSWORD = os.environ.get("FINOPS_PASSWORD", "Easylife786")
BOT_PUSH_SECRET = os.environ.get("RELAY_BOT_SECRET", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

BOT_ONLINE_THRESHOLD_SECONDS = 90  # no push in 90s => dashboard shows "offline"

app = FastAPI()
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Persistence layer: Postgres if DATABASE_URL is set (survives sleep/restart),
# otherwise an in-memory fallback (fine for local testing only).
# ---------------------------------------------------------------------------
_mem_lock = threading.Lock()
_mem_snapshot: dict = {}
_mem_last_seen: float = 0.0


def _pg_conn():
    import psycopg2
    return psycopg2.connect(DATABASE_URL, sslmode="require")


def _init_db():
    if not DATABASE_URL:
        return
    conn = _pg_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS bot_state (
            id INT PRIMARY KEY,
            snapshot TEXT NOT NULL,
            last_seen DOUBLE PRECISION NOT NULL
        )
        """
    )
    cur.execute(
        "INSERT INTO bot_state (id, snapshot, last_seen) VALUES (1, '{}', 0) "
        "ON CONFLICT (id) DO NOTHING"
    )
    conn.commit()
    cur.close()
    conn.close()


if DATABASE_URL:
    _init_db()


def save_snapshot(snapshot: dict):
    now = time.time()
    if DATABASE_URL:
        conn = _pg_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE bot_state SET snapshot=%s, last_seen=%s WHERE id=1",
            (json.dumps(snapshot), now),
        )
        conn.commit()
        cur.close()
        conn.close()
    else:
        with _mem_lock:
            global _mem_snapshot, _mem_last_seen
            _mem_snapshot = snapshot
            _mem_last_seen = now


def load_snapshot() -> tuple[dict, float]:
    if DATABASE_URL:
        conn = _pg_conn()
        cur = conn.cursor()
        cur.execute("SELECT snapshot, last_seen FROM bot_state WHERE id=1")
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row:
            return json.loads(row[0]), row[1]
        return {}, 0.0
    else:
        with _mem_lock:
            return dict(_mem_snapshot), _mem_last_seen


# Command queue (dashboard -> bot). Kept in memory: if this service restarts
# mid-command the operator just clicks the button again, which is fine.
_cmd_lock = threading.Lock()
_commands: list = []


# ---------------------------------------------------------------------------
# Auth: two SEPARATE secrets.
#   - OPERATOR_PASSWORD: humans logging into the dashboard.
#   - BOT_PUSH_SECRET: only your bot uses this to push status / pull commands.
# ---------------------------------------------------------------------------
TOKENS: dict = {}
TOKEN_TTL_SECONDS = 12 * 60 * 60

_FAILED_ATTEMPTS: dict = {}
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 300


def _check_throttle(key: str):
    now = time.time()
    count, first_ts = _FAILED_ATTEMPTS.get(key, (0, now))
    if now - first_ts > _WINDOW_SECONDS:
        count, first_ts = 0, now
    if count >= _MAX_ATTEMPTS:
        raise HTTPException(429, "Too many failed attempts. Try again later.")
    return count, first_ts


def _record_failure(key: str):
    count, first_ts = _FAILED_ATTEMPTS.get(key, (0, time.time()))
    _FAILED_ATTEMPTS[key] = (count + 1, first_ts)


def _clear_failures(key: str):
    _FAILED_ATTEMPTS.pop(key, None)


def require_operator(authorization: str = Header(default="")):
    tok = authorization.removeprefix("Bearer ").strip()
    expiry = TOKENS.get(tok)
    if expiry is None or expiry < time.time():
        TOKENS.pop(tok, None)
        raise HTTPException(401, "Unauthorized")


def require_bot(x_bot_secret: str = Header(default="")):
    if not BOT_PUSH_SECRET or not secrets.compare_digest(x_bot_secret, BOT_PUSH_SECRET):
        raise HTTPException(401, "Unauthorized bot")


# ---------------------------------------------------------------------------
# Dashboard-facing endpoints
# ---------------------------------------------------------------------------
class LoginIn(BaseModel):
    password: str


@app.post("/api/login")
def login(body: LoginIn):
    key = "global"
    _check_throttle(key)
    if not secrets.compare_digest(body.password, OPERATOR_PASSWORD):
        _record_failure(key)
        raise HTTPException(401, "Invalid password")
    _clear_failures(key)
    tok = secrets.token_urlsafe(24)
    TOKENS[tok] = time.time() + TOKEN_TTL_SECONDS
    return {"token": tok}


@app.get("/api/status", dependencies=[Depends(require_operator)])
def status():
    snap, last_seen = load_snapshot()
    online = (time.time() - last_seen) < BOT_ONLINE_THRESHOLD_SECONDS if last_seen else False
    return {
        "bot_online": online,
        "last_seen_seconds_ago": int(time.time() - last_seen) if last_seen else None,
        "internet_online": snap.get("internet_online", False),
        "balance": snap.get("balance", 0.0),
        "approved_today": snap.get("approved_today", 0),
        "pending_withdrawals_total": snap.get("pending_withdrawals_total", "0k"),
        "success_rate": snap.get("success_rate", 0.0),
    }


@app.get("/api/logs", dependencies=[Depends(require_operator)])
def logs():
    snap, _ = load_snapshot()
    return {"logs": snap.get("logs", [])}


@app.get("/api/pending", dependencies=[Depends(require_operator)])
def pending():
    snap, _ = load_snapshot()
    pending_map = snap.get("pending", {})
    now = time.time()
    items = []
    for tid, r in pending_map.items():
        age_s = int(now - r.get("ts", now))
        age = f"{age_s // 60}m {age_s % 60:02d}s" if age_s >= 60 else f"{age_s}s"
        items.append({"tid": tid, "amount": r.get("amount"), "status": r.get("status"), "age": age})
    return {"items": items}


class ApproveIn(BaseModel):
    tid: str


@app.post("/api/approve", dependencies=[Depends(require_operator)])
def approve(body: ApproveIn):
    with _cmd_lock:
        _commands.append({"cmd": "approve", "arg": body.tid.strip()})
    return {"ok": True}


@app.post("/api/refresh-pending", dependencies=[Depends(require_operator)])
def refresh():
    with _cmd_lock:
        _commands.append({"cmd": "refresh", "arg": None})
    return {"ok": True}


@app.post("/api/ticket-check", dependencies=[Depends(require_operator)])
def ticket():
    with _cmd_lock:
        _commands.append({"cmd": "ticket_check", "arg": None})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Bot-facing endpoints (separate secret, not the dashboard password)
# ---------------------------------------------------------------------------
@app.post("/api/bot/push", dependencies=[Depends(require_bot)])
def bot_push(snapshot: dict):
    save_snapshot(snapshot)
    return {"ok": True}


@app.get("/api/bot/commands", dependencies=[Depends(require_bot)])
def bot_pull_commands():
    with _cmd_lock:
        drained, _commands[:] = list(_commands), []
    return {"commands": drained}


@app.get("/")
def root():
    return {"ok": True, "service": "finops-relay"}
