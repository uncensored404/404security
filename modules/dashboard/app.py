import asyncio
import json
import time
from collections import deque
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from core.config import CONFIG
from core.database import Database

STATIC = Path(__file__).parent / "static"
DB = Database(CONFIG.get("logfire.db_path", "data/events.db"))
ALERT_RING = deque(maxlen=500)
WS_CLIENTS = set()

app = FastAPI(title="404SECURITY", docs_url="/api/docs")


def push_alert(source, severity, event_type, src_ip, details):
    entry = {"ts": time.time(), "source": source, "severity": severity,
             "type": event_type, "ip": src_ip, "details": details}
    ALERT_RING.appendleft(entry)
    payload = json.dumps(entry)
    for ws in list(WS_CLIENTS):
        try:
            asyncio.get_event_loop().create_task(ws.send_text(payload))
        except Exception:
            WS_CLIENTS.discard(ws)


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text()


@app.get("/api/alerts")
def alerts(limit: int = 100):
    return list(ALERT_RING)[:limit]


@app.get("/api/stats")
def stats():
    by_sev = {s: c for s, c in DB.query(
        "SELECT severity, COUNT(*) FROM events GROUP BY severity")}
    blocks = DB.query("SELECT COUNT(*) FROM blocks")[0][0]
    return {"by_severity": by_sev, "active_blocks": blocks,
            "events_total": DB.query("SELECT COUNT(*) FROM events")[0][0]}


@app.get("/api/blocks")
def blocks():
    return [{"ip": ip, "until": until, "reason": reason}
            for ip, until, reason in DB.query("SELECT ip, until, reason FROM blocks")]


@app.websocket("/ws")
async def ws(sock: WebSocket):
    await sock.accept()
    WS_CLIENTS.add(sock)
    try:
        while True:
            await sock.receive_text()
    except WebSocketDisconnect:
        WS_CLIENTS.discard(sock)
