import json
import sqlite3
import threading
import time
from contextlib import contextmanager


class Database:
    def __init__(self, path="data/events.db"):
        self.path = path
        self._lock = threading.Lock()
        self._init()

    def _init(self):
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, source TEXT, severity TEXT,
                event_type TEXT, src_ip TEXT, details TEXT);
            CREATE TABLE IF NOT EXISTS blocks(
                ip TEXT PRIMARY KEY, until REAL, reason TEXT);
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_src ON events(src_ip);
            """)

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=15)
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def insert_event(self, source, severity, event_type, src_ip, details):
        if not isinstance(details, str):
            details = json.dumps(details)
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO events(ts,source,severity,event_type,src_ip,details)"
                " VALUES(?,?,?,?,?,?)",
                (time.time(), source, severity, event_type, src_ip, details))

    def execute(self, sql, params=()):
        with self._lock, self._conn() as c:
            c.execute(sql, params)

    def query(self, sql, params=()):
        with self._conn() as c:
            return c.execute(sql, params).fetchall()
