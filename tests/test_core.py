import os
import tempfile

from core.database import Database
from modules.logfire.correlator import Correlator
from modules.responder.responder import Responder


def test_insert_and_query():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(os.path.join(tmp, "t.db"))
        db.insert_event("test", "high", "e1", "1.2.3.4", {"x": 1})
        assert db.query("SELECT COUNT(*) FROM events")[0][0] == 1


def test_scoring_blocks_ip():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(os.path.join(tmp, "t.db"))
        r = Responder(db, block_threshold=9, block_minutes=30, dry_run=True)
        for _ in range(3):
            r.feed("test", "medium", "e", "1.2.3.4", {})
        assert ("1.2.3.4",) in db.query("SELECT ip FROM blocks")


def test_correlator_window():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(os.path.join(tmp, "t.db"))
        c = Correlator.__new__(Correlator)
        c.db, c.on_alert, c.lock = db, lambda *a: None, None
        c.rules = [{"name": "ssh_bruteforce", "match_type": "ssh_connection",
                    "window_s": 120, "count": 8, "severity": "high"}]
        for _ in range(8):
            db.insert_event("honeypot", "high", "ssh_connection", "9.9.9.9", {})
        assert c._match_window("ssh_connection", "9.9.9.9", 120, 8)
