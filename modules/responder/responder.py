import subprocess
import threading
import time
from collections import defaultdict

SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 5, "critical": 10}


class Responder:
    """Scoring d'IP et blocage nftables automatique."""

    def __init__(self, db, block_threshold=10, block_minutes=30, dry_run=False):
        self.db = db
        self.block_threshold = block_threshold
        self.block_minutes = block_minutes
        self.dry_run = dry_run
        self.scores = defaultdict(int)
        self.lock = threading.Lock()
        if not dry_run:
            subprocess.run(["nft", "add", "table", "inet", "f404"], capture_output=True)
            subprocess.run(["nft", "add", "chain", "inet", "f404", "input",
                            "{", "type", "filter", "hook", "input", "priority", "0", ";",
                            "policy", "accept", ";", "}"], capture_output=True)

    def feed(self, source, severity, event_type, src_ip, details):
        if not src_ip:
            return
        with self.lock:
            self.scores[src_ip] += SEVERITY_WEIGHT.get(severity, 1)
            if self.scores[src_ip] >= self.block_threshold:
                self.block_ip(src_ip, f"score={self.scores[src_ip]} {event_type}")
                self.scores[src_ip] = 0

    def block_ip(self, ip, reason):
        until = time.time() + self.block_minutes * 60
        self.db.insert_event("responder", "high", "ip_blocked", ip, {"reason": reason})
        self.db.execute("INSERT OR REPLACE INTO blocks VALUES(?,?,?)", (ip, until, reason))
        if not self.dry_run:
            subprocess.run(["nft", "add", "rule", "inet", "f404", "input",
                            "ip", "saddr", ip, "drop"], capture_output=True)

    def unblock_expired(self):
        while True:
            now = time.time()
            for ip, until, _reason in self.db.query("SELECT ip, until, reason FROM blocks"):
                if until < now:
                    if not self.dry_run:
                        subprocess.run(["nft", "delete", "rule", "inet", "f404", "input",
                                        "ip", "saddr", ip, "drop"], capture_output=True)
                    self.db.execute("DELETE FROM blocks WHERE ip=?", (ip,))
            time.sleep(60)
