import threading
import time
from pathlib import Path

import yaml


class Correlator:
    def __init__(self, db, on_alert, rules_path="rules/correlation.yaml"):
        self.db = db
        self.on_alert = on_alert
        self.rules = yaml.safe_load(Path(rules_path).read_text())["rules"]
        self.lock = threading.Lock()

    def _match_window(self, event_type, src_ip, window, count):
        rows = self.db.query(
            "SELECT COUNT(*) FROM events WHERE event_type=? AND src_ip=? AND ts>?",
            (event_type, src_ip, time.time() - window))
        return rows[0][0] >= count

    def run_once(self):
        for rule in self.rules:
            with self.lock:
                rows = self.db.query(
                    "SELECT DISTINCT src_ip FROM events WHERE ts>? AND src_ip IS NOT NULL",
                    (time.time() - 3600,))
                for (src_ip,) in rows:
                    if self._match_window(rule["match_type"], src_ip,
                                          rule["window_s"], rule["count"]):
                        self.on_alert("logfire", rule["severity"], rule["name"],
                                      src_ip, {"description": rule.get("description", "")})

    def run_forever(self, interval=15):
        while True:
            self.run_once()
            time.sleep(interval)
