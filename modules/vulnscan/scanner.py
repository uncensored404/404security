import json
import subprocess
import time
from pathlib import Path

DB_FILE = Path(__file__).parent / "cve_db.json"


class VulnScan:
    def __init__(self, db, on_alert):
        self.db = db
        self.on_alert = on_alert
        self.signatures = json.loads(DB_FILE.read_text()) if DB_FILE.exists() else {}

    def scan(self):
        out = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True).stdout
        for banner, cves in self.signatures.items():
            if banner.lower() in out.lower():
                self.on_alert("vulnscan", "high", "vulnerable_service", None,
                              {"banner": banner, "cves": cves})
        self.db.insert_event("vulnscan", "low", "inventory", None,
                             {"listening": out[:1500]})
        return out

    def run_forever(self, interval=86400):
        while True:
            self.scan()
            time.sleep(interval)
