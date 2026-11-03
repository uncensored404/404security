import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

SUSPICIOUS_PATTERNS = (
    "nc -e", "/dev/tcp/", "chmod 777 /etc", "history -c &&",
    "cryptominer", "/tmp/.x", "base64 -d | sh",
)


class Sentinel:
    def __init__(self, db, on_alert, watch_paths, interval=60,
                 baseline_file="data/sentinel_baseline.json"):
        self.db = db
        self.on_alert = on_alert
        self.watch_paths = watch_paths
        self.interval = interval
        self.baseline_file = Path(baseline_file)
        self.baseline = self._load()

    @staticmethod
    def _hash(path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _load(self):
        if self.baseline_file.exists():
            return json.loads(self.baseline_file.read_text())
        return {}

    def build_baseline(self):
        for root in self.watch_paths:
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    path = os.path.join(dirpath, name)
                    try:
                        st = os.stat(path)
                        self.baseline[path] = {
                            "sha256": self._hash(path),
                            "mtime": st.st_mtime,
                            "size": st.st_size,
                        }
                    except OSError:
                        continue
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text(json.dumps(self.baseline, indent=1))

    def check_integrity(self):
        for path, rec in self.baseline.items():
            try:
                st = os.stat(path)
                if st.st_mtime != rec["mtime"]:
                    digest = self._hash(path)
                    if digest != rec["sha256"]:
                        self.on_alert("sentinel", "high", "file_modified", None,
                                      {"path": path, "old_sha": rec["sha256"][:16]})
                        rec["sha256"], rec["mtime"] = digest, st.st_mtime
            except FileNotFoundError:
                self.on_alert("sentinel", "high", "file_deleted", None, {"path": path})

    def check_processes(self):
        out = subprocess.run(["ps", "-eo", "pid,user,args"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines()[1:]:
            if any(p in line for p in SUSPICIOUS_PATTERNS):
                self.on_alert("sentinel", "critical", "suspicious_process", None,
                              {"process": line.strip()[:200]})

    def run_forever(self):
        while True:
            self.check_integrity()
            self.check_processes()
            time.sleep(self.interval)
