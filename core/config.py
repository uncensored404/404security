from pathlib import Path
import yaml


class Config:
    def __init__(self, path="config.yaml"):
        self.data = yaml.safe_load(Path(path).read_text()) or {}

    def get(self, key, default=None):
        cur = self.data
        for part in key.split("."):
            if not isinstance(cur, dict):
                return default
            cur = cur.get(part)
            if cur is None:
                return default
        return cur


CONFIG = Config()
