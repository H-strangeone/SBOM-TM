from __future__ import annotations
import yaml
from pathlib import Path


class CiConfig:
    def __init__(self, path: Path | None = None):
        self.path = path
        self.data = {}
        if path and path.exists():
            self.data = yaml.safe_load(path.read_text()) or {}

    def fail_on_severities(self):
        return set(self.data.get("fail_on", {}).get("vulnerabilities", []))

    def fail_on_rule_categories(self):
        return set(self.data.get("fail_on", {}).get("rule_categories", []))

    def ignore_cves(self):
        return set(self.data.get("ignore", {}).get("cves", []))

    def ignore_packages(self):
        return set(self.data.get("ignore", {}).get("packages", []))

    def min_threat_score(self):
        return self.data.get("threats", {}).get("min_score", 0)

    def allow_transitive(self):
        return bool(self.data.get("allow_transitive", False))
