from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[2]


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    db_path: Path
    rules_dir: Path
    report_dir: Path
    cache_dir: Path
    templates_dir: Path
    trivy_binary: str
    offline_scan: bool


@lru_cache
def get_settings() -> Settings:
    db_path = Path(os.getenv("DB_PATH", BASE_DIR / "db" / "sbom_tm.sqlite"))
    rules_dir = Path(os.getenv("RULES_DIR", BASE_DIR / "rules"))
    report_dir = Path(os.getenv("REPORT_DIR", BASE_DIR / "data" / "reports"))
    cache_dir = Path(os.getenv("TRIVY_CACHE_DIR", BASE_DIR / "data" / "cache"))
    templates_dir = Path(os.getenv("TEMPLATE_DIR", BASE_DIR / "templates"))

    db_path.parent.mkdir(parents=True, exist_ok=True)
    rules_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    templates_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        db_path=db_path,
        rules_dir=rules_dir,
        report_dir=report_dir,
        cache_dir=cache_dir,
        templates_dir=templates_dir,
        trivy_binary=os.getenv("TRIVY_BIN", "trivy"),
        offline_scan=_bool_env("TRIVY_OFFLINE", False),
    )
