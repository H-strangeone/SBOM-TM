from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass(slots=True)
class ServiceContext:
    service: str
    environment: str
    internet_exposed: bool
    data_class: list[str]
    value_metric: str
    exposure: Dict[str, Any]


def load_context(path: Optional[Path]) -> Dict[str, ServiceContext]:
    if path is None:
        return {}
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    mapping: Dict[str, ServiceContext] = {}
    for entry in payload:
        data_class = entry.get("data_class", [])
        if isinstance(data_class, str):
            data_items = [data_class]
        else:
            data_items = [str(item) for item in data_class]
        mapping[entry.get("component_purl") or entry.get("component_name")] = ServiceContext(
            service=entry.get("service", "unknown"),
            environment=entry.get("environment", "dev"),
            internet_exposed=bool(entry.get("internet_exposed", False)),
            data_class=data_items,
            value_metric=entry.get("value_metric", "medium"),
            exposure=entry.get("exposure", {}),
        )
    return mapping
