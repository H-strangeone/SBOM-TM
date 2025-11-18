from __future__ import annotations

import json
from datetime import datetime, UTC
from pathlib import Path
from typing import Iterable, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import get_settings


def write_json_report(threats: Iterable[dict], output_path: Path) -> None:
    payload = {
        "generated_at": datetime.now(UTC).isoformat() + "Z",
        "threats": list(threats),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_html_report(threats: List[dict], project: str) -> Path:
    settings = get_settings()
    env = Environment(
        loader=FileSystemLoader(settings.templates_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    rendered = template.render(project=project, threats=threats, generated=datetime.now(UTC))
    output_path = settings.report_dir / f"{project}_report.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        fh.write(rendered)
    return output_path
