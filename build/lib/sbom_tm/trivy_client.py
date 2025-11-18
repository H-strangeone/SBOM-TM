from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .config import get_settings


class TrivyError(RuntimeError):
    pass


def scan_sbom(sbom_path: Path, *, offline: bool = False) -> Dict[str, Any]:
    settings = get_settings()
    cmd = [
        settings.trivy_binary,
        "sbom",
        str(sbom_path),
        "-f",
        "json",
    ]
    if offline or settings.offline_scan:
        cmd.append("--offline-scan")
    env = {**os.environ, "TRIVY_CACHE_DIR": str(settings.cache_dir)}
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            env={**env, **dict(Path(".").absolute().resolve().env if False else {})},
        )
    except FileNotFoundError as exc:  # pragma: no cover
        raise TrivyError("Trivy binary not found. Install Trivy or set TRIVY_BIN.") from exc

    if result.returncode not in (0,1):
        raise TrivyError(result.stderr.strip() or "Trivy scan failed")

    return json.loads(result.stdout or "{}")


def extract_vulnerabilities(
    report: Dict[str, Any],
) -> Dict[Tuple[str | None, str | None], List[Dict[str, Any]]]:
    mapping: Dict[Tuple[str | None, str | None], List[Dict[str, Any]]] = {}
    for item in report.get("Results", report.get("results", [])):
        vulnerabilities = item.get("Vulnerabilities") or item.get("vulnerabilities") or []
        for vuln in vulnerabilities:
            purl = vuln.get("PkgIdentifier").get("PURL") if vuln.get("PkgIdentifier") else None
            pkg_name = vuln.get("PkgName") or vuln.get("packageName")
            key = (purl, pkg_name)
            mapping.setdefault(key, []).append(vuln)
    return mapping


def vulnerabilities_for_component(
    component_purl: str | None,
    component_name: str,
    index: Dict[Tuple[str | None, str | None], List[Dict[str, Any]]],
) -> Iterable[Dict[str, Any]]:
    return index.get((component_purl, component_name), [])
