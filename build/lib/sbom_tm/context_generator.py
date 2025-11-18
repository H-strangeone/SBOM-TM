from __future__ import annotations

import json
import os
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from . import sbom_loader


@dataclass(slots=True)
class ApplicationProfile:
    service_name: str
    environment: str
    internet_exposed: bool
    data_class: List[str]
    value_metric: str


_NODE_SERVER_HINTS = {
    "express",
    "fastify",
    "koa",
    "hapi",
    "restify",
    "next",
    "nuxt",
    "@nestjs/core",
}

_DATA_ACCESS_HINTS = {
    "pg",
    "mysql",
    "mongoose",
    "redis",
    "@aws-sdk/client-dynamodb",
    "dynamodb",
    "@prisma/client",
}

_PY_SERVER_HINTS = {
    "flask",
    "django",
    "fastapi",
    "uvicorn",
}

_PY_DATA_HINTS = {
    "sqlalchemy",
    "psycopg2",
    "psycopg2-binary",
    "django",
    "boto3",
}

_IMPORT_PATTERN = re.compile(
    r"(?:import\s+(?:[^'\"]+\s+from\s+)?|require\()\s*['\"](?P<target>[^'\"]+)['\"]",
)

_SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_SKIP_DIRS = {
    "node_modules",
    ".git",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".next",
    ".turbo",
    "tmp",
    "out",
}


def _collect_python_packages(project_dir: Path) -> set[str]:
    packages: set[str] = set()
    requirements_path = project_dir / "requirements.txt"
    if requirements_path.exists():
        for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            package_name = re.split(r"[<>=]", line, maxsplit=1)[0]
            packages.add(package_name.strip().lower())
    return packages


def _infer_ecosystems_from_components(
    components: Iterable[sbom_loader.ParsedComponent],
) -> set[str]:
    ecosystems: set[str] = set()
    for component in components:
        if not component.purl:
            continue
        purl = component.purl.lower()
        if purl.startswith("pkg:npm/"):
            ecosystems.add("npm")
        elif purl.startswith("pkg:pypi/") or purl.startswith("pkg:python/"):
            ecosystems.add("pypi")
        elif purl.startswith("pkg:golang/"):
            ecosystems.add("golang")
    return ecosystems


def _load_package_manifest(path: Path) -> Dict[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, FileNotFoundError):
        return {}


def _normalize_import_target(target: str) -> Optional[str]:
    value = target.strip()
    if not value or value.startswith((".", "/", "#")):
        return None
    if value.startswith("@"):
        parts = value.split("/")
        if len(parts) >= 2:
            return "/".join(parts[:2])
        return value
    return value.split("/", 1)[0]


def _extract_dependency_map(manifest: Dict[str, object]) -> Dict[str, tuple[str, Optional[str]]]:
    result: Dict[str, tuple[str, Optional[str]]] = {}
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        value = manifest.get(key)
        if isinstance(value, dict):
            for raw_name, raw_version in value.items():
                canonical = _normalize_import_target(str(raw_name))
                if not canonical:
                    continue
                version: Optional[str] = None
                if raw_version is not None:
                    version = str(raw_version)
                result[canonical] = (str(raw_name), version)
    return result


def _iter_source_files(project_dir: Path) -> List[Path]:
    files: List[Path] = []
    for root, dirs, filenames in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for filename in filenames:
            path = Path(root) / filename
            if path.suffix.lower() in _SOURCE_SUFFIXES:
                files.append(path)
    return files


def _scan_used_packages(project_dir: Path) -> Dict[str, set[Path]]:
    used: Dict[str, set[Path]] = {}
    for source_path in _iter_source_files(project_dir):
        try:
            text = source_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        try:
            relative_path = source_path.relative_to(project_dir)
        except ValueError:
            relative_path = source_path
        for match in _IMPORT_PATTERN.finditer(text):
            canonical = _normalize_import_target(match.group("target"))
            if canonical:
                used.setdefault(canonical, set()).add(relative_path)
    return used


def _choose_service_label(paths: set[Path]) -> str:
    labels = sorted(path.as_posix() for path in paths)
    if not labels:
        return "service"
    if len(labels) == 1:
        return labels[0]
    return ", ".join(labels)


def _resolve_package_manifest(base_dir: Path, package_name: str) -> Optional[Path]:
    node_modules_dir = base_dir / "node_modules"
    if not node_modules_dir.exists():
        return None
    path = node_modules_dir
    for part in package_name.split("/"):
        path = path / part
    manifest_path = path / "package.json"
    if manifest_path.exists():
        return manifest_path
    return None


def _make_component(name: str, version: Optional[str]) -> sbom_loader.ParsedComponent:
    normalized_version = None
    if version:
        normalized_version = version.lstrip("^~") or version
    purl = None
    if normalized_version:
        purl = f"pkg:npm/{name}@{normalized_version}"
    else:
        purl = f"pkg:npm/{name}"
    return sbom_loader.ParsedComponent(
        name=name,
        version=normalized_version,
        purl=purl,
        supplier=None,
        hashes={},
        properties={},
    )


def _collect_node_components(
    project_dir: Path,
) -> List[Tuple[sbom_loader.ParsedComponent, Optional[str]]]:
    package_json_path = project_dir / "package.json"
    manifest = _load_package_manifest(package_json_path)
    dependency_map = _extract_dependency_map(manifest)
    used_packages = _scan_used_packages(project_dir)

    selected: Dict[str, tuple[str, Optional[str]]] = {}
    for name, value in dependency_map.items():
        if name in used_packages:
            selected[name] = value

    if not selected:
        return []

    components: Dict[str, sbom_loader.ParsedComponent] = {}
    component_services: Dict[str, str] = {}
    queue: deque[tuple[str, Path, str]] = deque()

    for canonical, (raw_name, version) in selected.items():
        service_label = _choose_service_label(used_packages.get(canonical, set()))
        components[canonical] = _make_component(raw_name, version)
        component_services[canonical] = service_label
        queue.append((canonical, project_dir, service_label))

    visited: set[str] = set()

    while queue:
        package_name, base_dir, service_label = queue.popleft()
        if package_name in visited:
            continue
        visited.add(package_name)

        manifest_path = _resolve_package_manifest(base_dir, package_name)
        if manifest_path is None:
            continue

        manifest_data = _load_package_manifest(manifest_path)
        resolved_name_value = manifest_data.get("name")
        resolved_version_value = manifest_data.get("version")

        canonical = package_name
        if isinstance(resolved_name_value, str):
            normalized_name = _normalize_import_target(resolved_name_value)
            if normalized_name:
                canonical = normalized_name

        existing_component = components.get(canonical)
        if isinstance(resolved_name_value, str) and resolved_name_value.strip():
            display_name = resolved_name_value.strip()
        elif existing_component is not None:
            display_name = existing_component.name
        else:
            display_name = package_name

        new_version = None
        if resolved_version_value is not None:
            new_version = str(resolved_version_value)
        elif existing_component is not None:
            new_version = existing_component.version

        components[canonical] = _make_component(display_name, new_version)
        component_services.setdefault(canonical, service_label)

        dependencies = _extract_dependency_map(manifest_data)
        package_dir = manifest_path.parent
        for dep_canonical, (dep_raw, dep_version) in dependencies.items():
            if dep_canonical not in components:
                components[dep_canonical] = _make_component(dep_raw, dep_version)
            component_services.setdefault(dep_canonical, service_label)
            queue.append((dep_canonical, package_dir, service_label))

    results: List[Tuple[sbom_loader.ParsedComponent, Optional[str]]] = []
    for key in sorted(components.keys()):
        results.append((components[key], component_services.get(key)))
    return results


def detect_application_profile(
    project_dir: Optional[Path],
    project_name: str,
    components: Optional[Iterable[sbom_loader.ParsedComponent]] = None,
) -> ApplicationProfile:
    """Infer basic application traits for context generation.

    Currently supports light-weight heuristics for Node.js projects by inspecting
    ``package.json`` dependencies. Falls back to conservative defaults when the
    project footprint cannot be determined.
    """

    default_service = project_name or (project_dir.name if project_dir else "default-service")
    profile = ApplicationProfile(
        service_name=default_service,
        environment="prod",
        internet_exposed=False,
        data_class=["general"],
        value_metric="medium",
    )

    ecosystems: set[str] = set()
    if components is not None:
        ecosystems = _infer_ecosystems_from_components(components)
        if "npm" in ecosystems:
            profile.internet_exposed = True
            profile.value_metric = "high"
        if "pypi" in ecosystems:
            profile.data_class = ["pii"]
            profile.value_metric = "high"

    if not project_dir:
        return profile

    service_name = profile.service_name
    dependencies: Dict[str, object] = {}

    package_json_path = project_dir / "package.json"
    if package_json_path.exists():
        try:
            package_data: Dict[str, object] = json.loads(
                package_json_path.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            package_data = {}

        if isinstance(package_data, dict):
            name_value = package_data.get("name")
            if isinstance(name_value, str) and name_value.strip():
                service_name = name_value.strip()
                profile.service_name = service_name

            for key in ("dependencies", "devDependencies", "peerDependencies"):
                value = package_data.get(key)
                if isinstance(value, dict):
                    dependencies.update({str(dep).lower(): ver for dep, ver in value.items()})

            if any(hint in dependencies for hint in _NODE_SERVER_HINTS):
                profile.internet_exposed = True
                profile.value_metric = "high"

            if any(hint in dependencies for hint in _DATA_ACCESS_HINTS):
                profile.data_class = ["pii"]
                profile.value_metric = "high"

            if dependencies:
                return profile

    python_packages = _collect_python_packages(project_dir)
    if python_packages and not ecosystems:
        profile.service_name = service_name
        if python_packages & _PY_SERVER_HINTS:
            profile.internet_exposed = True
            profile.value_metric = "high"
        if python_packages & _PY_DATA_HINTS:
            profile.data_class = ["pii"]
            profile.value_metric = "high"

    return profile


def _build_context_entry(
    component: sbom_loader.ParsedComponent,
    profile: ApplicationProfile,
    service_label: Optional[str],
) -> Dict[str, object]:
    service_value = service_label or profile.service_name
    return {
        "component_name": component.name,
        "component_purl": component.purl,
        "service": service_value,
        "environment": profile.environment,
        "internet_exposed": profile.internet_exposed,
        "data_class": profile.data_class,
        "value_metric": profile.value_metric,
        "exposure": {
            "internet": profile.internet_exposed,
        },
    }


def generate_context_file(
    sbom_path: Optional[Path],
    project_dir: Optional[Path],
    project_name: str,
    output_dir: Optional[Path] = None,
) -> Path:
    """Create a context JSON file by analysing the project and/or SBOM."""

    components: List[Tuple[sbom_loader.ParsedComponent, Optional[str]]] = []
    if project_dir is not None:
        components = _collect_node_components(project_dir)

    if not components and sbom_path is not None and sbom_path.exists():
        components = [
            (component, None)
            for component in sbom_loader.load_components(sbom_path)
        ]

    profile = detect_application_profile(
        project_dir,
        project_name,
        [component for component, _ in components] or None,
    )

    output_root = output_dir
    if output_root is None:
        if project_dir is not None:
            output_root = project_dir / ".sbom_tm"
        elif sbom_path is not None:
            output_root = sbom_path.parent
        else:
            output_root = Path.cwd()
    output_root.mkdir(parents=True, exist_ok=True)

    safe_service = profile.service_name.replace(" ", "-") or "service"
    safe_service = safe_service.replace("/", "--")
    safe_service = re.sub(r"[^a-zA-Z0-9\-_]", "", safe_service)
    output_path = output_root / f"{safe_service}_context.generated.json"

    payload = [
        _build_context_entry(component, profile, service_label)
        for component, service_label in components
    ]

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    return output_path
