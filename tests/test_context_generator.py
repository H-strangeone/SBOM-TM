from __future__ import annotations

import json
from pathlib import Path

from src.sbom_tm.context_generator import detect_application_profile, generate_context_file
from src.sbom_tm.sbom_loader import ParsedComponent


def test_detect_application_profile_node(tmp_path: Path) -> None:
    project_dir = tmp_path / "app"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "sample-app",
                "dependencies": {
                    "express": "^4.18.0",
                    "pg": "^8.11.0",
                },
            }
        ),
        encoding="utf-8",
    )

    profile = detect_application_profile(project_dir, "fallback")
    assert profile.service_name == "sample-app"
    assert profile.internet_exposed is True
    assert profile.value_metric == "high"
    assert profile.data_class == ["pii"]


def test_detect_application_profile_python(tmp_path: Path) -> None:
    project_dir = tmp_path / "pyapp"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "requirements.txt").write_text(
        "Flask==2.3\npsycopg2-binary>=2.9\n",
        encoding="utf-8",
    )

    profile = detect_application_profile(project_dir, "py-service")

    assert profile.service_name == "py-service"
    assert profile.internet_exposed is True
    assert profile.value_metric == "high"
    assert profile.data_class == ["pii"]


def test_detect_application_profile_from_components() -> None:
    npm_component = ParsedComponent(
        name="express",
        version="4.18.0",
        purl="pkg:npm/express@4.18.0",
        supplier=None,
        hashes={},
        properties={},
    )
    pypi_component = ParsedComponent(
        name="django",
        version="4.2",
        purl="pkg:pypi/django@4.2",
        supplier=None,
        hashes={},
        properties={},
    )

    profile = detect_application_profile(
        project_dir=None,
        project_name="fallback",
        components=[npm_component, pypi_component],
    )

    assert profile.service_name == "fallback"
    assert profile.internet_exposed is True
    assert profile.value_metric == "high"
    assert profile.data_class == ["pii"]


def test_generate_context_file(tmp_path: Path) -> None:
    project_dir = tmp_path / "app"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "dependencies": {
                    "express": "^4.18.0",
                    "lodash": "^4.17.21",
                    "pg": "^8.0.0",
                },
            }
        ),
        encoding="utf-8",
    )

    src_dir = project_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "index.js").write_text("import express from 'express'\n", encoding="utf-8")

    express_manifest = {
        "name": "express",
        "version": "4.18.0",
        "dependencies": {
            "accepts": "1.3.8",
        },
    }
    node_modules = project_dir / "node_modules"
    (node_modules / "express").mkdir(parents=True, exist_ok=True)
    (node_modules / "express" / "package.json").write_text(
        json.dumps(express_manifest),
        encoding="utf-8",
    )

    accepts_manifest = {
        "name": "accepts",
        "version": "1.3.8",
        "dependencies": {},
    }
    (node_modules / "express" / "node_modules" / "accepts").mkdir(parents=True, exist_ok=True)
    (node_modules / "express" / "node_modules" / "accepts" / "package.json").write_text(
        json.dumps(accepts_manifest),
        encoding="utf-8",
    )

    output_dir = tmp_path / "generated"
    context_path = generate_context_file(
        sbom_path=None,
        project_dir=project_dir,
        project_name="demo",
        output_dir=output_dir,
    )

    data = json.loads(context_path.read_text(encoding="utf-8"))
    assert context_path.exists()
    component_services = {entry["component_name"]: entry["service"] for entry in data}
    assert "express" in component_services
    assert "accepts" in component_services
    assert component_services["express"] == "src/index.js"
    assert component_services["accepts"] == "src/index.js"
    assert "pg" not in component_services