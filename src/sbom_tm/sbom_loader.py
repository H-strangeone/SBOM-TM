from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass(slots=True)
class ParsedComponent:
    name: str
    version: Optional[str]
    purl: Optional[str]
    supplier: Optional[str]
    hashes: Dict[str, Any]
    properties: Dict[str, Any]
    bom_ref: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)


def load_sbom(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def iter_components(sbom: Dict[str, Any]) -> Iterable[ParsedComponent]:
    components = sbom.get("components", [])
    # first pass: create ParsedComponent objects and index by bom-ref and purl
    parsed: List[ParsedComponent] = []
    ref_map: Dict[str, ParsedComponent] = {}
    for component in components:
        bom_ref = component.get("bom-ref") or component.get("bom_ref")
        purl = component.get("purl")
        pc = ParsedComponent(
            name=component.get("name", "unknown"),
            version=component.get("version"),
            purl=purl,
            supplier=component.get("supplier"),
            hashes={
                hash_obj.get("alg") or hash_obj.get("algorithm", ""): hash_obj.get("content")
                for hash_obj in component.get("hashes", [])
            },
            properties={
                prop.get("name"): prop.get("value") for prop in component.get("properties", [])
            },
            bom_ref=bom_ref,
        )
        parsed.append(pc)
        if bom_ref:
            ref_map[str(bom_ref)] = pc
        if purl:
            ref_map[str(purl)] = pc

    # second pass: resolve dependencies from top-level 'dependencies' section when present
    deps = sbom.get("dependencies", [])
    for entry in deps:
        ref = entry.get("ref")
        depends_on = entry.get("dependsOn", []) or entry.get("depends_on", [])
        owner = ref_map.get(ref)
        if not owner:
            continue
        resolved = []
        for d in depends_on:
            target = ref_map.get(d)
            if target and target.purl:
                resolved.append(target.purl)
            else:
                # fallback to raw ref
                resolved.append(d)
        owner.dependencies = resolved

    for pc in parsed:
        yield pc


def load_components(path: Path) -> List[ParsedComponent]:
    sbom = load_sbom(path)
    return list(iter_components(sbom))
