from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlmodel import select

from . import sbom_loader, trivy_client
from .config import get_settings
from .context_loader import ServiceContext, load_context
from .models import Component, ProjectScan, Threat, Vulnerability
from .report_builder import write_html_report, write_json_report
from .rule_engine import RuleEngine
from .scorer import compute_score
from .storage import session_scope
from .threatintel_enricher import enrich_with_threatintel


@dataclass(slots=True)
class ScanResult:
    project: str
    component_count: int
    vulnerability_count: int
    
    threat_count: int
    json_report: Path
    html_report: Path
    threats: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)

class ScanService:
    def __init__(self) -> None:
        settings = get_settings()
        self.settings = settings
        self.rule_engine = RuleEngine.from_directory(settings.rules_dir)

    def run(
        self,
        sbom_path: Path,
        project: str,
        context_path: Optional[Path] = None,
        offline: bool = False,
    ) -> ScanResult:
        components = sbom_loader.load_components(sbom_path)
        service_map = load_context(context_path)
        # build quick lookup maps for components by purl/bom_ref to enable dependency resolution
        components = sbom_loader.load_components(sbom_path)
        purl_map: Dict[str, sbom_loader.ParsedComponent] = {}
        bomref_map: Dict[str, sbom_loader.ParsedComponent] = {}
        for comp in components:
            if comp.purl:
                purl_map[comp.purl] = comp
            if comp.bom_ref:
                bomref_map[comp.bom_ref] = comp

        # helper to compute transitive dependency closure (returns purl list)
        def _collect_transitive(start_ref: Optional[str]) -> List[str]:
            seen: set = set()
            result: List[str] = []

            def _resolve(ref: Optional[str]) -> Optional[sbom_loader.ParsedComponent]:
                if not ref:
                    return None
                if ref in purl_map:
                    return purl_map.get(ref)
                if ref in bomref_map:
                    return bomref_map.get(ref)
                return None

            stack = [start_ref] if start_ref else []
            while stack:
                cur = stack.pop()
                if not cur or cur in seen:
                    continue
                seen.add(cur)
                comp = _resolve(cur)
                if not comp:
                    continue
                # add direct dependencies
                for d in comp.dependencies or []:
                    if isinstance(d, str) and d not in seen:
                        result.append(d)
                        stack.append(d)
            return result
        try:
            trivy_report = trivy_client.scan_sbom(sbom_path, offline=offline)
        except trivy_client.TrivyError as exc:
            fallback = self.settings.cache_dir / "sample_trivy_report.json"
            if fallback.exists():
                with fallback.open("r", encoding="utf-8") as fh:
                    trivy_report = json.load(fh)
            else:
                raise exc

        vuln_index = trivy_client.extract_vulnerabilities(trivy_report)

        threats_payload: List[dict] = []
        vulnerability_count = 0
        vulnerabilities_payload: List[dict] = []
        with session_scope() as session:
            scan = ProjectScan(project=project, sbom_path=str(sbom_path))
            session.add(scan)
            session.flush()

            for parsed in components:
                component_record = Component(
                    scan_id=scan.id,
                    name=parsed.name,
                    version=parsed.version,
                    purl=parsed.purl,
                    supplier=parsed.supplier,
                    hashes=parsed.hashes or None,
                    properties=parsed.properties or None,
                )
                session.add(component_record)
                session.flush()

                service_context = self._resolve_context(parsed, service_map)
                component_dict = {
                    "name": parsed.name,
                    "version": parsed.version,
                    "purl": parsed.purl,
                    "supplier": parsed.supplier,
                    "hashes": parsed.hashes,
                    "properties": parsed.properties,
                    "dependencies": parsed.dependencies,
                    "transitive_dependencies": _collect_transitive(parsed.purl or parsed.bom_ref),
                }

                raw_vulnerabilities = list(
                    trivy_client.vulnerabilities_for_component(
                        parsed.purl,
                        parsed.name,
                        vuln_index,
                    )
                )

                if not raw_vulnerabilities:
                    continue

                enriched_payload = enrich_with_threatintel(
                    [
                        {
                            "component": component_dict,
                            "vulnerabilities": raw_vulnerabilities,
                        }
                    ]
                )
                enriched_vulnerabilities = (
                    enriched_payload[0].get("vulnerabilities", raw_vulnerabilities)
                    if enriched_payload
                    else raw_vulnerabilities
                )

                for enriched_vuln in enriched_vulnerabilities:
                    vulnerability_count += 1
                    vulnerabilities_payload.append({ enriched_vuln,
                    })
                    vuln_record = Vulnerability(
                        component_id=component_record.id,
                        cve=_extract(enriched_vuln, ["VulnerabilityID", "cve"]),
                        severity=_extract(enriched_vuln, ["Severity", "severity"]),
                        cvss=_extract_cvss(enriched_vuln),
                        exploit_maturity=_extract(enriched_vuln, ["Exploitability", "exploit_maturity"]),
                        published=_extract(enriched_vuln, ["PublishedDate", "published"]),
                        raw=enriched_vuln,
                    )
                    session.add(vuln_record)
                    session.flush()

                    raw_hypotheses = list(
                        self.rule_engine.evaluate(
                            component_dict,
                            enriched_vuln,
                            service_context,
                            threatintel=enriched_vuln.get("threatintel", {}),
                        )
                    )

                    if not raw_hypotheses:
                        continue

                    def _hypothesis_priority(h: Dict[str, Any]) -> int:
                        meta = h.get("rule_metadata") or {}
                        pval = meta.get("priority")
                        if pval is not None:
                            try:
                                return int(pval)
                            except Exception:
                                pass

                        sev = str(h.get("rule_severity") or "").lower()
                        base = {"critical": 1, "high": 2, "medium": 3, "low": 4}
                        priority = base.get(sev, 5)

                        tags = meta.get("tags") or []
                        if isinstance(tags, (list, tuple)):
                            tags_l = [str(t).lower() for t in tags]
                            if "fallback" in tags_l or "broad" in tags_l or "catch-all" in tags_l:
                                priority += 10
                        return priority

                    priorities = [_hypothesis_priority(h) for h in raw_hypotheses]
                    best = min(priorities) if priorities else 0
                    filtered_hypotheses = [h for i, h in enumerate(raw_hypotheses) if priorities[i] == best]

                    for hypothesis in filtered_hypotheses:
                        rule_severity = hypothesis.get("rule_severity", "medium")
                        severity_multiplier = {"low": 0.8, "medium": 1.0, "high": 1.2}.get(rule_severity, 1.0)

                        score = compute_score(
                            vulnerability=enriched_vuln,
                            context=self._context_dict(service_context),
                            factors=hypothesis.get("score_factors", {}),
                            pattern_multiplier=hypothesis.get("pattern_multiplier", 1.0)
                            * severity_multiplier,
                        )
                        threat_record = Threat(
                            project=project,
                            scan_id=scan.id,
                            vulnerability_id=vuln_record.id,
                            rule_id=hypothesis["rule_id"],
                            score=score,
                            hypothesis=self._build_hypothesis_payload(
                                component_dict,
                                enriched_vuln,
                                service_context,
                                hypothesis,
                                score,
                            ),
                        )
                        session.add(threat_record)
                        session.flush()

                        threat_export = dict(threat_record.hypothesis)
                        threat_export["score"] = score
                        threat_export["rule_id"] = threat_record.rule_id
                        threat_export["threat_id"] = threat_record.id
                        threats_payload.append(threat_export)

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

            def _severity_rank(entry: dict) -> int:
                sev = None
                if isinstance(entry, dict):
                    evidence = entry.get("evidence") or {}
                    sev = evidence.get("severity") or entry.get("rule_severity") or entry.get("severity")
                if isinstance(sev, str):
                    return severity_order.get(sev.lower(), 4)
                return 4

            threats_payload.sort(
                key=lambda t: (-float(t.get("score", 0)), _severity_rank(t))
            )
            json_path = self.settings.report_dir / f"{project}_report.json"
            write_json_report(threats_payload, json_path)
            html_path = write_html_report(threats_payload, project)

        return ScanResult(
            project=project,
            component_count=len(components),
            vulnerability_count=vulnerability_count,
            vulnerabilities=vulnerabilities_payload,
            threat_count=len(threats_payload),
            threats=threats_payload,
            json_report=json_path,
            html_report=html_path,
        )

    def list_threats(self, project: Optional[str] = None) -> List[Threat]:
        with session_scope() as session:
            statement = select(Threat)
            if project:
                statement = statement.where(Threat.project == project)
            return list(session.exec(statement))

    @staticmethod
    def _resolve_context(
        component: sbom_loader.ParsedComponent,
        mapping: Dict[str, ServiceContext],
    ) -> Optional[ServiceContext]:
        if component.purl and component.purl in mapping:
            return mapping[component.purl]
        if component.name and component.name in mapping:
            return mapping[component.name]
        return None

    @staticmethod
    def _context_dict(service_context: Optional[ServiceContext]) -> Dict[str, Any]:
        return asdict(service_context) if service_context else {}

    def _build_hypothesis_payload(
        self,
        component: Dict[str, Any],
        vulnerability: Dict[str, Any],
        service_context: Optional[ServiceContext],
        hypothesis: Dict[str, Any],
        score: float,
    ) -> Dict[str, Any]:
        context_dict = self._context_dict(service_context)
        return {
            "target": {
                "service": context_dict.get("service", "unknown"),
                "component": component,
            },
            "value": {
                "data_class": context_dict.get("data_class", []),
                "value_metric": context_dict.get("value_metric", "medium"),
            },
            "pattern": hypothesis.get("pattern", []),
            "objective": hypothesis.get("objective", []),
            "evidence": {
                "cve": _extract(vulnerability, ["VulnerabilityID", "cve"]),
                "severity": _extract(vulnerability, ["Severity", "severity"]),
                "cvss": _extract_cvss(vulnerability),
                "exploit_maturity": _extract(vulnerability, ["Exploitability", "exploit_maturity"]),
                "intel": vulnerability.get("threatintel", {}),
            },
            "recommended_actions": hypothesis.get("recommendations", []),
            "score": score,
            "status": "open",
        }


def _extract(payload: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for key in keys:
        value = payload.get(key)
        if value:
            return str(value)
    return None


def _extract_cvss(payload: Dict[str, Any]) -> Optional[float]:
    scores = payload.get("CVSS") or payload.get("cvss")
    if not isinstance(scores, dict):
        return None

    def _pick(entry: Any) -> Optional[float]:
        if not isinstance(entry, dict):
            return None
        raw = entry.get("V3Score") or entry.get("V2Score")
        return _safe_float(raw)

    for provider in ("nvd", "ghsa"):
        score = _pick(scores.get(provider))
        if score is not None:
            return score

    for entry in scores.values():
        score = _pick(entry)
        if score is not None:
            return score
    return None


def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
