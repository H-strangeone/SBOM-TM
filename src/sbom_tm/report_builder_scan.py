from pathlib import Path
from typing import Any, Dict, List


def extract_all_vulnerabilities(result) -> List[Dict[str, Any]]:
    """
    Try all known places where Trivy / ScanService might be storing vulnerabilities.
    This makes the markdown resilient to internal representation changes.
    """
    all_vuls: List[Dict[str, Any]] = []

    # 1) Preferred: flattened list
    v1 = getattr(result, "vulnerabilities", None)
    if isinstance(v1, list):
        all_vuls.extend(v1)

    # 2) Raw internal list, if exposed
    v2 = getattr(result, "raw_vulnerabilities", None)
    if isinstance(v2, list):
        all_vuls.extend(v2)

    # 3) Trivy JSON report shape: Results[].Vulnerabilities[]
    trivy_report = getattr(result, "trivy_report", None)
    if isinstance(trivy_report, dict):
        for res in trivy_report.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                if isinstance(v, dict):
                    all_vuls.append(v)

    # Optional: deduplicate by (VulnerabilityID, PkgName)
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for v in all_vuls:
        vid = (
            v.get("VulnerabilityID")
            or v.get("vulnerability_id")
            or v.get("CVE")
            or v.get("cve")
            or "UNKNOWN"
        )
        pkg = (
            v.get("PkgName")
            or v.get("PkgID")
            or v.get("package")
            or (v.get("Package") or {}).get("Name")
            if isinstance(v.get("Package"), dict)
            else None
        ) or "UNKNOWN_PKG"

        key = (str(vid), str(pkg))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(v)

    return deduped


def write_markdown_scan(result, output_path: Path) -> None:
    """
    Build a human-readable markdown scan report, including all vulnerabilities
    we can discover from the result object.
    """
    lines: List[str] = []

    lines.append(f"# SBOM Scan Report – {result.project}\n")
    lines.append(f"- **Components:** {getattr(result, 'component_count', 'unknown')}")
    lines.append(f"- **Vulnerabilities:** {getattr(result, 'vulnerability_count', 'unknown')}")
    lines.append(f"- **Threats:** {getattr(result, 'threat_count', 'unknown')}\n")

    # -------------------------
    # Vulnerabilities section
    # -------------------------
    lines.append("## Vulnerabilities\n")

    vuls = extract_all_vulnerabilities(result)

    if not vuls:
        lines.append("_No vulnerabilities detected by Trivy._")
    else:
        def get_field(v: Dict[str, Any], *keys: str):
            for k in keys:
                if k in v:
                    return v[k]
            return None

        for v in vuls:
            # CVE / ID
            cve = (
                get_field(v, "VulnerabilityID", "vulnerability_id", "CVE", "cve")
                or "unknown"
            )

            # Package (can be string or nested object)
            pkg = get_field(v, "PkgName", "PkgID", "package", "PkgName")
            if isinstance(pkg, dict):
                pkg = pkg.get("name") or pkg.get("id")
            pkg = pkg or "unknown"

            # Severity
            sev = (
                get_field(v, "Severity", "severity", "SeveritySource")
                or "unknown"
            )

            lines.append(f"- **{cve}** — *{pkg}* — **{sev}**")

    # -------------------------
    # Threats section
    # -------------------------
    lines.append("\n## Threats\n")
    threats = getattr(result, "threats", []) or []

    if not threats:
        lines.append("_No Rule Engine threats triggered._")
    else:
        for t in threats:
            rid = t.get("rule_id", "unknown")
            score = t.get("score", 0)
            cat = t.get("category", "unknown")
            lines.append(f"- Rule **{rid}** — Category **{cat}** — Score **{score}**")

    output_path.write_text("\n".join(lines), encoding="utf-8")
