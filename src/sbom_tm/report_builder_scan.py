from pathlib import Path

def write_markdown_scan(result, output_path: Path):
    lines = []
    lines.append(f"# SBOM Scan Report – {result.project}\n")
    lines.append(f"**Components:** {result.component_count}")
    lines.append(f"**Vulnerabilities:** {result.vulnerability_count}")
    lines.append(f"**Threats:** {result.threat_count}\n")

    lines.append("## Vulnerabilities\n")
    for v in result.vulnerabilities:
        cve = v.get("VulnerabilityID") or v.get("cve") or "unknown"
        pkg = v.get("PkgName") or v.get("package") or "unknown"
        sev = v.get("Severity") or v.get("severity") or "unknown"
        lines.append(f"- **{cve}** – *{pkg}* – {sev}")

    lines.append("\n## Threats\n")
    for t in result.threats:
        rid = t.get("rule_id", "unknown")
        score = t.get("score", 0)
        sev = t.get("evidence", {}).get("severity", "unknown")
        lines.append(f"- Rule **{rid}** – Score **{score}** – Severity {sev}")

    output_path.write_text("\n".join(lines), encoding="utf-8")
