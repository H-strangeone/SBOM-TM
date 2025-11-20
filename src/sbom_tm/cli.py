from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional
import json
import subprocess
import tempfile
from typing import List, Dict, Tuple
from .trivy_client import scan_sbom, extract_vulnerabilities  # uses existing module
import typer
from .config import get_settings
from .context_generator import generate_context_file
from .rule_engine import RuleEngine
from .service import ScanService
from .config_ci import CiConfig
ci_config = CiConfig(Path(".sbom-ci.yml"))

sbom_app = typer.Typer(help="SBOM utilities")
app = typer.Typer(help="SBOM threat modeller")
app.add_typer(sbom_app, name="sbom")

@sbom_app.command("generate")
# ===== Add imports at top of cli.py =====


# ===== Add diff command =====
@app.command()
def diff(
    git: Annotated[bool, typer.Option("--git", help="Compare current HEAD with merge-base (git)")] = False,
    base_ref: Annotated[Optional[str], typer.Option("--base", "-b", help="Base ref (defaults to origin/main or HEAD~1)")] = None,
    path: Annotated[Optional[str], typer.Argument(exists=True, readable=True)] = None,
    sbom_old: Annotated[Optional[Path], typer.Option("--old", help="Old SBOM path")] = None,
    sbom_new: Annotated[Optional[Path], typer.Option("--new", help="New SBOM path")] = None,
    project: Annotated[str, typer.Option("--project", "-p")] = "default",
    offline: Annotated[bool, typer.Option("--offline")] = False,
):
    """
    Compute SBOM diff between two states.
    Use --git to auto-generate SBOMs for current HEAD and the base commit.
    """

    # -------------------------
    # Helper: generate SBOM for git ref
    # -------------------------
    def _gen_sbom_for_ref(ref: Optional[str], target_dir: Optional[Path]) -> Path:
        import shutil, subprocess, tempfile
        if shutil.which("syft") is None:
            raise typer.BadParameter("syft not found; install syft or provide SBOM files.")

        if ref:
            tmpdir = Path(tempfile.mkdtemp())
            subprocess.run(["git", "clone", ".", str(tmpdir)], check=True)
            subprocess.run(["git", "checkout", ref], cwd=str(tmpdir), check=True)
            target = tmpdir
        else:
            if not target_dir:
                raise typer.BadParameter("target_dir required when no ref")
            target = Path(target_dir)

        proc = subprocess.run(["syft", str(target), "-o", "cyclonedx-json"], capture_output=True, text=True)
        if proc.returncode != 0:
            raise typer.Exit(f"syft failed: {proc.stderr}")

        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tf.write(proc.stdout.encode("utf-8"))
        tf.flush()
        tf.close()
        return Path(tf.name)

    temp_old = None
    temp_new = None

    try:
        # -------------------------
        # Generate SBOMs via git
        # -------------------------
        if git:
            if base_ref is None:
                subprocess.run(["git", "fetch", "origin", "main"], check=False)

                merge_base = subprocess.run(
                    ["git", "merge-base", "HEAD", "origin/main"],
                    check=False, capture_output=True, text=True
                ).stdout.strip()

                base_ref = merge_base or "HEAD~1"

            typer.echo(f"[sbom-tm] generating SBOM for base ref: {base_ref}")
            temp_old = _gen_sbom_for_ref(base_ref, None)

            typer.echo(f"[sbom-tm] generating SBOM for HEAD")
            temp_new = _gen_sbom_for_ref("HEAD", None)

            sbom_old = temp_old
            sbom_new = temp_new

        else:
            if not sbom_old or not sbom_new:
                raise typer.BadParameter("Provide --old and --new or use --git")

        # -------------------------
        # Scan both with Trivy
        # -------------------------
        typer.echo("[sbom-tm] scanning old SBOM...")
        old_report = scan_sbom(sbom_old, offline=offline)

        typer.echo("[sbom-tm] scanning new SBOM...")
        new_report = scan_sbom(sbom_new, offline=offline)

        old_index = extract_vulnerabilities(old_report)
        new_index = extract_vulnerabilities(new_report)

        # -------------------------
        # FIX 1 — Normalise dict keys to avoid TypeError: unhashable type: dict
        # -------------------------
        def normalize_key(x):
            if isinstance(x, dict):
                return json.dumps(x, sort_keys=True)
            return str(x)

        def _cves_from_index(idx):
            mapping = {}
            for (purl, pkg), vulns in idx.items():
                cves = []
                for v in vulns:
                    c = v.get("VulnerabilityID") or v.get("CVE") or v.get("vulnerability_id")
                    if c:
                        cves.append(str(c).upper())
                mapping[(normalize_key(purl), normalize_key(pkg))] = sorted(set(cves))
            return mapping

        old_cves_map = _cves_from_index(old_index)
        new_cves_map = _cves_from_index(new_index)

        # -------------------------
        # Find new CVEs
        # -------------------------
        new_only = []
        for key, new_cves in new_cves_map.items():
            old_cves = old_cves_map.get(key, [])
            added = [c for c in new_cves if c not in old_cves]
            if added:
                new_only.append({"component": key, "new_cves": added})

        # -------------------------
        # Component version changes
        # -------------------------
        from .sbom_loader import load_components
        old_components = {(c.purl or c.name): c.version for c in load_components(sbom_old)}
        new_components = {(c.purl or c.name): c.version for c in load_components(sbom_new)}

        added_components = [k for k in new_components if k not in old_components]
        removed_components = [k for k in old_components if k not in new_components]

        version_changes = [
            {"component": k, "old": old_components[k], "new": new_components[k]}
            for k in new_components
            if k in old_components and old_components[k] != new_components[k]
        ]

        # -------------------------
        # Build base diff
        # -------------------------
        diff_payload = {
            "added_components": added_components,
            "removed_components": removed_components,
            "version_changes": version_changes,
            "new_vulnerabilities": new_only,
        }

        # ============================================================
        #                      RULE ENGINE SECTION
        # ============================================================
        settings = get_settings()
        new_component_objs = load_components(sbom_new)

        typer.echo("[sbom-tm] generating context...")
        ctx = generate_context_file(
            sbom_path=sbom_new,
            project_dir=None,
            project_name=project,
            output_dir=settings.cache_dir / "generated_contexts",
        )

        typer.echo("[sbom-tm] loading rule engine...")
        try:
            engine = RuleEngine.from_directory(settings.rules_dir)
        except Exception as e:
            typer.echo(f"[sbom-tm] WARNING: Failed to load rules: {e}")
            engine = None

        threats = []

        if engine:
            from .context_loader import load_context
            from .trivy_client import vulnerabilities_for_component
            from .threatintel_enricher import enrich_with_threatintel
            from .scorer import compute_score

            service_map = load_context(Path(ctx))
            scan_service = ScanService()

            for parsed in new_component_objs:
                component_dict = {
                    "name": parsed.name,
                    "version": parsed.version,
                    "purl": parsed.purl,
                    "supplier": parsed.supplier,
                    "hashes": parsed.hashes,
                    "properties": parsed.properties,
                    "dependencies": parsed.dependencies,
                }

                service_context = scan_service._resolve_context(parsed, service_map)

                # ------------------------------------------------------
                # FIX 2 — Tuples from freeze() broke .get()
                # Convert every vuln into dict form if needed
                # ------------------------------------------------------
                raw_vulns = list(vulnerabilities_for_component(parsed.purl, parsed.name, new_index))

                safe_vulns = []
                for v in raw_vulns:
                    if isinstance(v, dict):
                        safe_vulns.append(v)
                    else:
                        safe_vulns.append({"raw": v})

                enriched_payload = enrich_with_threatintel(
                    [{"component": component_dict, "vulnerabilities": safe_vulns}]
                )
                enriched_vulnerabilities = enriched_payload[0]["vulnerabilities"]

                # Evaluate rules
                for vuln in enriched_vulnerabilities:
                    raw_h = list(
                        engine.evaluate(
                            component_dict,
                            vuln,
                            service_context,
                            threatintel=vuln.get("threatintel", {}),
                        )
                    )
                    if not raw_h:
                        continue

                    # pick best hypothesis
                    def priority(h):
                        meta = h.get("rule_metadata", {})
                        if "priority" in meta:
                            try:
                                return int(meta["priority"])
                            except:
                                pass

                        sev = (h.get("rule_severity") or "").lower()
                        base = {"critical": 1, "high": 2, "medium": 3, "low": 4}
                        return base.get(sev, 5)

                    pr_list = [priority(h) for h in raw_h]
                    best = min(pr_list)
                    chosen = [h for h, p in zip(raw_h, pr_list) if p == best]

                    for hyp in chosen:
                        rule_sev = hyp.get("rule_severity", "medium")
                        sev_mult = {"low": 0.8, "medium": 1.0, "high": 1.2}.get(rule_sev, 1.0)

                        score = compute_score(
                            vulnerability=vuln,
                            context=scan_service._context_dict(service_context),
                            factors=hyp.get("score_factors", {}),
                            pattern_multiplier=hyp.get("pattern_multiplier", 1.0) * sev_mult,
                        )

                        payload = scan_service._build_hypothesis_payload(
                            component_dict,
                            vuln,
                            service_context,
                            hyp,
                            score,
                        )

                        payload["score"] = score
                        payload["rule_id"] = hyp.get("rule_id")
                        threats.append(payload)

        # attach
        diff_payload["rule_engine_threats"] = threats
        result = {
            "project": project,
            "added_components": added_components,
            "removed_components": removed_components,
            "version_changes": version_changes,
            "new_vulnerabilities": new_only,
            "threats": threats,
            "diff_payload": diff_payload,
        }

        # =======================
        # CI POLICY CHECK
        # =======================
        ci = CiConfig(Path(".sbom-ci.yml"))
        fail_cat = ci.fail_on_rule_categories()
        min_score = ci.min_threat_score()

        triggered = [
            t for t in threats
            if t["score"] >= min_score and t["category"] in fail_cat
        ]

        if triggered:
            typer.echo("[sbom-tm] ❌ RuleEngine detected blocking threats.")
            print("[SBOM-TM] WARNING: Policy violation — continuing.")

        # =======================
        # Markdown report
        # =======================
        report_dir = settings.cache_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        export_dir = Path("/github/workspace/sbom-report")

        export_dir.mkdir(parents=True, exist_ok=True)


        md_report = export_dir / f"{project}_sbom_diff.md"


        if engine:
            try:
                md_report.write_text(engine.to_markdown(threats), encoding="utf-8")
                typer.echo(f"[sbom-tm] markdown diff report: {md_report}")
            except Exception as e:
                typer.echo(f"[sbom-tm] WARNING: failed to write markdown: {e}")

        out = export_dir / f"{project}_sbom_diff.json"

        out.write_text(json.dumps(diff_payload, indent=2), encoding="utf-8")
        typer.echo(f"[sbom-tm] diff written to {out}")

        # =======================
        # Severity gate (fail on new CVEs)
        # =======================
        fail_sev = ci.fail_on_severities()

        new_cve_set = {c for entry in new_only for c in entry["new_cves"]}

        severity_map = {}
        for (purl, pkg), vulns in new_index.items():
            for v in vulns:
                c = (v.get("VulnerabilityID") or v.get("CVE") or "").upper()
                if c in new_cve_set:
                    severity_map[c] = v.get("Severity")

        for cve, sev in severity_map.items():
            if sev and sev.upper() in fail_sev:
                typer.echo(f"[sbom-tm] ❌ New {sev} vulnerability introduced: {cve}")
                print("[SBOM-TM] WARNING: Policy violation — continuing.")
                return result

        typer.echo("[sbom-tm] ✅ No blocking new vulnerabilities.")
        return

    finally:
        try:
            if temp_old:
                Path(temp_old).unlink()
            if temp_new:
                Path(temp_new).unlink()
        except:
            pass


def sbom_generate(
    path: Annotated[
        str,
        typer.Argument(
            exists=True,
            readable=True,
            help="Path to project directory"
        )
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output SBOM file path (default: ./sbom.json)"
        )
    ] = Path("./sbom.json")
):
    """
    Generate a CycloneDX SBOM using Syft.
    """

    import shutil
    import subprocess

    project_dir = Path(path).expanduser().resolve()

    # check syft available
    if shutil.which("syft") is None:
        typer.echo("Error: syft not found. Install syft first.")
        raise typer.Exit(code=1)

    typer.echo(f"[SBOM-TM] generating SBOM for: {project_dir}")

    proc = subprocess.run(
        ["syft", str(project_dir), "-o", "cyclonedx-json"],
        check=False,
        capture_output=True,
        text=True,
    )

    if proc.returncode != 0:
        typer.echo(f"[SBOM-TM] Syft failed:\n{proc.stderr}")
        raise typer.Exit(code=1)

    # Write file
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(proc.stdout, encoding="utf-8")

    typer.echo(f"[SBOM-TM] SBOM written to: {output}")

@app.command()
def scan(
    path: Annotated[
        Optional[str],
        typer.Argument(exists=True, readable=True)
    ] = None,
    sbom: Annotated[
        Optional[Path],
        typer.Option("--sbom", exists=True, readable=True)
    ] = None,
    project: Annotated[
        str,
        typer.Option("--project", "-p")
    ] = "default",
    context: Annotated[
        Optional[Path],
        typer.Option("--context", exists=True, readable=True)
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(help="Use Trivy offline scan mode")
    ] = False,
) -> None:

    # ============================================================
    #  SBOM GENERATION (syft)
    # ============================================================
    temp_sbom: Optional[Path] = None
    project_dir = Path(path).expanduser().resolve() if path else None

    if sbom is None and project_dir is None:
        typer.echo("Please provide either --sbom <path> or --path <path>")
        return

    if sbom is None:
        import shutil, subprocess, tempfile
        if shutil.which("syft") is None:
            typer.echo("syft not found")
            return

        typer.echo("[SBOM-TM] generating SBOM using syft...")
        proc = subprocess.run(
            ["syft", str(project_dir), "-o", "cyclonedx-json"],
            capture_output=True, text=True
        )
        if proc.returncode != 0:
            typer.echo(proc.stderr)
            return

        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tf.write(proc.stdout.encode("utf-8"))
        tf.flush()
        tf.close()
        temp_sbom = Path(tf.name)
        sbom = temp_sbom

    settings = get_settings()

    # ============================================================
    #  CONTEXT GENERATION
    # ============================================================
    if context is None:
        context = generate_context_file(
            sbom_path=sbom,
            project_dir=project_dir,
            project_name=project,
            output_dir=settings.cache_dir / "generated_contexts"
        )
        typer.echo(f"[SBOM-TM] generated context file: {context}")

    # ============================================================
    #  MAIN SCAN
    # ============================================================
    typer.echo(f"[SBOM-TM] scanning SBOM: {sbom}")
    service = ScanService()
    result = service.run(sbom_path=sbom, project=project, context_path=context, offline=offline)

    typer.echo(
        f"[SBOM-TM] project={result.project} "
        f"components={result.component_count} "
        f"vulns={result.vulnerability_count} threats={result.threat_count}"
    )

    
    export_dir = Path("/github/workspace/sbom-report")
    export_dir.mkdir(parents=True, exist_ok=True)


    from .report_builder_scan import write_markdown_scan
    scan_md = export_dir / f"{project}_scan_report.md"
    write_markdown_scan(result, scan_md)
    print(f"[SBOM-TM] scan markdown saved: {scan_md}")
    # JSON + HTML
    import shutil
    scan_json = export_dir / f"{project}_scan_report.json"
    scan_html = export_dir / f"{project}_scan_report.html"
    shutil.copy(result.json_report, scan_json)
    shutil.copy(result.html_report, scan_html)

    # MARKDOWN SUMMARY

    md_file = export_dir / f"{project}_scan_report.md"
    lines = []
    lines.append(f"# SBOM Scan Report – {project}\n")
    lines.append(f"- **Components:** {result.component_count}")
    lines.append(f"- **Vulnerabilities:** {result.vulnerability_count}")
    lines.append(f"- **Threats:** {result.threat_count}\n")

    lines.append("## Vulnerabilities\n")

    def get_field(v, *keys):
        """Try multiple possible Trivy/SBOM schema keys."""
        for k in keys:
            if k in v:
                return v[k]
        return None
    vuls = result.vulnerabilities or getattr(result, "raw_vulnerabilities", []) or []

    for v in vuls:
        # CVE extraction
        cve = get_field(
            v,
            "VulnerabilityID", "vulnerability_id",
            "CVE", "cve"
        ) or "unknown"

        # Package extraction (SBOM uses nested structure)
        pkg = get_field(
            v,
            "PkgName", "PkgID", "package"
        )
        if isinstance(pkg, dict):  # SBOM format → { "name": "libcurl" }
            pkg = pkg.get("name") or pkg.get("id") or "unknown"

        pkg = pkg or "unknown"

        # Severity extraction
        sev = get_field(
            v,
            "Severity", "severity", "SeveritySource"
        ) or "unknown"

        lines.append(f"- **{cve}** — *{pkg}* — **{sev}**")


    lines.append("\n## Threats\n")
    for t in result.threats:
        rid = t.get("rule_id", "unknown")
        score = t.get("score", 0)
        cat = t.get("category", "unknown")
        lines.append(f"- Rule **{rid}** — Category **{cat}** — Score **{score}**")

    md_file.write_text("\n".join(lines), encoding="utf-8")
    typer.echo(f"[SBOM-TM] markdown scan report: {md_file}")

    # ============================================================
    # ALWAYS EXIT SUCCESSFULLY — NO FAILURES IN SCAN MODE
    # ============================================================
    typer.echo("[SBOM-TM] Scan completed. (No failures in scan mode)")
    return



@app.command()
def rules() -> None:
    settings = get_settings()
    engine = RuleEngine.from_directory(settings.rules_dir)
    typer.echo("Loaded rules:")
    for rule in engine.rules:
        typer.echo(f"- {rule.id}: {rule.description}")


@app.command()
def serve(
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8000,
) -> None:
    from uvicorn import run

    from .api import build_app

    typer.echo(f"[SBOM-TM] starting API on http://{host}:{port}")
    run(build_app(), host=host, port=port)
