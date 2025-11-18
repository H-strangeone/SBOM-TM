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
    base_ref: Annotated[Optional[str], typer.Option("--base", "-b", help="Base ref (defaults to origin/main or HEAD~1)")]=None,
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
    # helper to run syft and write sbom to a temp file
    def _gen_sbom_for_ref(ref: Optional[str], target_dir: Optional[Path]) -> Path:
        # if ref is None and target_dir provided, generate from target_dir
        import shutil
        import subprocess, tempfile
        if shutil.which("syft") is None:
            raise typer.BadParameter("syft not found; install syft or provide SBOM files.")
        if ref:
            # create a temp workdir and use git to checkout ref
            tmpdir = Path(tempfile.mkdtemp())
            subprocess.run(["git", "clone", ".", str(tmpdir)], check=True)
            subprocess.run(["git", "checkout", ref], cwd=str(tmpdir), check=True)
            target = tmpdir
        else:
            if not target_dir:
                raise typer.BadParameter("target_dir is required when no ref provided")
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
        if git:
            # determine base ref
            if base_ref is None:
                # try merge-base with origin/main or default to HEAD~1
                try:
                    # prefer origin/main if exists
                    subprocess.run(["git", "fetch", "origin", "main"], check=False)
                    merge_base = subprocess.run(
                        ["git", "merge-base", "HEAD", "origin/main"], check=False, capture_output=True, text=True
                    ).stdout.strip()
                    if merge_base:
                        base_ref = merge_base
                    else:
                        base_ref = "HEAD~1"
                except Exception:
                    base_ref = "HEAD~1"
            # generate SBOMs
            typer.echo(f"[sbom-tm] generating SBOM for base ref: {base_ref}")
            temp_old = _gen_sbom_for_ref(base_ref, None)
            typer.echo(f"[sbom-tm] generating SBOM for HEAD")
            temp_new = _gen_sbom_for_ref("HEAD", None)
            sbom_old = temp_old
            sbom_new = temp_new
        else:
            if sbom_old is None or sbom_new is None:
                raise typer.BadParameter("Provide --old and --new SBOM paths or use --git")
        # Scan both using trivy (reuse existing trivy_client)
        typer.echo("[sbom-tm] scanning old SBOM...")
        old_report = scan_sbom(sbom_old, offline=offline)
        typer.echo("[sbom-tm] scanning new SBOM...")
        new_report = scan_sbom(sbom_new, offline=offline)
        old_index = extract_vulnerabilities(old_report)
        new_index = extract_vulnerabilities(new_report)

        # Helper to get set of CVEs from index
        def _cves_from_index(idx) -> Dict[Tuple[str, str], List[str]]:
            mapping = {}
            for (purl, pkg), vulns in idx.items():
                cves = []
                for v in vulns:
                    c = v.get("VulnerabilityID") or v.get("CVE") or v.get("vulnerability_id")
                    if c:
                        cves.append(str(c).upper())
                mapping[(purl, pkg)] = sorted(set(cves))
            return mapping

        old_cves_map = _cves_from_index(old_index)
        new_cves_map = _cves_from_index(new_index)

        # compute new CVEs: present in new but not in old
        new_only = []
        for key, new_cves in new_cves_map.items():
            old_cves = old_cves_map.get(key, [])
            added = [c for c in new_cves if c not in old_cves]
            if added:
                new_only.append({"component": key, "new_cves": added})

        # detect changes in component versions: parse SBOM components lists
        from .sbom_loader import load_components
        old_components = { (c.purl or c.name): c.version for c in load_components(sbom_old) }
        new_components = { (c.purl or c.name): c.version for c in load_components(sbom_new) }

        added_components = [k for k in new_components.keys() if k not in old_components.keys()]
        removed_components = [k for k in old_components.keys() if k not in new_components.keys()]
        version_changes = []
        for k, new_v in new_components.items():
            old_v = old_components.get(k)
            if old_v and new_v and old_v != new_v:
                version_changes.append({"component": k, "old": old_v, "new": new_v})

        # Build diff payload
        diff_payload = {
            "added_components": added_components,
            "removed_components": removed_components,
            "version_changes": version_changes,
            "new_vulnerabilities": new_only,
        }
                # --------------------------------------------------------
        #  RULE ENGINE + THREAT INTEL CHECK (NEW)
        # --------------------------------------------------------
        settings = get_settings()

        # Load full new-component list for threat modelling
        from .sbom_loader import load_components
        new_component_objs = load_components(sbom_new)

        typer.echo("[sbom-tm] generating context for rule engine...")
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
            typer.echo("[sbom-tm] evaluating rules against updated SBOM...")
            threats = engine.evaluate(new_component_objs, ctx)

        # Attach threats to diff output
        diff_payload["rule_engine_threats"] = threats

        # --------------------------------------------------------
        # CI POLICY CHECK FOR RULE ENGINE
        # --------------------------------------------------------
        ci = CiConfig(Path(".sbom-ci.yml"))
        fail_categories = ci.fail_on_rule_categories()
        min_score = ci.min_threat_score()

        triggered = [
            t for t in threats
            if t["score"] >= min_score and t["category"] in fail_categories
        ]

        if triggered:
            typer.echo("[sbom-tm] ❌ RuleEngine detected blocking threats.")
            typer.echo(f"[sbom-tm] Threat count: {len(triggered)}")
            raise typer.Exit(1)

        # --------------------------------------------------------
        # MARKDOWN REPORT GENERATION (used by GitHub PR comments)
        # --------------------------------------------------------
        report_dir = settings.cache_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        md_report = report_dir / f"{project}_sbom_diff.md"

        if engine:
            try:
                md_report.write_text(
                    engine.to_markdown(threats),
                    encoding="utf-8"
                )
                typer.echo(f"[sbom-tm] markdown diff report: {md_report}")
            except Exception as e:
                typer.echo(f"[sbom-tm] WARNING: unable to write markdown report: {e}")

        # Write diff report
        out = Path.cwd() / f"{project}_sbom_diff.json"
        out.write_text(json.dumps(diff_payload, indent=2), encoding="utf-8")
        typer.echo(f"[sbom-tm] diff written to: {out}")

        # Determine policy triggers (use existing CiConfig)
        ci = CiConfig(Path(".sbom-ci.yml"))
        fail_sev = ci.fail_on_severities()
        # load severity for new-only CVEs by scanning new_report details
        # quick approach: gather severities for new CVEs
        new_cve_set = {c for entry in new_only for c in entry["new_cves"]}
        severity_map = {}
        for (purl, pkg), vulns in new_index.items():
            for v in vulns:
                c = (v.get("VulnerabilityID") or v.get("CVE") or "").upper()
                if c in new_cve_set:
                    sev = v.get("Severity") or v.get("Severity")
                    severity_map[c] = sev
        # if any new CVE has severity we must fail according to fail_sev
        for cve, sev in severity_map.items():
            if sev and sev.upper() in fail_sev:
                typer.echo(f"[sbom-tm] ❌ New {sev} vulnerability introduced: {cve}")
                raise typer.Exit(1)

        typer.echo("[sbom-tm] ✅ No blocking new vulnerabilities found.")
        return

    finally:
        # cleanup temp files if any
        try:
            if temp_old:
                Path(temp_old).unlink()
            if temp_new:
                Path(temp_new).unlink()
        except Exception:
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
        typer.Argument(
            exists=True,
            readable=True,
            help="Path to project directory for SBOM generation",
        ),
    ] = None,
    sbom: Annotated[
        Optional[Path],
        typer.Option(
            "--sbom",
            exists=True,
            readable=True,
            help="Path to CycloneDX SBOM file",
        ),
    ] = None,
    project: Annotated[
        str,
        typer.Option("--project", "-p", help="Project identifier"),
    ] = "default",
    context: Annotated[
        Optional[Path],
        typer.Option(
            "--context",
            exists=True,
            readable=True,
            help="Optional service context mapping JSON",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(help="Use Trivy offline scan mode"),
    ] = False,
) -> None:
    temp_sbom: Optional[Path] = None

    project_dir: Optional[Path] = Path(path).expanduser().resolve() if path else None

    if sbom is None and project_dir is None:
        typer.echo("Please provide either --sbom <path> or --path <path>")
        return
    if sbom is None:
        import shutil
        import subprocess
        import tempfile

        if project_dir is None:
            raise typer.BadParameter("--path is required when generating an SBOM automatically")

        if shutil.which("syft") is None:
            raise typer.BadParameter("syft not found. Install syft or provide --sbom <path>.")

        typer.echo("[SBOM-TM] generating SBOM using syft...")
        proc = subprocess.run(
            ["syft", str(project_dir), "-o", "cyclonedx-json"],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            typer.echo(f"syft failed: {proc.stderr.strip()}")
            raise typer.Exit(code=1)

        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tf.write(proc.stdout.encode("utf-8"))
        tf.flush()
        tf.close()
        temp_sbom = Path(tf.name)
        sbom = temp_sbom

    if sbom is None:
        raise typer.BadParameter("Unable to resolve SBOM path")

    settings = get_settings()

    if context is None:
        generated_context = generate_context_file(
            sbom_path=sbom,
            project_dir=project_dir,
            project_name=project,
            output_dir=settings.cache_dir / "generated_contexts",
        )
        typer.echo(f"[SBOM-TM] generated context file: {generated_context}")
        context = generated_context

    typer.echo(f"[SBOM-TM] scanning SBOM: {sbom}")
    service = ScanService()
    result = service.run(sbom_path=sbom, project=project, context_path=context, offline=offline)
    typer.echo(
        f"[SBOM-TM] project={result.project} components={result.component_count}"
        f" vulns={result.vulnerability_count} threats={result.threat_count}"
    )
    
    typer.echo(f"[SBOM-TM] json report: {result.json_report}")
    typer.echo(f"[SBOM-TM] html report: {result.html_report}")
    fail_severities = ci_config.fail_on_severities()
    fail_categories = ci_config.fail_on_rule_categories()
    ignored_cves = ci_config.ignore_cves()
    ignored_pkgs = ci_config.ignore_packages()
    min_score = ci_config.min_threat_score()
    allow_transitive = ci_config.allow_transitive()

    # 1️⃣ Fail on Rule Engine threats
    triggered_threats = [
        t for t in result.threats
        if t["score"] >= min_score and t["category"] in fail_categories
    ]

    if triggered_threats:
        typer.echo("[SBOM-TM] ❌ Rule Engine threats detected matching CI policy.")
        raise typer.Exit(1)

    # 2️⃣ Fail on Vulnerabilities (Trivy)
    # sev = getattr(result, "severity_counts", {})
    filtered_vulns = [
        v for v in result.vulnerabilities
        if v["cve"] not in ignored_cves
        and v["package"] not in ignored_pkgs
    ]

    # Recompute severity counts after filtering
    sev = {}
    for v in filtered_vulns:
        sev[v["severity"]] = sev.get(v["severity"], 0) + 1

    for severity, count in sev.items():
        if severity in fail_severities and count > 0:
            typer.echo(f"[SBOM-TM] ❌ {severity} vulnerabilities detected (CI policy).")
            raise typer.Exit(1)

    # 3️⃣ Check ignored CVEs
    violating_cves = [
        v for v in result.vulnerabilities
        if v["cve"] not in ignored_cves
    ]

    # 4️⃣ Check ignored packages
    violating_pkgs = [
        v for v in violating_cves
        if v["package"] not in ignored_pkgs
    ]

    if violating_pkgs:
        typer.echo("[SBOM-TM] ❌ Vulnerabilities (after ignore list) still present.")
        raise typer.Exit(1)

    
    typer.echo("[SBOM-TM] ✅ No CI policy violations.")
    if temp_sbom is not None:
        try:
            temp_sbom.unlink()
        except Exception:
            pass


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
