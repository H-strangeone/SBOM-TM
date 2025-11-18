from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

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
