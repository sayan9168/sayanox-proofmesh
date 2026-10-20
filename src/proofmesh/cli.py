"""ProofMesh command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from proofmesh import __version__
from proofmesh.checks.base import CheckStatus
from proofmesh.checks.osv import OSVCheck
from proofmesh.config import load_config, write_default_config
from proofmesh.evidence import (
    build_evidence,
    load_evidence,
    verify_evidence_integrity,
    write_evidence,
)
from proofmesh.export_pkg import export_evidence_zip
from proofmesh.gitdiff import inspect_repository
from proofmesh.integrity import generate_keypair, save_keypair, sign_evidence, verify_signature
from proofmesh.orchestrator import CORE_CHECK_IDS, Orchestrator
from proofmesh.policy import apply_policy, get_profile, list_profiles
from proofmesh.reports import print_terminal_summary, write_markdown_report
from proofmesh.rules import list_builtin_rules
from proofmesh.sarif import evidence_to_sarif
from proofmesh.schema_validate import validate_evidence
from proofmesh.storage import Storage
from proofmesh.suppressions import SuppressionSet

app = typer.Typer(
    name="proofmesh",
    help="SAYANOX ProofMesh — local-first software verification and evidence engine.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(stderr=True)


def _exit_for_status(overall: str) -> None:
    if overall == "passed":
        raise typer.Exit(0)
    if overall == "failed":
        raise typer.Exit(1)
    if overall == "errored":
        raise typer.Exit(2)
    raise typer.Exit(3)


@app.command()
def version() -> None:
    """Print version and exit."""
    console.print(f"sayanox-proofmesh {__version__}")


@app.command()
def init(
    path: Path = typer.Option(Path("."), "--path", "-p", help="Project path"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
) -> None:
    """Initialize ProofMesh configuration in the current project."""
    path = path.resolve()
    config_path = path / "proofmesh.json"
    evidence_dir = path / ".proofmesh" / "evidence"
    if config_path.exists() and not force:
        console.print(f"[yellow]Config already exists:[/yellow] {config_path}")
        console.print("Use --force to overwrite.")
        raise typer.Exit(1)
    write_default_config(config_path)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (path / ".proofmesh" / ".gitkeep").write_text("", encoding="utf-8")
    console.print(f"[green]Initialized[/green] ProofMesh at {path}")
    console.print(f"  Config:   {config_path}")
    console.print(f"  Evidence: {evidence_dir}")


@app.command()
def inspect(
    path: Path = typer.Option(Path("."), "--path", "-p", help="Repository path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """Inspect repository state and changed files."""
    state = inspect_repository(path)
    if json_out:
        print(json.dumps(state.to_dict(), indent=2))
    else:
        console.print(f"Root:     {state.root}")
        console.print(f"Git:      {state.is_git}")
        console.print(f"Commit:   {state.head_commit or '—'}")
        console.print(f"Branch:   {state.branch or ('(detached)' if state.is_detached else '—')}")
        console.print(f"Dirty:    {state.is_dirty}")
        console.print(f"Changes:  {len(state.changes)}")
        if state.inventory_incomplete:
            console.print("[yellow]Inventory incomplete[/yellow]")
            for e in state.inventory_errors:
                console.print(f"  • {e}")
        for c in state.changes[:30]:
            console.print(f"  [{c.status}] {c.path}" + (f" (from {c.old_path})" if c.old_path else ""))
        if len(state.changes) > 30:
            console.print(f"  … and {len(state.changes) - 30} more")


@app.command()
def verify(
    path: Path = typer.Option(Path("."), "--path", "-p", help="Repository path"),
    only: Optional[str] = typer.Option(None, "--only", help="Comma-separated check IDs"),
    with_osv: bool = typer.Option(False, "--with-osv", help="Enable OSV vulnerability lookup (network)"),
    with_gitleaks: bool = typer.Option(False, "--with-gitleaks", help="Run gitleaks if installed"),
    with_semgrep: bool = typer.Option(False, "--with-semgrep", help="Run semgrep if installed"),
    suppressions_file: Optional[Path] = typer.Option(
        None, "--suppressions", help="JSON suppressions with justification"
    ),
    policy: str = typer.Option(
        "standard",
        "--policy",
        help="Severity gate: strict | standard | relaxed | critical-only",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Evidence JSON path"),
    markdown: Optional[Path] = typer.Option(None, "--markdown", "-m", help="Markdown report path"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif", help="Write SARIF 2.1 report"),
    sign_key: Optional[Path] = typer.Option(None, "--sign-key", help="Ed25519 private key PEM to sign"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal summary"),
) -> None:
    """Run verification checks and produce evidence."""
    config = load_config()
    orch = Orchestrator(config)

    if only:
        only_list = [x.strip() for x in only.split(",") if x.strip()]
    else:
        only_list = list(CORE_CHECK_IDS)
        if with_osv:
            only_list.append("osv")
            orch.register("osv", lambda s: OSVCheck(enabled=True).run(s))
        if with_gitleaks:
            only_list.append("gitleaks")
        if with_semgrep:
            only_list.append("semgrep")

    state, results = orch.run(path=path, only=only_list)

    suppressed_audit: list[dict] = []
    if suppressions_file:
        try:
            sset = SuppressionSet.load(suppressions_file)
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Invalid suppressions file:[/red] {exc}")
            raise typer.Exit(2)
        for r in results:
            if not r.findings:
                continue
            active, audit = sset.filter_findings(r.findings)
            r.findings = active
            suppressed_audit.extend(audit)
            if not active and r.status == CheckStatus.FAILED:
                r.status = CheckStatus.PASSED
                r.message = (r.message or "") + f" ({len(audit)} suppressed)"
                r.exit_code = 0

    evidence = build_evidence(state, results)
    if suppressed_audit:
        evidence.setdefault("limitations", []).append(
            f"{len(suppressed_audit)} finding(s) suppressed with recorded justification."
        )
        evidence["suppressed_findings"] = suppressed_audit

    try:
        profile = get_profile(policy)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)
    all_findings = []
    for r in results:
        all_findings.extend(r.findings or [])
    gate_status, blocking, informational = apply_policy(all_findings, profile)
    evidence["policy"] = {
        "profile": profile.id,
        "description": profile.description,
        "gate_status": gate_status,
        "blocking_count": len(blocking),
        "informational_count": len(informational),
    }
    if gate_status == "failed" and evidence["summary"]["overall_status"] == "passed":
        evidence["summary"]["overall_status"] = "failed"
    elif gate_status == "passed" and evidence["summary"]["overall_status"] == "failed":
        if not blocking and evidence["summary"].get("check_counts", {}).get("errored", 0) == 0:
            evidence["summary"]["overall_status"] = "passed"

    if sign_key:
        if not sign_key.is_file():
            console.print(f"[red]Signing key not found:[/red] {sign_key}")
            raise typer.Exit(2)
        evidence = sign_evidence(evidence, sign_key.read_bytes())

    out_path = output
    if out_path is None:
        evidence_dir = path.resolve() / ".proofmesh" / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        out_path = evidence_dir / f"{evidence['run_id']}.evidence.json"

    file_hash = write_evidence(evidence, out_path)

    db = Storage(path.resolve() / ".proofmesh" / "runs.db")
    db.record_run(
        evidence["run_id"],
        evidence["summary"]["overall_status"],
        head_commit=state.head_commit,
        branch=state.branch,
        root_path=str(state.root),
        finding_count=evidence["summary"]["finding_count"],
        evidence_path=str(out_path),
        evidence_hash=file_hash,
        summary=evidence["summary"],
    )

    if markdown:
        write_markdown_report(evidence, markdown)
    if sarif_out:
        sarif_doc = evidence_to_sarif(evidence)
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8")
        if not quiet:
            console.print(f"SARIF written: {sarif_out}")

    if not quiet:
        print_terminal_summary(evidence, console=console)
        console.print(f"\nEvidence written: {out_path}")

    _exit_for_status(evidence["summary"]["overall_status"])


@app.command("evidence")
def evidence_cmd(
    action: str = typer.Argument(..., help="verify | show"),
    path: Path = typer.Argument(..., help="Path to evidence JSON"),
    public_key: Optional[Path] = typer.Option(None, "--public-key", help="Ed25519 public key for signature check"),
) -> None:
    """Inspect or verify an evidence bundle."""
    if not path.is_file():
        console.print(f"[red]File not found:[/red] {path}")
        raise typer.Exit(2)
    try:
        evidence = load_evidence(path)
    except (json.JSONDecodeError, ValueError) as exc:
        console.print(f"[red]Invalid evidence:[/red] {exc}")
        raise typer.Exit(2)

    if action == "show":
        print_terminal_summary(evidence, console=console)
        return

    if action == "verify":
        ok, msg = verify_evidence_integrity(evidence)
        if ok:
            console.print(f"[green]Integrity OK:[/green] {msg}")
        else:
            console.print(f"[red]Integrity FAILED:[/red] {msg}")
            raise typer.Exit(1)
        if public_key:
            if not public_key.is_file():
                console.print(f"[red]Public key not found:[/red] {public_key}")
                raise typer.Exit(2)
            sok, smsg = verify_signature(evidence, public_key.read_bytes())
            if sok:
                console.print(f"[green]Signature OK:[/green] {smsg}")
            else:
                console.print(f"[red]Signature FAILED:[/red] {smsg}")
                raise typer.Exit(1)
        elif evidence.get("integrity", {}).get("signed"):
            console.print("[yellow]Evidence is signed but no --public-key provided; signature not verified.[/yellow]")
        return

    console.print(f"[red]Unknown action:[/red] {action} (use verify or show)")
    raise typer.Exit(2)


@app.command("rules")
def rules_cmd(
    list_rules: bool = typer.Option(True, "--list", help="List built-in rules"),
) -> None:
    """List built-in detection rules."""
    rules = list_builtin_rules()
    for category, items in rules.items():
        console.print(f"\n[bold]{category}[/bold]")
        for r in items:
            console.print(f"  {r['id']}  [{r.get('severity', '?')}]  {r.get('name', '')}")


@app.command("report")
def report_cmd(
    evidence_path: Path = typer.Argument(..., help="Evidence JSON path"),
    markdown: Optional[Path] = typer.Option(None, "--markdown", "-m"),
) -> None:
    """Generate reports from an existing evidence file."""
    evidence = load_evidence(evidence_path)
    print_terminal_summary(evidence, console=console)
    if markdown:
        write_markdown_report(evidence, markdown)
        console.print(f"Markdown written: {markdown}")


@app.command("keygen")
def keygen(
    out_dir: Path = typer.Option(Path(".proofmesh/keys"), "--out", "-o"),
) -> None:
    """Generate an Ed25519 key pair for optional evidence signing."""
    priv, pub = generate_keypair()
    save_keypair(priv, pub, out_dir)
    console.print(f"[green]Key pair written to[/green] {out_dir}")
    console.print("  Protect the private key (mode 600). Never commit it.")


@app.command("schema")
def schema_cmd(
    action: str = typer.Argument("validate", help="validate"),
    evidence_path: Path = typer.Argument(..., help="Evidence JSON path"),
    schema_path: Optional[Path] = typer.Option(None, "--schema", help="Override schema path"),
) -> None:
    """Validate an evidence file against the JSON Schema."""
    if action != "validate":
        console.print(f"[red]Unknown action:[/red] {action}")
        raise typer.Exit(2)
    try:
        evidence = load_evidence(evidence_path)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        console.print(f"[red]Cannot load evidence:[/red] {exc}")
        raise typer.Exit(2)
    from proofmesh.schema_validate import load_schema

    try:
        schema = load_schema(schema_path) if schema_path else load_schema()
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)
    ok, errors = validate_evidence(evidence, schema)
    if ok:
        console.print("[green]Schema validation OK[/green]")
        raise typer.Exit(0)
    console.print(f"[red]Schema validation failed ({len(errors)} error(s))[/red]")
    for e in errors[:30]:
        console.print(f"  • {e}")
    raise typer.Exit(1)


@app.command("sarif")
def sarif_cmd(
    evidence_path: Path = typer.Argument(..., help="Evidence JSON path"),
    output: Path = typer.Option(Path("proofmesh.sarif"), "--output", "-o"),
) -> None:
    """Export evidence findings to SARIF 2.1.0."""
    evidence = load_evidence(evidence_path)
    doc = evidence_to_sarif(evidence)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    console.print(f"SARIF written: {output} ({len(doc['runs'][0]['results'])} result(s))")


@app.command("export")
def export_cmd(
    evidence_path: Path = typer.Argument(..., help="Evidence JSON path"),
    output: Path = typer.Option(Path("proofmesh-export.zip"), "--output", "-o"),
    markdown: Optional[Path] = typer.Option(None, "--markdown", "-m"),
    sarif: Optional[Path] = typer.Option(None, "--sarif"),
) -> None:
    """Package evidence (+ optional reports) into a zip archive."""
    try:
        path = export_evidence_zip(
            evidence_path,
            output,
            include_markdown=markdown,
            include_sarif=sarif,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]Export failed:[/red] {exc}")
        raise typer.Exit(2)
    console.print(f"[green]Export written:[/green] {path}")


@app.command("policy")
def policy_cmd(
    list_only: bool = typer.Option(True, "--list", help="List policy profiles"),
) -> None:
    """List severity policy profiles used by `verify --policy`."""
    for p in list_profiles():
        console.print(f"[bold]{p['id']}[/bold]  fail_on={','.join(p['fail_on'])}")
        console.print(f"  {p['description']}")


@app.command("compare")
def compare_cmd(
    a: Path = typer.Argument(..., help="First evidence JSON"),
    b: Path = typer.Argument(..., help="Second evidence JSON"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON diff summary"),
) -> None:
    """Compare two evidence runs (status, finding counts, rule IDs)."""
    ea = load_evidence(a)
    eb = load_evidence(b)

    def finding_keys(ev: dict) -> set[str]:
        keys: set[str] = set()
        for c in ev.get("checks") or []:
            for f in c.get("findings") or []:
                keys.add(f"{f.get('rule_id','')}|{f.get('path','')}|{f.get('line','')}")
        return keys

    ka, kb = finding_keys(ea), finding_keys(eb)
    only_a = sorted(ka - kb)
    only_b = sorted(kb - ka)
    summary = {
        "a": {
            "run_id": ea.get("run_id"),
            "overall": (ea.get("summary") or {}).get("overall_status"),
            "findings": (ea.get("summary") or {}).get("finding_count"),
        },
        "b": {
            "run_id": eb.get("run_id"),
            "overall": (eb.get("summary") or {}).get("overall_status"),
            "findings": (eb.get("summary") or {}).get("finding_count"),
        },
        "only_in_a": only_a[:100],
        "only_in_b": only_b[:100],
        "shared": len(ka & kb),
    }
    if json_out:
        print(json.dumps(summary, indent=2))
        return
    console.print(f"A: {summary['a']['run_id']}  status={summary['a']['overall']}  findings={summary['a']['findings']}")
    console.print(f"B: {summary['b']['run_id']}  status={summary['b']['overall']}  findings={summary['b']['findings']}")
    console.print(f"Shared finding keys: {summary['shared']}")
    console.print(f"Only in A: {len(only_a)}")
    for x in only_a[:15]:
        console.print(f"  - {x}")
    console.print(f"Only in B: {len(only_b)}")
    for x in only_b[:15]:
        console.print(f"  - {x}")


if __name__ == "__main__":
    app()
