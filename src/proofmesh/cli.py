"""ProofMesh command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from proofmesh import __version__
from proofmesh.config import load_config, write_default_config
from proofmesh.evidence import (
    build_evidence,
    load_evidence,
    verify_evidence_integrity,
    write_evidence,
)
from proofmesh.gitdiff import inspect_repository
from proofmesh.integrity import generate_keypair, save_keypair, sign_evidence, verify_signature
from proofmesh.orchestrator import Orchestrator
from proofmesh.reports import print_terminal_summary, write_markdown_report
from proofmesh.rules import list_builtin_rules
from proofmesh.storage import Storage

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
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Evidence JSON path"),
    markdown: Optional[Path] = typer.Option(None, "--markdown", "-m", help="Markdown report path"),
    sign_key: Optional[Path] = typer.Option(None, "--sign-key", help="Ed25519 private key PEM to sign"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal summary"),
) -> None:
    """Run verification checks and produce evidence."""
    config = load_config()
    orch = Orchestrator(config)
    only_list = [x.strip() for x in only.split(",")] if only else None
    state, results = orch.run(path=path, only=only_list)
    evidence = build_evidence(state, results)

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

    if not quiet:
        print_terminal_summary(evidence, console=console)
        console.print(f"\nEvidence written: {out_path}")

    _exit_for_status(evidence["summary"]["overall_status"])


@app.command("evidence")
def evidence_cmd(
    action: str = typer.Argument(..., help="verify | show"),
    path: Path = typer.Argument(..., help="Path to evidence JSON"),
    public_key: Optional[Path] = typer.Option(None, "--public-key", help="Ed25519 public key"),
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
            console.print("[yellow]Evidence is signed but no --public-key provided.[/yellow]")
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


if __name__ == "__main__":
    app()
