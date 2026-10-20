"""Human-readable and machine-readable report generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def print_terminal_summary(evidence: dict[str, Any], console: Console | None = None) -> None:
    """Print a concise terminal summary of a verification run."""
    console = console or Console()
    summary = evidence.get("summary") or {}
    overall = summary.get("overall_status", "unknown")
    counts = summary.get("check_counts") or {}
    finding_count = summary.get("finding_count", 0)
    repo = evidence.get("repository") or {}
    tool = evidence.get("tool") or {}

    color = {
        "passed": "green",
        "failed": "red",
        "errored": "yellow",
        "skipped": "dim",
    }.get(overall, "white")

    header = Text()
    header.append("ProofMesh ", style="bold")
    header.append(f"v{tool.get('version', '?')}", style="dim")
    header.append("  ·  ")
    header.append(overall.upper(), style=f"bold {color}")

    console.print(Panel(header, title="Verification Summary", border_style=color))

    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim")
    info.add_column()
    info.add_row("Run ID", evidence.get("run_id", ""))
    info.add_row("Commit", (repo.get("head_commit_short") or repo.get("head_commit") or "—"))
    info.add_row("Branch", repo.get("branch") or ("(detached)" if repo.get("is_detached") else "—"))
    info.add_row("Dirty", "yes" if repo.get("is_dirty") else "no")
    info.add_row(
        "Checks",
        f"passed={counts.get('passed', 0)}  failed={counts.get('failed', 0)}  "
        f"skipped={counts.get('skipped', 0)}  errored={counts.get('errored', 0)}",
    )
    info.add_row("Findings", str(finding_count))
    console.print(info)
    console.print()

    checks = evidence.get("checks") or []
    if checks:
        table = Table(title="Checks", show_lines=False)
        table.add_column("Check", style="cyan")
        table.add_column("Status")
        table.add_column("Findings", justify="right")
        table.add_column("Duration", justify="right")
        table.add_column("Message")
        for c in checks:
            st = c.get("status", "")
            st_style = {
                "passed": "green",
                "failed": "red",
                "errored": "yellow",
                "skipped": "dim",
            }.get(st, "")
            table.add_row(
                c.get("check_id", ""),
                Text(st, style=st_style),
                str(len(c.get("findings") or [])),
                f"{c.get('duration_ms', 0):.0f} ms",
                (c.get("message") or "")[:60],
            )
        console.print(table)
        console.print()

    all_findings = []
    for c in checks:
        for f in c.get("findings") or []:
            all_findings.append(f)
    if all_findings:
        ft = Table(title="Findings", show_lines=False)
        ft.add_column("Severity", style="bold")
        ft.add_column("Rule")
        ft.add_column("Location")
        ft.add_column("Message")
        for f in all_findings[:50]:
            loc = f.get("path", "")
            if f.get("line"):
                loc += f":{f['line']}"
            ft.add_row(
                f.get("severity", ""),
                f.get("rule_id", ""),
                loc,
                f.get("message", "")[:50],
            )
        console.print(ft)
        if len(all_findings) > 50:
            console.print(f"[dim]… and {len(all_findings) - 50} more findings[/dim]")
        console.print()

    limitations = evidence.get("limitations") or []
    if limitations:
        console.print("[dim]Limitations:[/dim]")
        for lim in limitations[:8]:
            console.print(f"  [dim]• {lim}[/dim]")

    integrity = evidence.get("integrity") or {}
    if integrity.get("signed"):
        console.print(f"\n[green]Signed[/green] (hint: {integrity.get('public_key_hint', '')})")
    else:
        console.print("\n[dim]Integrity: content hash present (unsigned)[/dim]")


def write_markdown_report(evidence: dict[str, Any], path: Path) -> None:
    """Write a Markdown report."""
    summary = evidence.get("summary") or {}
    repo = evidence.get("repository") or {}
    lines = [
        "# ProofMesh Verification Report",
        "",
        f"- **Run ID**: `{evidence.get('run_id', '')}`",
        f"- **Created**: {evidence.get('created_at', '')}",
        f"- **Overall**: **{summary.get('overall_status', 'unknown')}**",
        f"- **Commit**: `{repo.get('head_commit') or '—'}`",
        f"- **Branch**: {repo.get('branch') or '—'}",
        f"- **Findings**: {summary.get('finding_count', 0)}",
        "",
        "## Checks",
        "",
        "| Check | Status | Findings | Duration |",
        "|-------|--------|----------|----------|",
    ]
    for c in evidence.get("checks") or []:
        lines.append(
            f"| {c.get('check_id')} | {c.get('status')} | "
            f"{len(c.get('findings') or [])} | {c.get('duration_ms', 0):.0f} ms |"
        )
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    findings = []
    for c in evidence.get("checks") or []:
        findings.extend(c.get("findings") or [])
    if not findings:
        lines.append("_No findings._")
    else:
        for f in findings:
            loc = f.get("path", "")
            if f.get("line"):
                loc += f":{f['line']}"
            lines.append(
                f"- **[{f.get('severity')}]** `{f.get('rule_id')}` @ `{loc}` — {f.get('message')}"
            )
            if f.get("remediation"):
                lines.append(f"  - Remediation: {f['remediation']}")
            if f.get("matched_preview"):
                lines.append(f"  - Preview: `{f['matched_preview']}`")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for lim in evidence.get("limitations") or []:
        lines.append(f"- {lim}")
    lines.append("")
    integrity = evidence.get("integrity") or {}
    lines.append("## Integrity")
    lines.append("")
    lines.append(f"- Algorithm: `{integrity.get('algorithm')}`")
    lines.append(f"- Content hash: `{integrity.get('content_hash')}`")
    lines.append(f"- Signed: {integrity.get('signed', False)}")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
