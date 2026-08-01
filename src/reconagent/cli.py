from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from reconagent.aggregator import run_recon
from reconagent.correlator import correlate
from reconagent.llm_pivot import summarize
from reconagent.opsec import build_opsec_findings
from reconagent.reporting import write_html_report, write_json_report

console = Console()


@click.group()
def cli():
    """ReconAgent — passive, public-source-only OSINT reconnaissance."""


@cli.command()
@click.option("--target", required=True, help="The target value: domain, username, phone, or file path (image/pdf).")
@click.option("--type", "target_type", required=True,
              type=click.Choice(["domain", "username", "email", "phone", "image", "pdf"]),
              help="What kind of target this is.")
@click.option("--out", default="report", help="Output filename base (no extension).")
@click.option("--format", "formats", multiple=True, default=("html", "json"),
              type=click.Choice(["html", "json"]), help="Report format(s) to write.")
@click.option("--llm-backend", default="none", type=click.Choice(["none", "ollama", "groq"]),
              help="LLM backend for the summary/pivot layer. 'none' uses a deterministic template.")
@click.option("--timeout", default=30, help="Per-collector timeout in seconds.")
def run(target: str, target_type: str, out: str, formats: tuple[str, ...],
        llm_backend: str, timeout: int):
    """Run a full recon sweep against a single target."""
    console.print(f"[cyan]›[/cyan] running collectors for [bold]{target_type}[/bold]: {target}")
    results = run_recon(target, target_type, timeout_s=timeout)

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Collector")
    table.add_column("Status")
    table.add_column("Findings")
    for r in results:
        status = "[green]ok[/green]" if r.ok else f"[yellow]skip/fail[/yellow] {r.error or ''}"
        table.add_row(r.collector, status, str(len(r.findings)))
    console.print(table)

    correlation = correlate(results)
    opsec_findings = build_opsec_findings(results)
    llm_summary = summarize(results, correlation, backend=llm_backend)

    console.print("\n[bold cyan]AI Summary[/bold cyan]")
    console.print(llm_summary)

    if opsec_findings:
        console.print(f"\n[bold yellow]{len(opsec_findings)} OPSEC finding(s) flagged[/bold yellow]")

    for fmt in formats:
        path = f"{out}.{fmt}"
        if fmt == "json":
            write_json_report(path, target, target_type, results, correlation, opsec_findings, llm_summary)
        elif fmt == "html":
            write_html_report(path, target, target_type, results, correlation, opsec_findings, llm_summary)
        console.print(f"[green]✓[/green] wrote {path}")


@cli.command(name="list-collectors")
def list_collectors():
    """Show every registered collector grouped by target type."""
    from reconagent.collectors import REGISTRY
    for target_type, collectors in REGISTRY.items():
        console.print(f"\n[bold cyan]{target_type}[/bold cyan]")
        for c in collectors:
            key_note = f" (requires {c.key_env_var})" if c.requires_key else ""
            console.print(f"  - {c.name}{key_note}")


if __name__ == "__main__":
    cli()
