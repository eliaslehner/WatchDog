from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from models import Finding

SEVERITY_STYLES = {
    "critical": "red bold",
    "warning": "yellow",
    "info": "blue",
}


def print_findings(findings: list[Finding], verbose: bool = False):
    console = Console()

    if not findings:
        console.print("\n[green]No findings. Clean scan.[/green]\n")
        return

    sorted_findings = sorted(
        findings,
        key=lambda x: ["critical", "warning", "info"].index(x.severity.value),
    )

    if verbose:
        _print_verbose(console, sorted_findings)
    else:
        _print_table(console, sorted_findings)

    critical_count = sum(1 for f in findings if f.severity.value == "critical")
    warning_count = sum(1 for f in findings if f.severity.value == "warning")
    info_count = sum(1 for f in findings if f.severity.value == "info")

    summary = f"  {len(findings)} finding(s): {critical_count} critical, {warning_count} warning, {info_count} info"
    if critical_count:
        console.print(f"\n[red bold]{summary}[/red bold]")
        console.print("[red]  Pipeline will be blocked.[/red]\n")
    else:
        console.print(f"\n{summary}\n")


def _print_table(console: Console, findings: list[Finding]):
    table = Table(title="WatchDog Scan Results")
    table.add_column("Severity")
    table.add_column("Scanner")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Description", max_width=60)

    for f in findings:
        style = SEVERITY_STYLES.get(f.severity.value, "")
        table.add_row(
            f"[{style}]{f.severity.value.upper()}[/{style}]",
            f.scanner,
            f.file_path,
            str(f.line),
            f.description,
        )

    console.print()
    console.print(table)


def _print_verbose(console: Console, findings: list[Finding]):
    console.print()
    for f in findings:
        style = SEVERITY_STYLES.get(f.severity.value, "")
        header = f"[{style}]{f.severity.value.upper()}[/{style}] {f.description}"
        location = f"{f.file_path}:{f.line}" if f.line else f.file_path

        lines = [f"[dim]Scanner:[/dim] {f.scanner}", f"[dim]Location:[/dim] {location}"]
        if f.context:
            lines.append(f"[dim]Context:[/dim]  {f.context[:120]}")
        if f.reasoning:
            lines.append(f"[dim]Reasoning:[/dim] {f.reasoning}")

        console.print(Panel("\n".join(lines), title=header, border_style=style or "dim"))
