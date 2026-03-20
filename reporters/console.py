from rich.console import Console
from rich.table import Table

from models import Finding

SEVERITY_STYLES = {
    "critical": "red bold",
    "warning": "yellow",
    "info": "blue",
}


def print_findings(findings: list[Finding]):
    console = Console()

    if not findings:
        console.print("\n[green]No findings. Clean scan.[/green]\n")
        return

    table = Table(title="WatchDog Scan Results")
    table.add_column("Severity")
    table.add_column("Scanner")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Description", max_width=60)

    for f in sorted(findings, key=lambda x: ["critical", "warning", "info"].index(x.severity.value)):
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

    critical_count = sum(1 for f in findings if f.severity.value == "critical")
    warning_count = sum(1 for f in findings if f.severity.value == "warning")
    console.print(f"\n  {len(findings)} finding(s): {critical_count} critical, {warning_count} warning\n")
