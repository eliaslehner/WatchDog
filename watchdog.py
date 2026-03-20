import json
import sys

import click
from dotenv import load_dotenv

from orchestrator import run_scan, detect_framework
from reporters.console import print_findings

load_dotenv()


@click.group()
def cli():
    """WatchDog — security scanner for leaked credentials and misconfigs."""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--framework", default=None, help="Framework (auto-detected if omitted). e.g. nextjs, vite, django, rails")
@click.option("--target", default=None, help="Deployment target. e.g. vercel, aws, gcp")
@click.option("--output", "output_format", type=click.Choice(["console", "json", "gitlab"]), default="console")
@click.option("--scanners", default=None, help="Comma-separated scanner names. e.g. secrets,client-exposure,artifacts")
@click.option("--no-reasoning", is_flag=True, default=False, help="Skip Claude reasoning step")
def scan(path, framework, target, output_format, scanners, no_reasoning):
    """Scan a project directory for security issues."""
    scanner_list = [s.strip() for s in scanners.split(",")] if scanners else None

    detected = framework or detect_framework(path)
    if detected:
        click.echo(f"Framework: {detected}")

    findings = run_scan(
        path=path,
        framework=framework,
        target=target,
        scanners=scanner_list,
        reasoning=not no_reasoning,
    )

    if output_format == "console":
        print_findings(findings)
    elif output_format == "json":
        data = [
            {
                "severity": f.severity.value,
                "scanner": f.scanner,
                "file": f.file_path,
                "line": f.line,
                "description": f.description,
                "context": f.context,
                "reasoning": f.reasoning,
            }
            for f in findings
        ]
        click.echo(json.dumps(data, indent=2))
    elif output_format == "gitlab":
        from reporters.gitlab_mr import format_mr_comment
        click.echo(format_mr_comment(findings))

    # Exit with non-zero if critical findings
    critical = any(f.severity.value == "critical" for f in findings)
    if critical:
        sys.exit(1)


if __name__ == "__main__":
    cli()
