import json
import sys

import click
from dotenv import load_dotenv

from orchestrator import run_scan, detect_framework, SCANNER_MAP
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
@click.option("--output", "output_format", type=click.Choice(["console", "json", "gitlab", "codequality"]), default="console")
@click.option("--scanners", default=None, help="Comma-separated scanner names. e.g. secrets,client-exposure,artifacts")
@click.option("--no-reasoning", is_flag=True, default=False, help="Skip Claude reasoning step")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show detailed findings with context and reasoning")
@click.option("--exclude", multiple=True, help="Directory names to exclude from scanning (repeatable)")
def scan(path, framework, target, output_format, scanners, no_reasoning, verbose, exclude):
    """Scan a project directory for security issues."""
    scanner_list = None
    if scanners:
        scanner_list = [s.strip() for s in scanners.split(",")]
        invalid = [s for s in scanner_list if s not in SCANNER_MAP]
        if invalid:
            valid = ", ".join(SCANNER_MAP.keys())
            click.echo(f"Error: unknown scanner(s): {', '.join(invalid)}", err=True)
            click.echo(f"Valid scanners: {valid}", err=True)
            sys.exit(2)

    detected = framework or detect_framework(path)
    if detected:
        click.echo(f"Framework: {detected}")

    findings = run_scan(
        path=path,
        framework=framework,
        target=target,
        scanners=scanner_list,
        reasoning=not no_reasoning,
        exclude=list(exclude) if exclude else None,
    )

    if output_format == "console":
        print_findings(findings, verbose=verbose)
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
    elif output_format == "codequality":
        from reporters.pipeline import format_gitlab_report
        click.echo(format_gitlab_report(findings))

    from reporters.pipeline import get_exit_code
    sys.exit(get_exit_code(findings))


@cli.command(name="list-scanners")
def list_scanners():
    """List available scanner names."""
    for name in SCANNER_MAP:
        click.echo(name)


if __name__ == "__main__":
    cli()
