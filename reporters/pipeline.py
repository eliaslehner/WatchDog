import json
import sys

from models import Finding, Severity


def get_exit_code(findings: list[Finding]) -> int:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return 1
    return 0


def format_gitlab_report(findings: list[Finding]) -> str:
    """GitLab Code Quality compatible JSON report."""
    items = []
    for f in findings:
        items.append({
            "description": f.description,
            "check_name": f"watchdog/{f.scanner}",
            "fingerprint": f"{f.scanner}:{f.file_path}:{f.line}",
            "severity": _map_severity(f.severity),
            "location": {
                "path": f.file_path,
                "lines": {"begin": f.line or 1},
            },
        })
    return json.dumps(items, indent=2)


def _map_severity(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "blocker",
        Severity.WARNING: "major",
        Severity.INFO: "minor",
    }.get(severity, "info")
