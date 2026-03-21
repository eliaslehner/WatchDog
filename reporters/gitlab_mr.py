from models import Finding, Severity

SEVERITY_EMOJI = {
    "critical": "\u274c",  # red X
    "warning": "\u26a0\ufe0f",   # warning sign
    "info": "\u2139\ufe0f",      # info
}


def format_mr_comment(findings: list[Finding]) -> str:
    if not findings:
        return "## WatchDog Security Scan\n\nNo issues found. Clean scan."

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    info = [f for f in findings if f.severity == Severity.INFO]

    parts = ["## WatchDog Security Scan\n"]

    if critical:
        parts.append(f"**{len(critical)} critical** | {len(warnings)} warning | {len(info)} info\n")
        parts.append("> **Pipeline blocked** — critical findings must be resolved before merge.\n")
    else:
        parts.append(f"{len(warnings)} warning | {len(info)} info\n")

    if critical:
        parts.append("### Critical\n")
        for f in critical:
            parts.append(_format_finding(f))

    if warnings:
        parts.append("### Warnings\n")
        for f in warnings:
            parts.append(_format_finding(f))

    if info:
        parts.append("<details>\n<summary>Info ({} items)</summary>\n".format(len(info)))
        for f in info:
            parts.append(_format_finding(f))
        parts.append("</details>\n")

    return "\n".join(parts)


def _format_finding(f: Finding) -> str:
    emoji = SEVERITY_EMOJI.get(f.severity.value, "")
    location = f"`{f.file_path}:{f.line}`" if f.line else f"`{f.file_path}`"

    lines = [f"- {emoji} **{f.description}** ({f.scanner})"]
    lines.append(f"  {location}")

    if f.context:
        lines.append(f"  `{f.context[:100]}`")

    if f.reasoning:
        lines.append(f"  > {f.reasoning}")

    lines.append("")
    return "\n".join(lines)
