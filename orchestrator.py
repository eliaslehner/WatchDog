import json
from pathlib import Path

from agents.secret_scanner import SecretScanner
from agents.client_exposure import ClientExposureAnalyzer
from agents.env_tracer import EnvTracer
from agents.config_checker import ConfigChecker
from agents.iac_scanner import IacScanner
from agents.dep_checker import DepChecker
from agents.artifact_inspector import ArtifactInspector
from models import Finding


SCANNER_MAP = {
    "secrets": SecretScanner,
    "client-exposure": ClientExposureAnalyzer,
    "env-flow": EnvTracer,
    "config": ConfigChecker,
    "iac": IacScanner,
    "dependencies": DepChecker,
    "artifacts": ArtifactInspector,
}


def detect_framework(path: str) -> str | None:
    p = Path(path)

    pkg_json = p / "package.json"
    if pkg_json.exists():
        try:
            pkg = json.loads(pkg_json.read_text())
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            if "next" in deps:
                return "nextjs"
            if "nuxt" in deps:
                return "nuxt"
            if "vite" in deps:
                return "vite"
            if "@sveltejs/kit" in deps:
                return "sveltekit"
            if "react-scripts" in deps:
                return "create-react-app"
            return "node"
        except (json.JSONDecodeError, OSError):
            return "node"

    if (p / "manage.py").exists():
        return "django"

    if (p / "Gemfile").exists() and (p / "config").is_dir():
        return "rails"

    if (p / "go.mod").exists():
        return "go"

    return None


def run_scan(
    path: str,
    framework: str | None = None,
    target: str | None = None,
    scanners: list[str] | None = None,
    reasoning: bool = True,
) -> list[Finding]:
    framework = framework or detect_framework(path)

    if scanners:
        active = {k: v for k, v in SCANNER_MAP.items() if k in scanners}
    else:
        active = SCANNER_MAP

    findings: list[Finding] = []
    for name, scanner_cls in active.items():
        agent = scanner_cls(path, framework=framework, target=target)
        findings.extend(agent.scan())

    # Deduplicate by (file, line, scanner)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.file_path, f.line, f.scanner)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    if reasoning:
        from reasoning.claude_client import ClaudeClient
        client = ClaudeClient()
        deduped = client.enrich_findings(deduped, framework=framework, target=target)

    return deduped
