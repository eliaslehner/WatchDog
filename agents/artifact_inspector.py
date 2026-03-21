import re
from pathlib import Path

from agents.base import BaseAgent
from models import Finding, Severity

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("GitHub Token", re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')),
    ("GitLab Token", re.compile(r'glpat-[A-Za-z0-9\-_]{20,}')),
    ("Slack Token", re.compile(r'xox[bpors]-[A-Za-z0-9\-]+')),
    ("Stripe Secret Key", re.compile(r'sk_(test|live)_[A-Za-z0-9]{20,}')),
    ("Private Key", re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----')),
    ("API Key assignment", re.compile(r'(?i)(?:api_key|apikey|api_secret|secret_key)\s*[:=]\s*["\']([^"\']{16,})["\']')),
    ("Connection string", re.compile(r'(?:postgres|mysql|mongodb|redis)://[^\s"\']+:[^\s"\']+@')),
]

BUILD_DIRS = ['.next', 'dist', 'build', 'out', '_site', 'public/build']
BUILD_EXTENSIONS = {'.js', '.mjs', '.cjs', '.css', '.html', '.json', '.map'}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB


class ArtifactInspector(BaseAgent):
    name = "artifacts"

    def scan(self) -> list[Finding]:
        findings = []
        for build_dir_name in BUILD_DIRS:
            build_dir = self.path / build_dir_name
            if build_dir.is_dir():
                findings.extend(self._scan_build_dir(build_dir))
        findings.extend(self._check_source_maps())
        findings.extend(self._check_env_in_build())
        return findings

    def _scan_build_dir(self, build_dir: Path) -> list[Finding]:
        findings = []
        for fpath in build_dir.rglob('*'):
            if not fpath.is_file():
                continue
            if fpath.suffix.lower() not in BUILD_EXTENSIONS:
                continue
            if fpath.stat().st_size > MAX_FILE_SIZE:
                continue

            try:
                content = fpath.read_text(errors='replace')
            except OSError:
                continue

            for label, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    start = max(0, match.start() - 40)
                    end = min(len(content), match.end() + 40)
                    context = content[start:end].replace('\n', ' ')

                    line_no = content[:match.start()].count('\n') + 1

                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        file_path=self.rel_path(fpath),
                        line=line_no,
                        description=f"{label} found in build artifact",
                        context=context[:120],
                    ))

        return findings

    def _check_source_maps(self) -> list[Finding]:
        findings = []
        for build_dir_name in BUILD_DIRS:
            build_dir = self.path / build_dir_name
            if not build_dir.is_dir():
                continue

            for fpath in build_dir.rglob('*.map'):
                if not fpath.is_file():
                    continue

                findings.append(Finding(
                    severity=Severity.INFO,
                    scanner=self.name,
                    file_path=self.rel_path(fpath),
                    line=0,
                    description="Source map file in build output — may expose source code",
                    context="Source maps reveal original source code to anyone who downloads them",
                ))

                if fpath.stat().st_size <= MAX_FILE_SIZE:
                    try:
                        content = fpath.read_text(errors='replace')
                        for label, pattern in SECRET_PATTERNS:
                            if pattern.search(content):
                                findings.append(Finding(
                                    severity=Severity.CRITICAL,
                                    scanner=self.name,
                                    file_path=self.rel_path(fpath),
                                    line=0,
                                    description=f"{label} found in source map",
                                    context="Secrets in source maps are exposed to anyone who downloads the map file",
                                ))
                    except OSError:
                        pass

        return findings

    def _check_env_in_build(self) -> list[Finding]:
        findings = []
        for build_dir_name in BUILD_DIRS:
            build_dir = self.path / build_dir_name
            if not build_dir.is_dir():
                continue

            for fpath in build_dir.rglob('.env*'):
                if fpath.is_file():
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        file_path=self.rel_path(fpath),
                        line=0,
                        description=f"Env file '{fpath.name}' found in build output",
                        context="Env files in build directories may be served to users",
                    ))

        return findings
