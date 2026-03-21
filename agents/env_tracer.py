import re
from pathlib import Path

from agents.base import BaseAgent
from models import Finding, Severity

SENSITIVE_KEY_PATTERN = re.compile(
    r'(?i)(?:SECRET|PASSWORD|PASSWD|PWD|PRIVATE|KEY|TOKEN|AUTH|CREDENTIAL|'
    r'DATABASE_URL|DB_URL|DB_PASS|REDIS_URL|MONGO|STRIPE|TWILIO|SENDGRID|'
    r'SMTP_PASS|ENCRYPTION|SIGNING|JWT|SESSION_SECRET|API_KEY|API_SECRET)'
)

SAFE_PREFIXES = {'NODE_ENV', 'APP_NAME', 'APP_ENV', 'LOG_LEVEL', 'PORT', 'HOST', 'TZ'}


class EnvTracer(BaseAgent):
    name = "env-flow"

    def scan(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_env_files_gitignored())
        findings.extend(self._check_env_with_secrets())
        findings.extend(self._check_env_example_secrets())
        return findings

    def _check_env_files_gitignored(self) -> list[Finding]:
        findings = []
        gitignore = self.path / '.gitignore'
        ignored_patterns = set()

        if gitignore.exists():
            for _, line in self.read_lines(gitignore):
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    ignored_patterns.add(stripped)

        env_files = [f for f in self.walk_files() if f.name.startswith('.env')]
        for fpath in env_files:
            name = fpath.name
            if name in ('.env.example', '.env.sample'):
                continue

            is_ignored = any(
                name == pat or pat == '.env*' or pat == '.env'
                for pat in ignored_patterns
            )

            if not is_ignored:
                has_secrets = False
                for _, line in self.read_lines(fpath):
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#') and '=' in stripped:
                        key = stripped.split('=', 1)[0].strip()
                        value = stripped.split('=', 1)[1].strip().strip('"').strip("'")
                        if value and SENSITIVE_KEY_PATTERN.search(key):
                            has_secrets = True
                            break

                if has_secrets:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        file_path=self.rel_path(fpath),
                        line=0,
                        description=f"'{fpath.name}' contains secrets and is not in .gitignore",
                    ))

        return findings

    def _check_env_with_secrets(self) -> list[Finding]:
        findings = []
        env_files = [f for f in self.walk_files() if f.name == '.env' or f.name == '.env.local']

        for fpath in env_files:
            for line_no, line in self.read_lines(fpath):
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or '=' not in stripped:
                    continue

                key = stripped.split('=', 1)[0].strip()
                value = stripped.split('=', 1)[1].strip().strip('"').strip("'")

                if not value or key in SAFE_PREFIXES:
                    continue

                if SENSITIVE_KEY_PATTERN.search(key) and len(value) >= 8:
                    if not re.match(r'^(placeholder|example|changeme|your[-_])', value, re.I):
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            scanner=self.name,
                            file_path=self.rel_path(fpath),
                            line=line_no,
                            description=f"Sensitive env var '{key}' has hardcoded value",
                            context=f"{key}=***",
                        ))

        return findings

    def _check_env_example_secrets(self) -> list[Finding]:
        findings = []
        example_files = [
            f for f in self.walk_files()
            if f.name in ('.env.example', '.env.sample')
        ]

        for fpath in example_files:
            for line_no, line in self.read_lines(fpath):
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or '=' not in stripped:
                    continue

                key = stripped.split('=', 1)[0].strip()
                value = stripped.split('=', 1)[1].strip().strip('"').strip("'")

                if SENSITIVE_KEY_PATTERN.search(key) and value and len(value) >= 16:
                    if not re.match(r'^(placeholder|example|changeme|your[-_]|xxx|<)', value, re.I):
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            scanner=self.name,
                            file_path=self.rel_path(fpath),
                            line=line_no,
                            description=f"Example env file may contain real secret for '{key}'",
                            context=f"{key}=***",
                        ))

        return findings
