import re

from agents.base import BaseAgent
from models import Finding, Severity


HIGH_CONFIDENCE = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("GitHub Token", re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')),
    ("GitLab Token", re.compile(r'glpat-[A-Za-z0-9\-_]{20,}')),
    ("Slack Token", re.compile(r'xox[bpors]-[A-Za-z0-9\-]+')),
    ("Stripe Secret Key", re.compile(r'sk_(test|live)_[A-Za-z0-9]{20,}')),
    ("Stripe Restricted Key", re.compile(r'rk_(test|live)_[A-Za-z0-9]{20,}')),
    ("Private Key", re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----')),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("SendGrid Key", re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}')),
    ("npm Token", re.compile(r'npm_[A-Za-z0-9]{36}')),
    ("Twilio Key", re.compile(r'SK[0-9a-fA-F]{32}')),
]

MEDIUM_CONFIDENCE = [
    ("Hardcoded password", re.compile(
        r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']'
    )),
    ("Hardcoded secret", re.compile(
        r'(?i)(?:secret|secret_key|api_secret)\s*[:=]\s*["\']([^"\']{8,})["\']'
    )),
    ("Hardcoded API key", re.compile(
        r'(?i)(?:api_key|apikey|api[-_]?token)\s*[:=]\s*["\']([^"\']{8,})["\']'
    )),
    ("Hardcoded auth token", re.compile(
        r'(?i)(?:auth_token|access_token|bearer_token)\s*[:=]\s*["\']([^"\']{8,})["\']'
    )),
    ("Database connection string", re.compile(
        r'(?:postgres|mysql|mongodb|redis|amqp)://[^\s"\'<>]+:[^\s"\'<>]+@'
    )),
    ("JWT token", re.compile(
        r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    )),
    ("AWS Secret Key assignment", re.compile(
        r'(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
    )),
]

PLACEHOLDER = re.compile(
    r'(?i)(?:example|placeholder|your[-_]?|changeme|fixme|todo|xxx|'
    r'test[-_]?|fake|dummy|mock|sample|replace|insert|put[-_]?your|'
    r'<[^>]+>|\$\{|process\.env|os\.environ|ENV\[)'
)

SKIP_FILES = {
    'package-lock.json', 'yarn.lock', 'poetry.lock', 'Cargo.lock',
    'go.sum', 'Gemfile.lock', 'pnpm-lock.yaml', 'composer.lock',
}


class SecretScanner(BaseAgent):
    name = "secrets"

    def scan(self) -> list[Finding]:
        findings = []
        for fpath in self.walk_files():
            if fpath.name in SKIP_FILES:
                continue
            for line_no, line in self.read_lines(fpath):
                findings.extend(self._check_line(fpath, line_no, line))
        return findings

    def _check_line(self, fpath, line_no, line):
        findings = []
        stripped = line.strip()

        for label, pattern in HIGH_CONFIDENCE:
            match = pattern.search(line)
            if match:
                if PLACEHOLDER.search(match.group(0)):
                    continue
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    scanner=self.name,
                    file_path=self.rel_path(fpath),
                    line=line_no,
                    description=f"{label} detected",
                    context=stripped[:120],
                ))

        for label, pattern in MEDIUM_CONFIDENCE:
            match = pattern.search(line)
            if match:
                value = match.group(1) if match.lastindex else match.group(0)
                if PLACEHOLDER.search(value):
                    continue
                findings.append(Finding(
                    severity=Severity.WARNING,
                    scanner=self.name,
                    file_path=self.rel_path(fpath),
                    line=line_no,
                    description=f"{label}",
                    context=stripped[:120],
                ))

        return findings
