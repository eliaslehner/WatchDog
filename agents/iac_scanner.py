import re

from agents.base import BaseAgent
from models import Finding, Severity

DOCKER_SECRET_PATTERNS = [
    (re.compile(r'(?i)(?:ENV|ARG)\s+(?:\w*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)\w*)\s*=\s*\S+'),
     "Hardcoded secret in Dockerfile ENV/ARG"),
]

COMPOSE_SECRET_PATTERNS = [
    (re.compile(r'(?i)(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY)\s*[:=]\s*["\']?[A-Za-z0-9+/=_\-]{8,}["\']?'),
     "Hardcoded secret in docker-compose"),
]

COMPOSE_SECURITY_PATTERNS = [
    (re.compile(r'(?i)privileged:\s*true'), "Privileged container — full host access"),
    (re.compile(r'(?i)network_mode:\s*["\']?host["\']?'), "Host network mode — no network isolation"),
]

TF_SECRET_PATTERNS = [
    (re.compile(r'(?i)(?:password|secret|token|api_key)\s*=\s*"[^"]{8,}"'),
     "Hardcoded secret in Terraform config"),
    (re.compile(r'(?i)default\s*=\s*"[^"]{8,}"'),
     None),  # Only flag if the variable name is sensitive
]

TF_SECURITY_PATTERNS = [
    (re.compile(r'''(?i)cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"\s*\]?'''),
     "Security group open to 0.0.0.0/0 (entire internet)"),
    (re.compile(r'(?i)publicly_accessible\s*=\s*true'),
     "Resource is publicly accessible"),
    (re.compile(r'(?i)encryption\s*=\s*false'),
     "Encryption explicitly disabled"),
    (re.compile(r'(?i)encrypted\s*=\s*false'),
     "Encryption explicitly disabled"),
]

K8S_SECRET_PATTERN = re.compile(
    r'(?i)(?:password|secret|token|api[-_]?key)\s*:\s*["\']?[A-Za-z0-9+/=_\-]{8,}["\']?'
)

K8S_SECURITY_PATTERNS = [
    (re.compile(r'(?i)privileged:\s*true'), "Privileged container in k8s manifest"),
    (re.compile(r'(?i)runAsUser:\s*0\b'), "Container runs as root"),
    (re.compile(r'(?i)hostNetwork:\s*true'), "Pod uses host network"),
    (re.compile(r'(?i)hostPID:\s*true'), "Pod shares host PID namespace"),
    (re.compile(r'(?i)allowPrivilegeEscalation:\s*true'), "Privilege escalation allowed"),
]

PLACEHOLDER = re.compile(
    r'(?i)(?:example|placeholder|changeme|your[-_]|xxx|TODO|FIXME|\$\{|<[^>]+>)'
)

IAC_EXTENSIONS = {'.tf', '.hcl', '.tfvars', '.yaml', '.yml'}
IAC_NAMES = {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}


class IacScanner(BaseAgent):
    name = "iac"

    def scan(self) -> list[Finding]:
        findings = []
        for fpath in self.walk_files():
            if fpath.name == 'Dockerfile':
                findings.extend(self._scan_docker(fpath))
            elif fpath.name in ('docker-compose.yml', 'docker-compose.yaml'):
                findings.extend(self._scan_k8s_or_compose(fpath))
            elif fpath.suffix.lower() in {'.tf', '.hcl', '.tfvars'}:
                findings.extend(self._scan_terraform(fpath))
            elif fpath.suffix.lower() in {'.yaml', '.yml'}:
                findings.extend(self._scan_k8s_or_compose(fpath))
        return findings

    def _scan_docker(self, fpath) -> list[Finding]:
        findings = []
        for line_no, line in self.read_lines(fpath):
            for pattern, desc in DOCKER_SECRET_PATTERNS:
                match = pattern.search(line)
                if match and not PLACEHOLDER.search(line):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        file_path=self.rel_path(fpath),
                        line=line_no,
                        description=desc,
                        context=line.strip()[:120],
                    ))
        return findings

    def _scan_terraform(self, fpath) -> list[Finding]:
        findings = []
        for line_no, line in self.read_lines(fpath):
            for pattern, desc in TF_SECRET_PATTERNS:
                if desc and pattern.search(line) and not PLACEHOLDER.search(line):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        file_path=self.rel_path(fpath),
                        line=line_no,
                        description=desc,
                        context=line.strip()[:120],
                    ))

            for pattern, desc in TF_SECURITY_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        severity=Severity.WARNING,
                        scanner=self.name,
                        file_path=self.rel_path(fpath),
                        line=line_no,
                        description=desc,
                        context=line.strip()[:120],
                    ))
        return findings

    def _scan_k8s_or_compose(self, fpath) -> list[Finding]:
        findings = []
        content = ''
        try:
            content = fpath.read_text(errors='replace')
        except OSError:
            return findings

        is_compose = 'services:' in content and ('image:' in content or 'build:' in content)
        is_k8s = 'apiVersion:' in content or 'kind:' in content

        for line_no, line in self.read_lines(fpath):
            if is_compose:
                for pattern, desc in COMPOSE_SECRET_PATTERNS:
                    if pattern.search(line) and not PLACEHOLDER.search(line):
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            scanner=self.name,
                            file_path=self.rel_path(fpath),
                            line=line_no,
                            description=desc,
                            context=line.strip()[:120],
                        ))
                for pattern, desc in COMPOSE_SECURITY_PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            scanner=self.name,
                            file_path=self.rel_path(fpath),
                            line=line_no,
                            description=desc,
                            context=line.strip()[:120],
                        ))

            if is_k8s:
                if K8S_SECRET_PATTERN.search(line) and not PLACEHOLDER.search(line):
                    findings.append(Finding(
                        severity=Severity.WARNING,
                        scanner=self.name,
                        file_path=self.rel_path(fpath),
                        line=line_no,
                        description="Possible hardcoded secret in k8s manifest",
                        context=line.strip()[:120],
                    ))
                for pattern, desc in K8S_SECURITY_PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            scanner=self.name,
                            file_path=self.rel_path(fpath),
                            line=line_no,
                            description=desc,
                            context=line.strip()[:120],
                        ))

        return findings
