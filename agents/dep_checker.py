import json
import re

from agents.base import BaseAgent
from models import Finding, Severity

KNOWN_VULNERABLE = {
    'event-stream': 'Compromised with credential-stealing malware (CVE-2018-16396)',
    'ua-parser-js': 'Compromised with cryptominer (versions 0.7.29, 0.8.0, 1.0.0)',
    'coa': 'Compromised — malicious release (v2.0.3, v2.0.4, v2.1.1, v2.1.3, v3.0.1)',
    'rc': 'Compromised — malicious release (v1.2.9, v1.3.9, v2.3.9)',
    'colors': 'Deliberately sabotaged by maintainer (v1.4.1, v1.4.2)',
    'faker': 'Deliberately sabotaged by maintainer (v6.6.6)',
    'node-ipc': 'Deliberately sabotaged — protestware (v10.1.1, v10.1.2, v10.1.3)',
    'flatmap-stream': 'Malicious package targeting cryptocurrency wallets',
}

KNOWN_VULNERABLE_PY = {
    'pyyaml': {'affected': '<5.4', 'note': 'Arbitrary code execution via yaml.load (CVE-2020-14343)'},
    'jinja2': {'affected': '<2.11.3', 'note': 'Sandbox escape (CVE-2020-28493)'},
    'urllib3': {'affected': '<1.26.5', 'note': 'CRLF injection (CVE-2021-33503)'},
    'requests': {'affected': '<2.31.0', 'note': 'Leaking Proxy-Authorization headers (CVE-2023-32681)'},
    'django': {'affected': '<4.2', 'note': 'Multiple CVEs in older releases'},
    'flask': {'affected': '<2.3.2', 'note': 'Security headers bypass'},
    'cryptography': {'affected': '<41.0.0', 'note': 'Multiple CVEs in older releases'},
    'pillow': {'affected': '<10.0.0', 'note': 'Multiple CVEs in older releases'},
}

WILDCARD_VERSION = re.compile(r'^\*$|^latest$|^x$')
UNPINNED_RANGE = re.compile(r'^[>~^]')


class DepChecker(BaseAgent):
    name = "dependencies"

    def scan(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_package_json())
        findings.extend(self._check_requirements_txt())
        return findings

    def _check_package_json(self) -> list[Finding]:
        findings = []
        pkg_file = self.path / 'package.json'
        if not pkg_file.exists():
            return findings

        try:
            pkg = json.loads(pkg_file.read_text())
        except (json.JSONDecodeError, OSError):
            return findings

        all_deps = {}
        for section in ('dependencies', 'devDependencies'):
            all_deps.update(pkg.get(section, {}))

        for name, version in all_deps.items():
            if name in KNOWN_VULNERABLE:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    scanner=self.name,
                    file_path='package.json',
                    line=0,
                    description=f"Known malicious/vulnerable package: {name}",
                    context=KNOWN_VULNERABLE[name],
                ))

            if isinstance(version, str) and WILDCARD_VERSION.match(version.strip()):
                findings.append(Finding(
                    severity=Severity.WARNING,
                    scanner=self.name,
                    file_path='package.json',
                    line=0,
                    description=f"Unpinned dependency '{name}': {version}",
                    context="Wildcard versions can pull in breaking or malicious updates",
                ))

        return findings

    def _check_requirements_txt(self) -> list[Finding]:
        findings = []
        req_file = self.path / 'requirements.txt'
        if not req_file.exists():
            return findings

        for line_no, line in self.read_lines(req_file):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('-'):
                continue

            match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(.*)', stripped)
            if not match:
                continue

            pkg_name = match.group(1).lower().replace('-', '_').replace('.', '_')
            version_spec = match.group(2).strip()

            if pkg_name.replace('_', '-') in KNOWN_VULNERABLE_PY or pkg_name in KNOWN_VULNERABLE_PY:
                lookup = pkg_name if pkg_name in KNOWN_VULNERABLE_PY else pkg_name.replace('_', '-')
                if lookup not in KNOWN_VULNERABLE_PY:
                    for k in KNOWN_VULNERABLE_PY:
                        if k.replace('-', '_') == pkg_name:
                            lookup = k
                            break
                if lookup in KNOWN_VULNERABLE_PY:
                    info = KNOWN_VULNERABLE_PY[lookup]
                    findings.append(Finding(
                        severity=Severity.INFO,
                        scanner=self.name,
                        file_path='requirements.txt',
                        line=line_no,
                        description=f"Package '{stripped.split('=')[0].split('>')[0].split('<')[0].strip()}' has known vulnerabilities in older versions",
                        context=info['note'],
                    ))

            if not version_spec or version_spec.startswith('#'):
                findings.append(Finding(
                    severity=Severity.WARNING,
                    scanner=self.name,
                    file_path='requirements.txt',
                    line=line_no,
                    description=f"Unpinned dependency: {stripped}",
                    context="Pin dependencies with == to ensure reproducible builds",
                ))
            elif not re.search(r'==', version_spec):
                findings.append(Finding(
                    severity=Severity.INFO,
                    scanner=self.name,
                    file_path='requirements.txt',
                    line=line_no,
                    description=f"Loosely pinned dependency: {stripped}",
                    context="Consider using == for exact version pinning",
                ))

        return findings
