import re

from agents.base import BaseAgent
from models import Finding, Severity

DEBUG_PATTERNS = [
    (re.compile(r'(?i)\bDEBUG\s*[:=]\s*(?:True|true|1|"true"|yes)\b'), "DEBUG mode enabled"),
    (re.compile(r'(?i)\bVERBOSE\s*[:=]\s*(?:True|true|1|"true")\b'), "VERBOSE mode enabled"),
    (re.compile(r'''(?i)NODE_ENV\s*[:=]\s*['"]?development['"]?'''), "NODE_ENV set to development"),
    (re.compile(r'''(?i)FLASK_ENV\s*[:=]\s*['"]?development['"]?'''), "FLASK_ENV set to development"),
    (re.compile(r'''(?i)RAILS_ENV\s*[:=]\s*['"]?development['"]?'''), "RAILS_ENV set to development"),
    (re.compile(r'''(?i)APP_DEBUG\s*[:=]\s*['"]?true['"]?'''), "APP_DEBUG enabled (Laravel)"),
    (re.compile(r'(?i)DJANGO_DEBUG\s*[:=]\s*(?:True|1)'), "DJANGO_DEBUG enabled"),
]

CORS_PATTERNS = [
    (re.compile(r'''(?i)Access-Control-Allow-Origin['",:\s]+.*['"]\*['"]'''), "CORS allows all origins (wildcard *)"),
    (re.compile(r'''(?i)Access-Control-Allow-Origin['",:\s]+\*'''), "CORS allows all origins (wildcard *)"),
    (re.compile(r'''(?i)allow_origins\s*[:=]\s*\[?\s*['"]\*['"]\s*\]?'''), "CORS allows all origins"),
    (re.compile(r'''(?i)cors\(\s*\)'''), "CORS enabled with no restrictions"),
    (re.compile(r'''(?i)origin:\s*true\b'''), "CORS reflects origin header (potential misconfiguration)"),
]

SECURITY_HEADER_PATTERNS = [
    (re.compile(r'''(?i)X-Frame-Options:\s*['"]?ALLOWALL['"]?'''), "X-Frame-Options set to ALLOWALL"),
    (re.compile(r'''(?i)X-Content-Type-Options:\s*['"]?none['"]?'''), "X-Content-Type-Options disabled"),
]

ERROR_EXPOSURE_PATTERNS = [
    (re.compile(r'(?i)(?:show|display|expose)[-_]?(?:error|stack|trace)\s*[:=]\s*(?:True|true|1)'),
     "Stack traces exposed in production config"),
    (re.compile(r'''(?i)['"]errorhandler['"].*(?:detail|verbose|full)'''),
     "Verbose error handler configured"),
]

SKIP_SUFFIXES = {'.md', '.txt', '.rst', '.lock'}


class ConfigChecker(BaseAgent):
    name = "config"

    def scan(self) -> list[Finding]:
        findings = []
        for fpath in self.walk_files():
            if fpath.suffix.lower() in SKIP_SUFFIXES:
                continue
            for line_no, line in self.read_lines(fpath):
                findings.extend(self._check_line(fpath, line_no, line))
        return findings

    def _check_line(self, fpath, line_no, line):
        findings = []
        stripped = line.strip()

        for pattern, desc in DEBUG_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    severity=Severity.WARNING,
                    scanner=self.name,
                    file_path=self.rel_path(fpath),
                    line=line_no,
                    description=desc,
                    context=stripped[:120],
                ))

        for pattern, desc in CORS_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    severity=Severity.WARNING,
                    scanner=self.name,
                    file_path=self.rel_path(fpath),
                    line=line_no,
                    description=desc,
                    context=stripped[:120],
                ))

        for pattern, desc in SECURITY_HEADER_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    severity=Severity.WARNING,
                    scanner=self.name,
                    file_path=self.rel_path(fpath),
                    line=line_no,
                    description=desc,
                    context=stripped[:120],
                ))

        for pattern, desc in ERROR_EXPOSURE_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    severity=Severity.INFO,
                    scanner=self.name,
                    file_path=self.rel_path(fpath),
                    line=line_no,
                    description=desc,
                    context=stripped[:120],
                ))

        return findings
