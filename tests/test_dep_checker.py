import tempfile
from pathlib import Path

from agents.dep_checker import DepChecker
from models import Severity

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_detects_known_malicious_npm():
    scanner = DepChecker(FIXTURE)
    findings = scanner.scan()
    malicious = [f for f in findings if "malicious" in f.description.lower() or "Known" in f.description]
    npm_malicious = [f for f in malicious if f.file_path == "package.json"]
    assert len(npm_malicious) >= 1  # event-stream and/or colors


def test_detects_wildcard_version():
    scanner = DepChecker(FIXTURE)
    findings = scanner.scan()
    wildcard = [f for f in findings if "Unpinned" in f.description and "package.json" in f.file_path]
    assert len(wildcard) >= 1  # express: *


def test_detects_unpinned_python():
    scanner = DepChecker(FIXTURE)
    findings = scanner.scan()
    unpinned = [f for f in findings if "requirements.txt" in f.file_path and "npinned" in f.description]
    assert len(unpinned) >= 1  # flask, pillow


def test_detects_loosely_pinned():
    scanner = DepChecker(FIXTURE)
    findings = scanner.scan()
    loose = [f for f in findings if "Loosely pinned" in f.description]
    assert len(loose) >= 1


def test_clean_deps_minimal_findings():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "package.json").write_text('{"dependencies": {"react": "18.2.0"}}')
        Path(tmp, "requirements.txt").write_text("flask==3.0.0\nrequests==2.31.0\n")
        scanner = DepChecker(tmp)
        findings = scanner.scan()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0
