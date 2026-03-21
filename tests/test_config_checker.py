import tempfile
from pathlib import Path

from agents.config_checker import ConfigChecker
from models import Severity

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_detects_debug_mode():
    scanner = ConfigChecker(FIXTURE)
    findings = scanner.scan()
    debug = [f for f in findings if "DEBUG" in f.description]
    assert len(debug) >= 1


def test_detects_cors_wildcard():
    scanner = ConfigChecker(FIXTURE)
    findings = scanner.scan()
    cors = [f for f in findings if "CORS" in f.description]
    assert len(cors) >= 1


def test_detects_dev_node_env():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "config.js").write_text('const env = NODE_ENV = "development"\n')
        scanner = ConfigChecker(tmp)
        findings = scanner.scan()
        node_env = [f for f in findings if "NODE_ENV" in f.description]
        assert len(node_env) >= 1


def test_clean_config_no_findings():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "config.py").write_text(
            'DEBUG = False\n'
            'ALLOWED_HOSTS = ["myapp.com"]\n'
        )
        scanner = ConfigChecker(tmp)
        findings = scanner.scan()
        assert len(findings) == 0
