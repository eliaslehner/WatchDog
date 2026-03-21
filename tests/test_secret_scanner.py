import tempfile
from pathlib import Path

from agents.secret_scanner import SecretScanner
from models import Severity

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_detects_aws_key():
    scanner = SecretScanner(FIXTURE)
    findings = scanner.scan()
    aws = [f for f in findings if "AWS" in f.description]
    assert len(aws) >= 1
    assert any(f.severity == Severity.CRITICAL for f in aws)


def test_detects_github_token():
    scanner = SecretScanner(FIXTURE)
    findings = scanner.scan()
    gh = [f for f in findings if "GitHub" in f.description]
    assert len(gh) >= 1


def test_detects_google_api_key():
    scanner = SecretScanner(FIXTURE)
    findings = scanner.scan()
    google = [f for f in findings if "Google" in f.description]
    assert len(google) >= 1


def test_detects_hardcoded_password():
    scanner = SecretScanner(FIXTURE)
    findings = scanner.scan()
    pw = [f for f in findings if "password" in f.description.lower()]
    assert len(pw) >= 1


def test_detects_connection_string():
    scanner = SecretScanner(FIXTURE)
    findings = scanner.scan()
    conn = [f for f in findings if "connection string" in f.description.lower()]
    assert len(conn) >= 1


def test_ignores_placeholders():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "config.py").write_text(
            'api_key = "your-api-key-here"\n'
            'password = "changeme"\n'
            'secret = "example_secret_value"\n'
        )
        scanner = SecretScanner(tmp)
        findings = scanner.scan()
        assert len(findings) == 0


def test_ignores_env_references():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "config.py").write_text(
            'api_key = os.environ["API_KEY"]\n'
            'secret = process.env.SECRET_KEY\n'
        )
        scanner = SecretScanner(tmp)
        findings = scanner.scan()
        assert len(findings) == 0
