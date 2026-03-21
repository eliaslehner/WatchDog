import tempfile
from pathlib import Path

from agents.client_exposure import ClientExposureAnalyzer
from models import Severity

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_detects_public_prefix_with_sensitive_var():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, ".env").write_text("NEXT_PUBLIC_SECRET_KEY=real_secret_value_abc123\n")
        scanner = ClientExposureAnalyzer(tmp, framework="nextjs")
        findings = scanner.scan()
        public = [f for f in findings if "public prefix" in f.description.lower()]
        assert len(public) >= 1
        assert any(f.severity == Severity.CRITICAL for f in public)


def test_detects_server_var_in_client_code():
    scanner = ClientExposureAnalyzer(FIXTURE, framework="nextjs")
    findings = scanner.scan()
    client = [f for f in findings if "client-side" in f.description.lower() or "client code" in f.description.lower()]
    assert len(client) >= 1


def test_no_false_positive_on_api_routes():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, ".env").write_text("DATABASE_URL=postgres://localhost/db\n")
        api_dir = Path(tmp, "pages", "api")
        api_dir.mkdir(parents=True)
        Path(api_dir, "handler.ts").write_text(
            'const db = process.env.DATABASE_URL;\n'
        )
        scanner = ClientExposureAnalyzer(tmp, framework="nextjs")
        findings = scanner.scan()
        client = [f for f in findings if "client-side" in f.description.lower()]
        assert len(client) == 0
