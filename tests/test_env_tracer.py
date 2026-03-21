import tempfile
from pathlib import Path

from agents.env_tracer import EnvTracer
from models import Severity

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_detects_env_not_gitignored():
    scanner = EnvTracer(FIXTURE)
    findings = scanner.scan()
    not_ignored = [f for f in findings if "not in .gitignore" in f.description]
    assert len(not_ignored) >= 1


def test_detects_hardcoded_secrets_in_env():
    scanner = EnvTracer(FIXTURE)
    findings = scanner.scan()
    hardcoded = [f for f in findings if "hardcoded value" in f.description]
    assert len(hardcoded) >= 1


def test_detects_real_secrets_in_example():
    scanner = EnvTracer(FIXTURE)
    findings = scanner.scan()
    example = [f for f in findings if "Example env" in f.description]
    assert len(example) >= 1


def test_clean_env_no_findings():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, ".gitignore").write_text(".env\n.env.*\n")
        Path(tmp, ".env").write_text("PORT=3000\nNODE_ENV=production\n")
        Path(tmp, ".env.example").write_text("SECRET_KEY=changeme\nAPI_KEY=your-api-key\n")
        scanner = EnvTracer(tmp)
        findings = scanner.scan()
        not_ignored = [f for f in findings if "not in .gitignore" in f.description]
        assert len(not_ignored) == 0
