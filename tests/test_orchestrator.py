from pathlib import Path

from orchestrator import run_scan, detect_framework

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_detect_nextjs_framework():
    assert detect_framework(FIXTURE) == "nextjs"


def test_run_scan_finds_issues():
    findings = run_scan(FIXTURE, reasoning=False)
    assert len(findings) > 0


def test_run_scan_specific_scanners():
    findings = run_scan(FIXTURE, scanners=["secrets"], reasoning=False)
    assert all(f.scanner == "secrets" for f in findings)
    assert len(findings) > 0


def test_run_scan_deduplicates():
    findings = run_scan(FIXTURE, reasoning=False)
    keys = [(f.file_path, f.line, f.scanner) for f in findings]
    assert len(keys) == len(set(keys))


def test_run_scan_multiple_scanners():
    findings = run_scan(FIXTURE, scanners=["secrets", "config"], reasoning=False)
    scanners = {f.scanner for f in findings}
    assert "secrets" in scanners
    assert "config" in scanners
