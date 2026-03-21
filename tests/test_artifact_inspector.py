from pathlib import Path

from agents.artifact_inspector import ArtifactInspector
from models import Severity

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_detects_secrets_in_build_output():
    scanner = ArtifactInspector(FIXTURE)
    findings = scanner.scan()
    build = [f for f in findings if "build artifact" in f.description.lower()]
    assert len(build) >= 1
    assert any(f.severity == Severity.CRITICAL for f in build)


def test_detects_source_maps():
    scanner = ArtifactInspector(FIXTURE)
    findings = scanner.scan()
    maps = [f for f in findings if "source map" in f.description.lower() or "Source map" in f.description]
    assert len(maps) >= 1


def test_detects_secrets_in_source_maps():
    scanner = ArtifactInspector(FIXTURE)
    findings = scanner.scan()
    map_secrets = [
        f for f in findings
        if ".map" in f.file_path and f.severity == Severity.CRITICAL
    ]
    assert len(map_secrets) >= 1
