import json

from models import Finding, Severity
from reporters.gitlab_mr import format_mr_comment
from reporters.pipeline import get_exit_code, format_gitlab_report


def _findings():
    return [
        Finding(Severity.CRITICAL, "secrets", "config.py", 5, "AWS key detected", "AKIA...", "Exploitable"),
        Finding(Severity.WARNING, "config", "settings.py", 10, "DEBUG enabled", "DEBUG=True"),
        Finding(Severity.INFO, "dependencies", "requirements.txt", 1, "Loosely pinned dep"),
    ]


# --- MR comment ---

def test_mr_comment_has_header():
    comment = format_mr_comment(_findings())
    assert "## WatchDog Security Scan" in comment


def test_mr_comment_shows_critical_count():
    comment = format_mr_comment(_findings())
    assert "1 critical" in comment


def test_mr_comment_blocks_pipeline_on_critical():
    comment = format_mr_comment(_findings())
    assert "Pipeline blocked" in comment


def test_mr_comment_no_block_without_critical():
    findings = [Finding(Severity.WARNING, "config", "f.py", 1, "DEBUG on")]
    comment = format_mr_comment(findings)
    assert "Pipeline blocked" not in comment


def test_mr_comment_includes_reasoning():
    comment = format_mr_comment(_findings())
    assert "Exploitable" in comment


def test_mr_comment_clean_scan():
    comment = format_mr_comment([])
    assert "No issues found" in comment


def test_mr_comment_info_in_details():
    comment = format_mr_comment(_findings())
    assert "<details>" in comment
    assert "Loosely pinned" in comment


# --- Pipeline ---

def test_exit_code_critical():
    assert get_exit_code(_findings()) == 1


def test_exit_code_no_critical():
    findings = [Finding(Severity.WARNING, "config", "f.py", 1, "DEBUG on")]
    assert get_exit_code(findings) == 0


def test_exit_code_empty():
    assert get_exit_code([]) == 0


# --- Code Quality report ---

def test_codequality_valid_json():
    report = format_gitlab_report(_findings())
    items = json.loads(report)
    assert len(items) == 3


def test_codequality_severity_mapping():
    report = format_gitlab_report(_findings())
    items = json.loads(report)
    assert items[0]["severity"] == "blocker"
    assert items[1]["severity"] == "major"
    assert items[2]["severity"] == "minor"


def test_codequality_has_fingerprint():
    report = format_gitlab_report(_findings())
    items = json.loads(report)
    assert all("fingerprint" in item for item in items)


def test_codequality_has_location():
    report = format_gitlab_report(_findings())
    items = json.loads(report)
    assert items[0]["location"]["path"] == "config.py"
    assert items[0]["location"]["lines"]["begin"] == 5
