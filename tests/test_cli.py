import json
import tempfile
from pathlib import Path

from click.testing import CliRunner

from watchdog import cli

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_scan_console_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", FIXTURE, "--no-reasoning"])
    assert result.exit_code == 1  # critical findings
    assert "WatchDog Scan Results" in result.output
    assert "critical" in result.output.lower()


def test_scan_json_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", FIXTURE, "--no-reasoning", "--output", "json"])
    assert result.exit_code == 1
    data = json.loads(result.output.split("Framework:")[1].split("\n", 1)[1])
    assert len(data) > 0
    assert all("severity" in item for item in data)


def test_scan_gitlab_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", FIXTURE, "--no-reasoning", "--output", "gitlab"])
    assert result.exit_code == 1
    assert "## WatchDog Security Scan" in result.output
    assert "Pipeline blocked" in result.output


def test_scan_codequality_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", FIXTURE, "--no-reasoning", "--output", "codequality"])
    output = result.output.split("Framework:")[1].split("\n", 1)[1]
    data = json.loads(output)
    assert len(data) > 0
    assert all("fingerprint" in item for item in data)


def test_scan_specific_scanners():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", FIXTURE, "--no-reasoning", "--scanners", "config"])
    assert result.exit_code == 0  # no critical from config alone
    assert "DEBUG" in result.output


def test_scan_invalid_scanner():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", FIXTURE, "--no-reasoning", "--scanners", "nonexistent"])
    assert result.exit_code == 2
    assert "unknown scanner" in result.output


def test_scan_verbose_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", FIXTURE, "--no-reasoning", "--verbose"])
    assert result.exit_code == 1
    assert "Scanner:" in result.output
    assert "Location:" in result.output


def test_scan_clean_project():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "clean.py").write_text("print('hello')\n")
        result = runner.invoke(cli, ["scan", tmp, "--no-reasoning"])
        assert result.exit_code == 0
        assert "Clean scan" in result.output


def test_list_scanners():
    runner = CliRunner()
    result = runner.invoke(cli, ["list-scanners"])
    assert result.exit_code == 0
    assert "secrets" in result.output
    assert "iac" in result.output
    assert "artifacts" in result.output
