import json
from unittest.mock import MagicMock, patch

from models import Finding, Severity
from reasoning.claude_client import ClaudeClient, _build_user_prompt, SYSTEM_PROMPT


def _sample_findings():
    return [
        Finding(
            severity=Severity.CRITICAL,
            scanner="secrets",
            file_path="config.py",
            line=5,
            description="AWS Access Key detected",
            context="AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7VULN0001'",
        ),
        Finding(
            severity=Severity.WARNING,
            scanner="config",
            file_path="settings.py",
            line=10,
            description="DEBUG mode enabled",
            context="DEBUG = True",
        ),
    ]


def test_build_user_prompt_includes_findings():
    findings = _sample_findings()
    prompt = _build_user_prompt(findings, framework="django", target="aws")
    assert "Framework: django" in prompt
    assert "Deployment target: aws" in prompt
    assert "[0] CRITICAL" in prompt
    assert "AWS Access Key" in prompt
    assert "[1] WARNING" in prompt
    assert "DEBUG mode" in prompt


def test_build_user_prompt_no_framework():
    findings = _sample_findings()
    prompt = _build_user_prompt(findings, framework=None, target=None)
    assert "Framework:" not in prompt
    assert "[0]" in prompt


def test_skips_without_api_key():
    with patch.dict("os.environ", {}, clear=True):
        client = ClaudeClient()
        client._api_key = None
        findings = _sample_findings()
        result = client.enrich_findings(findings, framework="django")
        assert result == findings
        assert result[0].reasoning == ""


def test_enriches_findings_with_mock():
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps([
        {
            "index": 0,
            "severity": "critical",
            "reasoning": "This AWS key is hardcoded and directly exploitable.",
            "false_positive": False,
        },
        {
            "index": 1,
            "severity": "info",
            "reasoning": "DEBUG=True in a settings file that is only used in development.",
            "false_positive": True,
        },
    ]))]

    client = ClaudeClient()
    client._api_key = "test-key"
    mock_anthropic = MagicMock()
    mock_anthropic.messages.create.return_value = mock_response
    client._client = mock_anthropic

    findings = _sample_findings()
    result = client.enrich_findings(findings, framework="django", target="aws")

    assert len(result) == 2
    assert result[0].severity == Severity.CRITICAL
    assert "exploitable" in result[0].reasoning
    assert result[1].severity == Severity.INFO
    assert "development" in result[1].reasoning

    call_args = mock_anthropic.messages.create.call_args
    assert call_args.kwargs["system"] == SYSTEM_PROMPT
    assert "django" in call_args.kwargs["messages"][0]["content"]


def test_handles_api_error_gracefully():
    client = ClaudeClient()
    client._api_key = "test-key"
    mock_anthropic = MagicMock()
    mock_anthropic.messages.create.side_effect = Exception("API error")
    client._client = mock_anthropic

    findings = _sample_findings()
    result = client.enrich_findings(findings)

    assert len(result) == 2
    assert result[0].severity == Severity.CRITICAL
    assert result[0].reasoning == ""


def test_handles_malformed_json_gracefully():
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="not valid json")]

    client = ClaudeClient()
    client._api_key = "test-key"
    mock_anthropic = MagicMock()
    mock_anthropic.messages.create.return_value = mock_response
    client._client = mock_anthropic

    findings = _sample_findings()
    result = client.enrich_findings(findings)

    assert len(result) == 2
    assert result[0].reasoning == ""


def test_batching_multiple_calls():
    mock_response = MagicMock()

    client = ClaudeClient()
    client._api_key = "test-key"
    mock_anthropic = MagicMock()
    client._client = mock_anthropic

    def make_response(batch_size):
        items = [{"index": i, "severity": "warning", "reasoning": "ok", "false_positive": False}
                 for i in range(batch_size)]
        resp = MagicMock()
        resp.content = [MagicMock(text=json.dumps(items))]
        return resp

    # 20 findings should produce 2 batches (15 + 5)
    findings = [
        Finding(severity=Severity.WARNING, scanner="test", file_path=f"f{i}.py", line=i, description="test")
        for i in range(20)
    ]

    mock_anthropic.messages.create.side_effect = [make_response(15), make_response(5)]
    result = client.enrich_findings(findings)

    assert len(result) == 20
    assert mock_anthropic.messages.create.call_count == 2


def test_empty_findings_returns_empty():
    client = ClaudeClient()
    client._api_key = "test-key"
    assert client.enrich_findings([]) == []
