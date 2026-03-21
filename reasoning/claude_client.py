import json
import os
import sys

from models import Finding, Severity

BATCH_SIZE = 15

SYSTEM_PROMPT = """\
You are a security analyst reviewing automated scanner findings for a software project.
Your job is to assess each finding's real-world exploitability and provide contextual reasoning.

For each finding, you must:
1. Determine if it's a true positive or likely false positive
2. Assess severity in context (critical / warning / info)
3. Explain WHY it's dangerous — describe the exploit path, not just the pattern match
4. Suggest a specific fix

You may upgrade or downgrade severity based on context:
- Upgrade: a "warning" that's trivially exploitable in the given framework/target
- Downgrade: a "critical" that's actually safe due to framework protections or deployment context
- Dismiss: findings that are clearly false positives (set severity to "info" with explanation)

Respond with a JSON array. Each element must have these exact keys:
- "index": the finding's index (integer, 0-based)
- "severity": "critical" | "warning" | "info"
- "reasoning": a concise explanation (2-3 sentences max)
- "false_positive": true | false

Return ONLY the JSON array, no markdown fences or other text.\
"""


def _build_user_prompt(findings: list[Finding], framework: str | None, target: str | None) -> str:
    parts = ["Analyze these security findings:\n"]

    if framework:
        parts.append(f"Framework: {framework}")
    if target:
        parts.append(f"Deployment target: {target}")
    parts.append("")

    for i, f in enumerate(findings):
        parts.append(f"[{i}] {f.severity.value.upper()} | {f.scanner} | {f.file_path}:{f.line}")
        parts.append(f"    {f.description}")
        if f.context:
            parts.append(f"    Context: {f.context}")
        parts.append("")

    return "\n".join(parts)


class ClaudeClient:
    def __init__(self):
        self._api_key = os.environ.get("ANTHROPIC_API_KEY")
        self._client = None

    @property
    def client(self):
        if self._client is None and self._api_key:
            from anthropic import Anthropic
            self._client = Anthropic(api_key=self._api_key)
        return self._client

    def enrich_findings(
        self,
        findings: list[Finding],
        framework: str | None = None,
        target: str | None = None,
    ) -> list[Finding]:
        if not self._api_key:
            print("Warning: ANTHROPIC_API_KEY not set — skipping reasoning step", file=sys.stderr)
            return findings

        if not findings:
            return findings

        enriched = []
        for batch_start in range(0, len(findings), BATCH_SIZE):
            batch = findings[batch_start:batch_start + BATCH_SIZE]
            enriched.extend(self._analyze_batch(batch, framework, target))

        return enriched

    def _analyze_batch(
        self,
        findings: list[Finding],
        framework: str | None,
        target: str | None,
    ) -> list[Finding]:
        user_prompt = _build_user_prompt(findings, framework, target)

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            text = response.content[0].text.strip()
            analyses = json.loads(text)

            for item in analyses:
                idx = item.get("index", -1)
                if 0 <= idx < len(findings):
                    f = findings[idx]
                    new_sev = item.get("severity", f.severity.value)
                    if new_sev in ("critical", "warning", "info"):
                        f.severity = Severity(new_sev)
                    f.reasoning = item.get("reasoning", "")

            return findings

        except Exception as e:
            print(f"Warning: Claude reasoning failed ({e}) — returning raw findings", file=sys.stderr)
            return findings
