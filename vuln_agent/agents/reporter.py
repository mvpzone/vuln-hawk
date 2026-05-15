"""Reporter agent — Sonnet-class model that synthesises the final report.

Receives confirmed findings from all analyzers and produces the
canonical JSON vulnerability report. Has no tools — pure synthesis.
"""

from __future__ import annotations

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from vuln_agent.config import ModelConfig


REPORTER_INSTRUCTION = """\
You are a security report writer. Multiple deep-analysis agents have
examined a Python web application codebase. Their confirmed findings are
below.

## Confirmed findings from analyzers
{confirmed_findings}

## Your task

Deduplicate, normalise, and produce the FINAL vulnerability report as a
single fenced JSON block. The schema:

```json
{{
  "summary": "<one-paragraph overview>",
  "findings": [
    {{
      "id": "F1",
      "vuln_class": "SQL Injection | Command Injection | Path Traversal | SSTI | IDOR | SSRF | Hardcoded Secret | XSS | Insecure Deserialization | Open Redirect",
      "file": "<relative path>",
      "function": "<handler name>",
      "line_range": [<start>, <end>],
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "confidence": "HIGH | MEDIUM | LOW",
      "data_flow": "<source -> transforms -> sink>",
      "example_exploit": "<concrete request>",
      "suggested_fix": "<short remediation>"
    }}
  ]
}}
```

Rules:
- Only include findings with confidence HIGH.
- Merge duplicates (same file + function + vuln class = one finding).
- Assign sequential IDs: F1, F2, F3, ...
- Do NOT invent findings — only report what the analyzers confirmed.
- Do NOT call transfer_to_agent.
"""


def create_reporter(
    confirmed_findings: str,
    model_config: ModelConfig | None = None,
) -> Agent:
    cfg = model_config or ModelConfig()
    return Agent(
        name="reporter",
        model=Claude(model=cfg.reporter),
        description="Synthesises confirmed findings into the final JSON vulnerability report",
        instruction=REPORTER_INSTRUCTION.format(confirmed_findings=confirmed_findings),
        tools=[],
        output_key="reporter_output",
    )
