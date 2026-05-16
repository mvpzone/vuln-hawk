"""Scanner agent — Sonnet-class model for per-file triage.

Receives its assignment from the root agent via transfer_to_agent.
The root agent's message carries which file and functions to examine.
After scanning, transfers back to the root with findings.
"""

from __future__ import annotations

from google.adk.agents import Agent

from vuln_agent.config import ModelConfig, create_llm
from vuln_agent.tools import (
    analyze_python_ast,
    read_file,
    search_code,
)


SCANNER_INSTRUCTION = """\
You are a fast security scanner. The root agent has transferred you a
specific file and set of functions to triage for potential vulnerabilities.

## Steps

1. Use `read_file` to read the assigned file.
2. For each function mentioned, identify:
   - All user-controlled inputs (request.args, request.form, request.POST,
     request.GET, request.json, request.FILES, URL parameters, headers,
     cookies, function arguments that originate from HTTP handlers).
   - All dangerous sinks (SQL execution, subprocess, eval, exec, file ops,
     template rendering, outbound HTTP, deserialization, pickle, yaml.load).
   - Whether user input can reach a sink WITHOUT adequate validation.
3. Use `search_code` to check for shared middleware, decorators, or
   validation helpers that might sanitize input before it reaches the sink.
4. Use `analyze_python_ast` with "calls" to confirm which dangerous
   functions are actually invoked in this file.

## Output format

Report your findings in this XML format:

<scanner_findings file="<filename>">
<flag function="function_name" line="42" sink="cursor.execute"
      confidence="HIGH|MEDIUM|LOW"
      vuln_class="SQL Injection|Command Injection|Path Traversal|SSTI|IDOR|SSRF|Hardcoded Secret|XSS|Insecure Deserialization|XXE">
Brief description of the data flow: user input source -> transforms -> sink.
Note any partial mitigations observed.
</flag>
<safe function="other_function" line="55" reason="Uses parameterized query binding"/>
</scanner_findings>

Mark functions as <safe> when they use dangerous APIs but the input is
not user-controlled or is properly validated. This is just as important
as flagging vulnerable functions.

When you are done, transfer back to the root agent `vuln_discovery_agent`
with your complete findings.
"""


def create_scanner(model_config: ModelConfig | None = None) -> Agent:
    cfg = model_config or ModelConfig()
    return Agent(
        name="scanner",
        model=create_llm(cfg.scanner),
        description=(
            "Fast security scanner. Transfer a file and functions to this "
            "agent for quick vulnerability triage. It will report back with "
            "flagged and safe functions."
        ),
        instruction=SCANNER_INSTRUCTION,
        tools=[read_file, search_code, analyze_python_ast],
    )
