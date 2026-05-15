"""Scanner agent — Haiku-class model for fast per-file triage.

Each scanner instance is assigned a single file (or small set of
functions) and performs a quick pass to flag suspicious patterns.
Multiple scanners run in parallel via ADK's ParallelAgent. The output
is a preliminary list of flagged locations, NOT confirmed
vulnerabilities — confirmation is the analyzer's job.
"""

from __future__ import annotations

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from vuln_agent.config import ModelConfig
from vuln_agent.tools import (
    analyze_python_ast,
    read_file,
    search_code,
)


SCANNER_INSTRUCTION = """\
You are a fast security scanner. You have been assigned a specific file
and set of functions to triage for potential vulnerabilities.

## Your assignment
File: {file}
Functions to examine: {functions}
Known sinks in this file: {sinks}
Context: {description}

## Steps

1. Use `read_file` to read the entire assigned file.
2. For each function listed, identify:
   - All user-controlled inputs (request.args, request.form, request.json,
     request.files, URL parameters, headers, cookies, function arguments
     that originate from HTTP handlers).
   - All dangerous sinks (SQL execution, subprocess, eval, file ops,
     template rendering, outbound HTTP, deserialization).
   - Whether user input can reach a sink WITHOUT adequate validation.
3. Use `search_code` to check for shared middleware, decorators, or
   validation helpers that might sanitize input before it reaches the sink.
4. Use `analyze_python_ast` with "calls" to confirm which dangerous
   functions are actually invoked in this file.

## Output format

Output a single XML block with your preliminary findings:

<scanner_findings file="{file}">
<flag function="function_name" line="42" sink="cursor.execute"
      confidence="HIGH|MEDIUM|LOW"
      vuln_class="SQL Injection|Command Injection|Path Traversal|SSTI|IDOR|SSRF|Hardcoded Secret|XSS">
Brief description of the data flow: user input source -> transforms -> sink.
Note any partial mitigations observed.
</flag>
<safe function="other_function" line="55" reason="Uses parameterized query binding"/>
</scanner_findings>

Mark functions as <safe> when they use dangerous APIs but the input is
not user-controlled or is properly validated. This is just as important
as flagging vulnerable functions.

Do NOT call transfer_to_agent.
"""


def create_scanner(
    file: str,
    functions: str,
    sinks: str,
    description: str,
    model_config: ModelConfig | None = None,
) -> Agent:
    cfg = model_config or ModelConfig()
    safe_name = file.replace(".", "_").replace("/", "_")
    return Agent(
        name=f"scanner_{safe_name}",
        model=Claude(model=cfg.scanner),
        description=f"Fast security scanner for {file}",
        instruction=SCANNER_INSTRUCTION.format(
            file=file,
            functions=functions,
            sinks=sinks,
            description=description,
        ),
        tools=[read_file, search_code, analyze_python_ast],
        output_key=f"scanner_{safe_name}_output",
    )
