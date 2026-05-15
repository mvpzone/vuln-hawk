"""Analyzer agent — Sonnet-class model for deep data-flow confirmation.

Receives preliminary flags from a scanner and performs rigorous
data-flow tracing to confirm or reject each one. Has access to all
tools including run_python_snippet for custom AST analysis. Only
HIGH-confidence confirmed findings survive this stage.
"""

from __future__ import annotations

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from vuln_agent.config import ModelConfig
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    run_python_snippet,
    search_code,
)


ANALYZER_INSTRUCTION = """\
You are a deep security analyst. A fast scanner has flagged the
following potential vulnerabilities. Your job is to CONFIRM or REJECT
each flag by performing rigorous data-flow analysis.

## Scanner flags to investigate
{scanner_flags}

## Methodology

For EACH flag:
1. Use `read_file` to examine the flagged function AND any callers or
   shared code it depends on.
2. Trace the complete data flow from user-controlled source to the
   dangerous sink. Name every variable and function call in the chain.
3. Check for mitigations: input validation, parameterized queries,
   secure_filename, allowlists, type coercion (e.g., <int:id>).
4. If mitigations exist, determine whether they can be bypassed.
5. Use `search_code` to find how the flagged function is called — is
   user input actually passed to it?
6. Use `run_python_snippet` if you need custom AST traversal to trace
   complex call chains.

## Output format

Output a single XML block:

<analyzer_results>
<confirmed id="A1" function="search_users" file="db.py" line_range="42-51"
           vuln_class="SQL Injection" severity="CRITICAL" confidence="HIGH"
           data_flow="request.args.get('q') -> local var q -> f-string -> cursor.execute"
           example_exploit="GET /search?q=' OR '1'='1"
           suggested_fix="Use parameterized binding: cursor.execute('...WHERE name=?', (q,))"/>
<rejected function="get_user_by_id" file="db.py" line_range="55-65"
          reason="Uses parameterized query with ? placeholder; user_id is also type-coerced by Flask's int converter"/>
</analyzer_results>

Only mark a finding as <confirmed> if you can trace the COMPLETE path
from user input to sink with no effective mitigation. Precision is
paramount — a false positive is worse than a miss.

Do NOT call transfer_to_agent.
"""


def create_analyzer(
    scanner_flags: str,
    area_id: str = "0",
    model_config: ModelConfig | None = None,
) -> Agent:
    cfg = model_config or ModelConfig()
    return Agent(
        name=f"analyzer_{area_id}",
        model=Claude(model=cfg.analyzer),
        description=f"Deep data-flow analyzer for area {area_id}",
        instruction=ANALYZER_INSTRUCTION.format(scanner_flags=scanner_flags),
        tools=[read_file, search_code, list_directory, analyze_python_ast, run_python_snippet],
        output_key=f"analyzer_{area_id}_output",
    )
