"""Analyzer agent — Sonnet-class model for deep data-flow confirmation.

Receives preliminary flags from the root agent via transfer_to_agent.
Performs rigorous data-flow tracing to confirm or reject each flag,
then transfers back to the root with proof.
"""

from __future__ import annotations

from google.adk.agents import Agent

from vuln_agent.config import ModelConfig, create_llm
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    run_python_snippet,
    search_code,
)


ANALYZER_INSTRUCTION = """\
You are a deep security analyst. The root agent has transferred you a set
of preliminary vulnerability flags to investigate. Your job is to CONFIRM
or REJECT each flag by performing rigorous data-flow analysis.

## Methodology

For EACH flag:
1. Use `read_file` to examine the flagged function AND any callers or
   shared code it depends on.
2. Trace the complete data flow from user-controlled source to the
   dangerous sink. Name every variable and function call in the chain.
3. Check for mitigations: input validation, parameterized queries,
   secure_filename, allowlists, type coercion, CSRF protection.
4. If mitigations exist, determine whether they can be bypassed.
5. Use `search_code` to find how the flagged function is called — is
   user input actually passed to it?
6. Use `run_python_snippet` if you need custom AST traversal to trace
   complex call chains.

## Output format

Report your results in this XML format:

<analyzer_results>
<confirmed id="A1" function="search_users" file="db.py" line_range="42-51"
           vuln_class="SQL Injection" severity="CRITICAL" confidence="HIGH"
           data_flow="request.args.get('q') -> local var q -> f-string -> cursor.execute"
           example_exploit="GET /search?q=' OR '1'='1"
           suggested_fix="Use parameterized binding: cursor.execute('...WHERE name=?', (q,))"/>
<rejected function="get_user_by_id" file="db.py" line_range="55-65"
          reason="Uses parameterized query with ? placeholder"/>
</analyzer_results>

Only mark a finding as <confirmed> if you can trace the COMPLETE path
from user input to sink with no effective mitigation. Precision is
paramount — a false positive is worse than a miss.

When you are done, transfer back to the root agent `vuln_discovery_agent`
with your complete results.
"""


def create_analyzer(model_config: ModelConfig | None = None) -> Agent:
    cfg = model_config or ModelConfig()
    return Agent(
        name="analyzer",
        model=create_llm(cfg.analyzer),
        description=(
            "Deep security analyzer. Transfer scanner flags to this agent "
            "for rigorous data-flow confirmation. It will report back with "
            "confirmed vulnerabilities including full proof of exploitability."
        ),
        instruction=ANALYZER_INSTRUCTION,
        tools=[read_file, search_code, list_directory, analyze_python_ast, run_python_snippet],
    )
