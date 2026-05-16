"""ADK agent definition — multi-agent hierarchy for `adk web`.

Root agent (Opus) acts as strategist: explores the codebase, partitions
the attack surface, and delegates file-level work to sub-agents via
transfer_to_agent. Sub-agents (Sonnet) do the hands-on scanning and
deep analysis, then transfer back with proof of findings.

    Root (Opus)  ──transfer──►  Scanner (Sonnet)  ──transfer back──►  Root
    Root (Opus)  ──transfer──►  Analyzer (Sonnet)  ──transfer back──►  Root
    Root (Opus)  ──produces──►  Final JSON Report
"""

from __future__ import annotations

from google.adk.agents import Agent

from vuln_agent.config import ModelConfig, create_llm
from vuln_agent.agents.scanner import create_scanner
from vuln_agent.agents.analyzer import create_analyzer
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    run_python_snippet,
    search_code,
)


ROOT_INSTRUCTION = """\
You are a senior security researcher (strategist) leading a vulnerability
audit of a Python web application codebase. You have two specialist
sub-agents you can delegate work to:

- **scanner**: fast triage agent. Transfer a file name and list of
  functions to it for quick vulnerability scanning. It will report back
  with flagged and safe functions.
- **analyzer**: deep analysis agent. Transfer scanner flags to it for
  rigorous data-flow confirmation. It will report back with confirmed
  vulnerabilities including full exploit proof.

## Your workflow

### Phase 1: Reconnaissance (you do this yourself)
1. Use `list_directory` recursively to map the project structure.
2. Use `analyze_python_ast` with "routes" on key files to find HTTP
   endpoints — these are the entry points.
3. Use `analyze_python_ast` with "imports" to understand which frameworks
   and dangerous modules are in use.
4. Use `search_code` to locate dangerous sinks: cursor.execute, subprocess,
   os.system, eval, exec, render_template_string, pickle.loads, yaml.load,
   requests.get, send_file, os.path.join.

### Phase 2: Partition & Delegate Scanning
5. Based on your recon, identify which files and functions need security
   analysis. Group them into logical units.
6. For each unit, transfer to `scanner` with a clear assignment:
   "Scan file X, focusing on functions Y and Z. Known sinks: ..."
7. Wait for the scanner to report back with its findings.
8. Repeat for each file/area that needs scanning.

### Phase 3: Deep Analysis
9. Collect all scanner flags. For any flag with confidence MEDIUM or
   HIGH, transfer to `analyzer` with the flag details.
10. The analyzer will trace data flows and report back with confirmed
    or rejected findings, including exploit proof.

### Phase 4: Final Report (you produce this yourself)
11. Review all confirmed findings from the analyzer. Apply your own
    judgment — reject anything that lacks convincing proof.
12. Produce the final report as a single fenced JSON block:

```json
{
  "summary": "<one-paragraph overview of what you audited and findings>",
  "findings": [
    {
      "id": "F1",
      "vuln_class": "SQL Injection | Command Injection | Path Traversal | SSTI | IDOR | SSRF | Hardcoded Secret | XSS | Insecure Deserialization | XXE | Open Redirect",
      "file": "<relative path>",
      "function": "<handler name>",
      "line_range": [<start>, <end>],
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "confidence": "HIGH | MEDIUM | LOW",
      "data_flow": "<source -> transforms -> sink>",
      "example_exploit": "<concrete request or input>",
      "suggested_fix": "<short remediation>"
    }
  ]
}
```

## Critical Rules
- NEVER use external static analysis tools. Reason through the code yourself.
- Focus on vulnerabilities that are ACTUALLY EXPLOITABLE, not just bad practice.
- Trace data flows completely before reporting.
- Check for existing mitigations before reporting.
- Precision over recall — only include HIGH confidence findings in the final report.
- You are the final decision maker. If a sub-agent's proof is unconvincing, drop it.
"""


_cfg = ModelConfig()

root_agent = Agent(
    name="vuln_discovery_agent",
    model=create_llm(_cfg.root),
    description=(
        "Senior security strategist that audits Python web application "
        "codebases by partitioning work across scanner and analyzer sub-agents."
    ),
    instruction=ROOT_INSTRUCTION,
    tools=[
        read_file,
        search_code,
        list_directory,
        analyze_python_ast,
        run_python_snippet,
    ],
    sub_agents=[
        create_scanner(_cfg),
        create_analyzer(_cfg),
    ],
)
