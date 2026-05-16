"""ADK agent definition — dynamic sub-agent spawning for `adk web`.

Root agent (Opus) does recon, then calls create_scan_team() to
dynamically spawn N scanner sub-agents based on codebase size. These
appear as real sub-agents visible in `adk web` via transfer_to_agent.
After scanning, calls create_analysis_team() to spawn analyzers.

    Root (Opus)
      ├── calls create_scan_team(areas)  → injects scanner_0..N into sub_agents
      ├── transfer_to_agent("scanner_0") → visible in adk web
      ├── transfer_to_agent("scanner_1") → visible in adk web
      ├── ...
      ├── calls create_analysis_team(flags) → injects analyzer_0..M into sub_agents
      ├── transfer_to_agent("analyzer_0") → visible in adk web
      └── produces final JSON report
"""

from __future__ import annotations

from google.adk.agents import Agent

from vuln_agent.config import ModelConfig, create_llm, MAX_PARALLEL_SCANNERS
from vuln_agent.security import (
    after_model_callback,
    after_tool_callback,
    before_tool_callback,
    on_tool_error_callback,
)
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    run_python_snippet,
    search_code,
)


_cfg = ModelConfig()


# ── Scanner / Analyzer instructions ─────────────────────────────────

SCANNER_INSTRUCTION = """\
You are scanner agent `{name}` assigned to a specific area of the codebase.

## Your assignment
{assignment}

## Steps

1. Use `read_file` to read the assigned file(s).
2. For each function, identify user-controlled inputs and dangerous sinks.
3. Determine if user input reaches a sink without adequate validation.
4. Use `search_code` to check for middleware or validation helpers.
5. Use `analyze_python_ast` with "calls" to confirm invoked sinks.

## Output

Report findings as XML:

<scanner_findings>
<flag function="fn_name" line="42" sink="cursor.execute"
      confidence="HIGH|MEDIUM|LOW"
      vuln_class="SQL Injection|Command Injection|Path Traversal|SSTI|IDOR|SSRF|Hardcoded Secret|XSS|Insecure Deserialization|XXE">
Data flow: source -> transforms -> sink. Note mitigations.
</flag>
<safe function="other_fn" line="55" reason="Uses parameterized query"/>
</scanner_findings>

Mark safe functions explicitly. When done, transfer back to `vuln_discovery_agent`.
"""

ANALYZER_INSTRUCTION = """\
You are analyzer agent `{name}`. Investigate these scanner flags and
CONFIRM or REJECT each by tracing the complete data flow.

## Scanner flags to investigate
{scanner_flags}

## Methodology

For EACH flag:
1. Read the flagged function and its callers.
2. Trace the complete path from user input to sink.
3. Check for mitigations (validation, parameterization, allowlists).
4. Determine if mitigations can be bypassed.
5. Use `search_code` to find how the function is called.
6. Use `run_python_snippet` for custom AST analysis if needed.

## Output

<analyzer_results>
<confirmed id="A1" function="fn" file="f.py" line_range="42-51"
           vuln_class="SQL Injection" severity="CRITICAL" confidence="HIGH"
           data_flow="request.POST['name'] -> f-string -> objects.raw()"
           example_exploit="POST /sql_lab name=' OR 1=1--"
           suggested_fix="Use parameterized queries"/>
<rejected function="fn2" file="f.py" line_range="55-65"
          reason="Input is sanitized"/>
</analyzer_results>

Precision is paramount. When done, transfer back to `vuln_discovery_agent`.
"""


# ── Dynamic team creation tools ──────────────────────────────────────

# Reference to root_agent — set after definition below.
_root_agent: Agent | None = None


def _inject_sub_agents(agents: list[Agent]) -> None:
    """Add agents to root's sub_agents at runtime. Sets parent_agent so
    transfer_to_agent discovers them on the next LLM call."""
    for agent in agents:
        agent.parent_agent = _root_agent
    _root_agent.sub_agents.extend(agents)


def _clear_sub_agents(prefix: str) -> None:
    """Remove sub-agents matching a name prefix (cleanup between phases)."""
    to_remove = [a for a in _root_agent.sub_agents if a.name.startswith(prefix)]
    for agent in to_remove:
        agent.parent_agent = None
    _root_agent.sub_agents = [a for a in _root_agent.sub_agents if a not in to_remove]


def create_scan_team(focus_areas: list[dict]) -> dict:
    """Dynamically create scanner sub-agents from focus areas identified during
    reconnaissance. Each scanner becomes a transfer target visible in the UI.
    After calling this, use transfer_to_agent to delegate to each scanner.

    Args:
        focus_areas: List of dicts, each with keys: file, functions, sinks,
            description. Example: [{"file": "views.py", "functions": "sql_lab,
            cmd_lab", "sinks": "objects.raw, subprocess", "description":
            "SQL injection and command injection"}]

    Returns:
        dict with scanner names created. Transfer to each one to start scanning.
    """
    _clear_sub_agents("scanner_")
    n = min(len(focus_areas), MAX_PARALLEL_SCANNERS)
    scanners = []
    for i, area in enumerate(focus_areas[:n]):
        if isinstance(area, dict):
            file = area.get("file", "")
            functions = area.get("functions", "")
            sinks = area.get("sinks", "")
            description = area.get("description", "")
        else:
            file = functions = sinks = ""
            description = str(area)

        assignment = (
            f"File: {file}\n"
            f"Functions: {functions}\n"
            f"Known sinks: {sinks}\n"
            f"Context: {description}"
        )
        name = f"scanner_{i}"
        agent = Agent(
            name=name,
            model=create_llm(_cfg.scanner),
            description=f"Security scanner for {file}: {description}",
            instruction=SCANNER_INSTRUCTION.format(name=name, assignment=assignment),
            tools=[read_file, search_code, analyze_python_ast],
            before_tool_callback=before_tool_callback,
            after_tool_callback=after_tool_callback,
            after_model_callback=after_model_callback,
            on_tool_error_callback=on_tool_error_callback,
        )
        scanners.append(agent)

    _inject_sub_agents(scanners)
    names = [a.name for a in scanners]
    return {
        "status": "ok",
        "scanners_created": names,
        "instruction": (
            f"Created {len(names)} scanner agents: {', '.join(names)}. "
            "Now transfer to each one to start scanning. Transfer to them "
            "one at a time — each will report back when done."
        ),
    }


def create_analysis_team(flag_sets: list[dict]) -> dict:
    """Dynamically create analyzer sub-agents from scanner findings.
    Each analyzer becomes a transfer target visible in the UI.

    Args:
        flag_sets: List of dicts, each with keys: scanner_name, flags_xml.
            flags_xml is the <scanner_findings> XML block from a scanner.
            Example: [{"scanner_name": "scanner_0", "flags_xml": "<scanner_findings>...</scanner_findings>"}]

    Returns:
        dict with analyzer names created. Transfer to each one to start analysis.
    """
    _clear_sub_agents("analyzer_")
    analyzers = []
    for i, flag_set in enumerate(flag_sets):
        if isinstance(flag_set, dict):
            flags_xml = flag_set.get("flags_xml", "")
        else:
            flags_xml = str(flag_set)

        name = f"analyzer_{i}"
        agent = Agent(
            name=name,
            model=create_llm(_cfg.analyzer),
            description=f"Deep security analyzer for flag set {i}",
            instruction=ANALYZER_INSTRUCTION.format(name=name, scanner_flags=flags_xml),
            tools=[read_file, search_code, list_directory, analyze_python_ast, run_python_snippet],
            before_tool_callback=before_tool_callback,
            after_tool_callback=after_tool_callback,
            after_model_callback=after_model_callback,
            on_tool_error_callback=on_tool_error_callback,
        )
        analyzers.append(agent)

    _inject_sub_agents(analyzers)
    names = [a.name for a in analyzers]
    return {
        "status": "ok",
        "analyzers_created": names,
        "instruction": (
            f"Created {len(names)} analyzer agents: {', '.join(names)}. "
            "Now transfer to each one to start deep analysis. Each will "
            "report back with confirmed/rejected findings."
        ),
    }


# ── Root agent ───────────────────────────────────────────────────────

ROOT_INSTRUCTION = """\
You are a senior security researcher (strategist) leading a vulnerability
audit of a Python web application codebase.

You have two team-creation tools that dynamically spawn specialist
sub-agents you can then transfer to:

- **create_scan_team(focus_areas)**: Creates N scanner sub-agents (one per
  focus area). After calling it, transfer to each scanner by name.
- **create_analysis_team(flag_sets)**: Creates M analyzer sub-agents (one
  per set of scanner flags). After calling it, transfer to each analyzer.

## Your workflow

### Phase 1: Reconnaissance (you do this yourself)
1. Use `list_directory` recursively to map the project structure.
2. Use `analyze_python_ast` with "routes" on key files to find HTTP endpoints.
3. Use `analyze_python_ast` with "imports" to identify dangerous modules.
4. Use `search_code` to locate dangerous sinks: cursor.execute, .objects.raw,
   subprocess, os.system, eval, exec, render_template_string, pickle.loads,
   yaml.load, requests.get, send_file, os.path.join, parseString.

### Phase 2: Create & Delegate Scanners
5. Based on recon, build a list of focus areas (file + functions + sinks).
6. Call `create_scan_team` with the focus areas — this spawns scanner agents.
7. Transfer to each scanner one at a time. Each will scan its assigned file
   and transfer back to you with findings.

### Phase 3: Create & Delegate Analyzers
8. Collect all scanner flags with confidence MEDIUM or HIGH.
9. Call `create_analysis_team` with the flag sets — this spawns analyzer agents.
10. Transfer to each analyzer one at a time. Each will trace data flows and
    transfer back with confirmed/rejected findings.

### Phase 4: Final Report (you produce this yourself)
11. Review all confirmed findings. Reject anything with unconvincing proof.
12. Produce the final report as a single fenced JSON block:

```json
{
  "summary": "<one-paragraph overview>",
  "findings": [
    {
      "id": "F1",
      "vuln_class": "SQL Injection | Command Injection | Path Traversal | SSTI | IDOR | SSRF | Hardcoded Secret | XSS | Insecure Deserialization | XXE",
      "file": "<relative path>",
      "function": "<handler name>",
      "line_range": [<start>, <end>],
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "confidence": "HIGH | MEDIUM | LOW",
      "data_flow": "<source -> transforms -> sink>",
      "example_exploit": "<concrete request>",
      "suggested_fix": "<short remediation>"
    }
  ]
}
```

## Critical Rules
- NEVER use external static analysis tools. Reason through the code yourself.
- Focus on vulnerabilities that are ACTUALLY EXPLOITABLE.
- Precision over recall — only include HIGH confidence findings.
- You are the final decision maker.
"""


root_agent = Agent(
    name="vuln_discovery_agent",
    model=create_llm(_cfg.root),
    description=(
        "Senior security strategist that audits Python web application "
        "codebases by dynamically spawning scanner and analyzer sub-agents."
    ),
    instruction=ROOT_INSTRUCTION,
    tools=[
        read_file,
        search_code,
        list_directory,
        analyze_python_ast,
        run_python_snippet,
        create_scan_team,
        create_analysis_team,
    ],
    before_tool_callback=before_tool_callback,
    after_tool_callback=after_tool_callback,
    after_model_callback=after_model_callback,
    on_tool_error_callback=on_tool_error_callback,
)

# Set the module-level reference so team-creation tools can mutate sub_agents.
_root_agent = root_agent
