"""Dynamic parallel pipeline — modelled on the mythos parallel harness.

Phase 1: Planner (Opus) explores the codebase, identifies focus areas
Phase 2: ParallelAgent runs N scanners (Sonnet) simultaneously
Phase 3: Sequential per set of flags: analyzer (Sonnet) confirms/rejects
Phase 4: Opus synthesises the final JSON report

Each scanner and analyzer is created dynamically at runtime based on
planner output. Scanner tools are bound via closures so parallel
execution doesn't collide (each agent reads from the same target but
operates on its own assigned file scope).
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from google.adk.agents import Agent, ParallelAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from vuln_agent.config import MAX_PARALLEL_SCANNERS, ModelConfig, create_llm, GENERATE_CONTENT_CONFIG  # noqa: F401
from vuln_agent.security import (
    after_model_callback,
    after_tool_callback,
    before_tool_callback,
    on_tool_error_callback,
    print_session_stats,
)
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    run_python_snippet,
    search_code,
)

APP_NAME = "vuln_pipeline"

# ── Colours for terminal output ──────────────────────────────────────
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_CYAN = "\033[36m"
C_RED = "\033[31m"
C_MAGENTA = "\033[35m"
C_ITALIC = "\033[3m"

# ── Token tracking ───────────────────────────────────────────────────
_token_counts: dict[str, dict[str, int]] = {}


def _track_tokens(event, agent_name: str | None = None) -> None:
    usage = getattr(event, "usage_metadata", None)
    if not usage:
        return
    author = agent_name or getattr(event, "author", "unknown")
    inp = getattr(usage, "prompt_token_count", 0) or 0
    out = getattr(usage, "candidates_token_count", 0) or 0
    if author not in _token_counts:
        _token_counts[author] = {"input": 0, "output": 0}
    _token_counts[author]["input"] += inp
    _token_counts[author]["output"] += out


def print_token_summary() -> None:
    if not _token_counts:
        return
    print(f"\n{C_BOLD}Token Usage{C_RESET}", file=sys.stderr)
    total_in = total_out = 0
    for name, counts in sorted(_token_counts.items()):
        inp, out = counts["input"], counts["output"]
        total_in += inp
        total_out += out
        print(f"  {name:35s}  {inp:>8,} in  {out:>8,} out  {inp+out:>8,} total", file=sys.stderr)
    print(
        f"  {C_BOLD}{'TOTAL':35s}  {total_in:>8,} in  {total_out:>8,} out  "
        f"{total_in+total_out:>8,} total{C_RESET}",
        file=sys.stderr,
    )


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class FocusArea:
    file: str
    functions: str
    sinks: str
    description: str


@dataclass
class PipelineResult:
    final_report_text: str = ""
    planner_output: str = ""
    scanner_outputs: dict[str, str] = field(default_factory=dict)
    analyzer_outputs: dict[str, str] = field(default_factory=dict)
    phase_log: list[str] = field(default_factory=list)


def _log(result: PipelineResult, msg: str) -> None:
    result.phase_log.append(msg)
    print(f"[pipeline] {msg}", file=sys.stderr)


# ── Agent runners ────────────────────────────────────────────────────

async def _run_single(agent: Agent, prompt: str, verbose: bool = False) -> str:
    """Run one agent to completion, return its text output."""
    svc = InMemorySessionService()
    sid = f"{agent.name}-session"
    await svc.create_session(app_name=APP_NAME, user_id="pipeline", session_id=sid)
    runner = Runner(agent=agent, app_name=APP_NAME, session_service=svc)
    msg = types.Content(role="user", parts=[types.Part(text=prompt)])
    final = ""
    async for event in runner.run_async(user_id="pipeline", session_id=sid, new_message=msg):
        _track_tokens(event, agent.name)
        if verbose and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "function_call") and part.function_call:
                    fc = part.function_call
                    args_str = str(dict(fc.args))[:150] if fc.args else ""
                    print(f"    {C_GREEN}TOOL:{C_RESET} {fc.name}({args_str})", file=sys.stderr)
                elif part.text:
                    for line in part.text.strip().split("\n")[:3]:
                        print(f"    {C_MAGENTA}{C_ITALIC}{line[:120]}{C_RESET}", file=sys.stderr)
        if event.is_final_response() and event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    final += part.text
    return final


async def _run_parallel_workflow(agents: list[Agent], prompt: str) -> dict[str, str]:
    """Run N agents via ParallelAgent, return outputs keyed by agent name."""
    if not agents:
        return {}
    parallel = ParallelAgent(
        name="parallel_batch",
        description="Runs sub-agents concurrently",
        sub_agents=agents,
    )
    svc = InMemorySessionService()
    await svc.create_session(app_name=APP_NAME, user_id="pipeline", session_id="parallel")
    runner = Runner(agent=parallel, app_name=APP_NAME, session_service=svc)
    msg = types.Content(role="user", parts=[types.Part(text=prompt)])
    outputs: dict[str, str] = {}
    async for event in runner.run_async(user_id="pipeline", session_id="parallel", new_message=msg):
        _track_tokens(event)
        author = getattr(event, "author", None) or ""
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    outputs[author] = outputs.get(author, "") + part.text
                    preview = part.text.strip()[:100]
                    print(f"  {C_CYAN}[{author}]{C_RESET} {preview}", file=sys.stderr)
    return outputs


# ── Agent factories (dynamic, closure-bound) ─────────────────────────

PLANNER_INSTRUCTION = """\
You are a security research planner. Explore the target Python web
application and identify which files and functions need deep vulnerability
analysis.

## Steps

1. Use `list_directory` (recursive) to map the project structure.
2. Use `analyze_python_ast` with "routes" on Python files to find HTTP endpoints.
3. Use `analyze_python_ast` with "imports" to identify dangerous modules.
4. Use `search_code` to locate dangerous sinks: cursor.execute, .objects.raw,
   subprocess, os.system, eval, exec, render_template_string, pickle.loads,
   yaml.load, requests.get, send_file, os.path.join, parseString.
5. Read key files to understand data flow near sinks.

## Output

<focus_areas>
<area file="views.py" functions="sql_lab,cmd_lab" sinks="objects.raw, subprocess shell=True">SQL injection and command injection in views</area>
<area file="utils.py" functions="preview_url" sinks="requests.get">SSRF via unvalidated URL fetch</area>
</focus_areas>

Include EVERY file with at least one dangerous sink reachable from user input.
Do NOT produce a vulnerability report — only the focus areas.
"""


SCANNER_INSTRUCTION = """\
You are a fast security scanner assigned to a specific file.

## Your assignment
File: {file}
Functions to examine: {functions}
Known sinks: {sinks}
Context: {description}

## Steps

1. Use `read_file` to read the assigned file.
2. For each function, identify user-controlled inputs and dangerous sinks.
3. Determine if user input reaches a sink without adequate validation.
4. Use `search_code` to check for middleware or validation helpers.
5. Use `analyze_python_ast` with "calls" to confirm invoked sinks.

## Output

<scanner_findings file="{file}">
<flag function="fn_name" line="42" sink="cursor.execute"
      confidence="HIGH|MEDIUM|LOW"
      vuln_class="SQL Injection|Command Injection|Path Traversal|SSTI|IDOR|SSRF|Hardcoded Secret|XSS|Insecure Deserialization|XXE">
Data flow description: source -> transforms -> sink. Note mitigations.
</flag>
<safe function="other_fn" line="55" reason="Uses parameterized query"/>
</scanner_findings>

Mark safe functions explicitly. Do NOT call transfer_to_agent.
"""


ANALYZER_INSTRUCTION = """\
You are a deep security analyst. Investigate these scanner flags and
CONFIRM or REJECT each by tracing the complete data flow.

## Scanner flags
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
          reason="Input is sanitized by secure_filename"/>
</analyzer_results>

Precision is paramount. Do NOT call transfer_to_agent.
"""


REPORTER_INSTRUCTION = """\
You are a senior security researcher producing the final vulnerability report.
Review the confirmed findings below and apply your own judgment — reject
anything with unconvincing proof.

## Confirmed findings from analyzers
{confirmed_findings}

## Output

Produce a single fenced JSON block:

```json
{{
  "summary": "<one-paragraph overview>",
  "findings": [
    {{
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
    }}
  ]
}}
```

Rules:
- Only include HIGH confidence findings.
- Merge duplicates (same file + function + class = one finding).
- Sequential IDs: F1, F2, F3, ...
- Do NOT invent findings beyond what was confirmed.
"""


_AGENT_KWARGS = dict(
    before_tool_callback=before_tool_callback,
    after_tool_callback=after_tool_callback,
    after_model_callback=after_model_callback,
    on_tool_error_callback=on_tool_error_callback,
)
if GENERATE_CONTENT_CONFIG:
    _AGENT_KWARGS["generate_content_config"] = GENERATE_CONTENT_CONFIG


def _create_planner(cfg: ModelConfig) -> Agent:
    return Agent(
        name="planner",
        model=create_llm(cfg.root),
        description="Reconnaissance planner — maps attack surface",
        instruction=PLANNER_INSTRUCTION,
        tools=[list_directory, read_file, search_code, analyze_python_ast],
        output_key="planner_output",
        **_AGENT_KWARGS,
    )


def _create_scanner(area: FocusArea, index: int, cfg: ModelConfig) -> Agent:
    return Agent(
        name=f"scanner_{index}",
        model=create_llm(cfg.scanner),
        description=f"Scanner for {area.file}: {area.description}",
        instruction=SCANNER_INSTRUCTION.format(
            file=area.file,
            functions=area.functions,
            sinks=area.sinks,
            description=area.description,
        ),
        tools=[read_file, search_code, analyze_python_ast],
        output_key=f"scanner_{index}_output",
        **_AGENT_KWARGS,
    )


def _create_analyzer(scanner_flags: str, index: int, cfg: ModelConfig) -> Agent:
    return Agent(
        name=f"analyzer_{index}",
        model=create_llm(cfg.analyzer),
        description=f"Deep analyzer for flag set {index}",
        instruction=ANALYZER_INSTRUCTION.format(scanner_flags=scanner_flags),
        tools=[read_file, search_code, list_directory, analyze_python_ast, run_python_snippet],
        output_key=f"analyzer_{index}_output",
        **_AGENT_KWARGS,
    )


def _create_reporter(confirmed_findings: str, cfg: ModelConfig) -> Agent:
    return Agent(
        name="reporter",
        model=create_llm(cfg.root),
        description="Final report synthesiser",
        instruction=REPORTER_INSTRUCTION.format(confirmed_findings=confirmed_findings),
        tools=[],
        output_key="reporter_output",
    )


# ── Parsers ──────────────────────────────────────────────────────────

def _parse_focus_areas(planner_output: str) -> list[FocusArea]:
    m = re.search(r"<focus_areas>(.*?)</focus_areas>", planner_output, re.DOTALL)
    if not m:
        return []
    try:
        root = ET.fromstring(f"<root>{m.group(1)}</root>")
    except ET.ParseError:
        return []
    areas = []
    for elem in root.findall("area"):
        areas.append(
            FocusArea(
                file=elem.get("file", ""),
                functions=elem.get("functions", ""),
                sinks=elem.get("sinks", ""),
                description=(elem.text or "").strip(),
            )
        )
    return areas


def _extract_xml_block(text: str, tag: str) -> str:
    m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", text, re.DOTALL)
    return m.group(0) if m else text


# ── Main pipeline ────────────────────────────────────────────────────

async def run_pipeline(model_config: ModelConfig | None = None) -> PipelineResult:
    """Execute the full parallel audit pipeline."""
    cfg = model_config or ModelConfig()
    result = PipelineResult()

    # ── Phase 1: Planner (Opus) ──────────────────────────────────────
    print(f"\n{C_BOLD}Phase 1: Planning — exploring codebase{C_RESET}", file=sys.stderr)
    _log(result, "Phase 1: running planner (Opus) for reconnaissance")

    planner_agent = _create_planner(cfg)
    result.planner_output = await _run_single(
        planner_agent,
        "Explore the target codebase and identify all files and functions "
        "that need security analysis. Output the <focus_areas> block.",
        verbose=True,
    )

    areas = _parse_focus_areas(result.planner_output)
    _log(result, f"Phase 1 complete: {len(areas)} focus areas identified")

    if not areas:
        _log(result, "No focus areas found — planner may have failed")
        result.final_report_text = result.planner_output
        return result

    n = min(len(areas), MAX_PARALLEL_SCANNERS)
    print(f"\n  {C_CYAN}[planner]{C_RESET} {C_BOLD}Focus areas ({len(areas)}):{C_RESET}", file=sys.stderr)
    for i, area in enumerate(areas):
        print(f"    {C_GREEN}{i}{C_RESET}: {area.file} — {area.description}", file=sys.stderr)

    # ── Phase 2: Parallel scanners (Sonnet) ──────────────────────────
    print(f"\n{C_BOLD}Phase 2: Launching {n} scanners in parallel{C_RESET}", file=sys.stderr)
    _log(result, f"Phase 2: launching {n} Sonnet scanners in parallel")

    scanner_agents = []
    for i, area in enumerate(areas[:n]):
        agent = _create_scanner(area, i, cfg)
        scanner_agents.append(agent)
        print(f"  {C_GREEN}[scanner_{i}]{C_RESET} {area.file}: {area.functions}", file=sys.stderr)

    scanner_results = await _run_parallel_workflow(
        scanner_agents,
        "Examine the file assigned to you and output your <scanner_findings> block.",
    )
    result.scanner_outputs = scanner_results
    _log(result, f"Phase 2 complete: received output from {len(scanner_results)} scanners")

    all_flags: list[tuple[str, str]] = []
    for name, output in scanner_results.items():
        flags_xml = _extract_xml_block(output, "scanner_findings")
        if "<flag " in flags_xml:
            all_flags.append((name, flags_xml))
            print(f"  {C_GREEN}[{name}]{C_RESET} Flags raised", file=sys.stderr)
        else:
            print(f"  {C_YELLOW}[{name}]{C_RESET} No flags", file=sys.stderr)

    if not all_flags:
        _log(result, "No flags raised — codebase may be clean")
        result.final_report_text = '```json\n{"summary": "No vulnerabilities found.", "findings": []}\n```'
        return result

    # ── Phase 3: Sequential analyzers (Sonnet) ───────────────────────
    print(f"\n{C_BOLD}Phase 3: Analyzing {len(all_flags)} flag sets{C_RESET}", file=sys.stderr)
    _log(result, f"Phase 3: launching {len(all_flags)} Sonnet analyzers")

    confirmed_blocks = []
    for i, (scanner_name, flags_xml) in enumerate(all_flags):
        print(f"\n  {C_BLUE}[analyzer_{i}]{C_RESET} Investigating flags from {scanner_name}", file=sys.stderr)
        analyzer_agent = _create_analyzer(flags_xml, i, cfg)
        analyzer_output = await _run_single(
            analyzer_agent,
            "Investigate each scanner flag. Confirm or reject it with full "
            "data-flow evidence. Output your <analyzer_results> block.",
        )
        result.analyzer_outputs[f"analyzer_{i}"] = analyzer_output

        block = _extract_xml_block(analyzer_output, "analyzer_results")
        if "<confirmed " in block:
            confirmed_blocks.append(block)
            print(f"  {C_GREEN}[analyzer_{i}]{C_RESET} Confirmed findings", file=sys.stderr)
        else:
            print(f"  {C_YELLOW}[analyzer_{i}]{C_RESET} All flags rejected", file=sys.stderr)

    _log(result, f"Phase 3 complete: {len(confirmed_blocks)} blocks with confirmed findings")

    if not confirmed_blocks:
        _log(result, "No confirmed findings")
        result.final_report_text = '```json\n{"summary": "No confirmed vulnerabilities.", "findings": []}\n```'
        return result

    # ── Phase 4: Reporter (Opus) ─────────────────────────────────────
    confirmed_text = "\n\n".join(confirmed_blocks)
    print(f"\n{C_BOLD}Phase 4: Synthesising final report{C_RESET}", file=sys.stderr)
    _log(result, f"Phase 4: reporter synthesising {len(confirmed_blocks)} confirmed blocks")

    reporter = _create_reporter(confirmed_text, cfg)
    result.final_report_text = await _run_single(
        reporter,
        "Produce the final deduplicated JSON vulnerability report.",
    )
    _log(result, "Phase 4 complete: final report generated")

    print_session_stats()
    return result
