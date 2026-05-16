"""Host-driven multi-agent audit pipeline.

Orchestrates four phases using different Claude model tiers:

    Phase 1 — Planner (Sonnet): recon + attack surface mapping
    Phase 2 — Scanners (Haiku, parallel): fast per-file triage
    Phase 3 — Analyzers (Sonnet, parallel): deep data-flow confirmation
    Phase 4 — Reporter (Sonnet): synthesise final JSON report

ADK's transfer_to_agent is Gemini-only, so orchestration is driven by
Python — each phase creates its own Runner, collects output, and feeds
it into the next phase. ParallelAgent handles concurrent sub-agents.
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

from vuln_agent.agents.planner import create_planner
from vuln_agent.agents.scanner import create_scanner
from vuln_agent.agents.analyzer import create_analyzer
from vuln_agent.agents.reporter import create_reporter
from vuln_agent.config import MAX_PARALLEL_SCANNERS, ModelConfig


APP_NAME = "vuln_pipeline"


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


async def _run_single(agent: Agent, prompt: str) -> str:
    """Run one agent to completion and return the final text."""
    svc = InMemorySessionService()
    runner = Runner(agent=agent, app_name=APP_NAME, session_service=svc)
    user_id = "pipeline"
    sid = f"{agent.name}-session"
    await svc.create_session(app_name=APP_NAME, user_id=user_id, session_id=sid)
    msg = types.Content(role="user", parts=[types.Part(text=prompt)])
    final = ""
    async for event in runner.run_async(user_id=user_id, session_id=sid, new_message=msg):
        if event.is_final_response() and event.content and event.content.parts:
            final = event.content.parts[0].text or ""
    return final


async def _run_parallel(agents: list[Agent], prompt: str) -> dict[str, str]:
    """Run multiple agents concurrently via ParallelAgent, return outputs keyed by agent name."""
    if not agents:
        return {}
    parallel = ParallelAgent(
        name="parallel_batch",
        description="Runs sub-agents concurrently",
        sub_agents=agents,
    )
    svc = InMemorySessionService()
    runner = Runner(agent=parallel, app_name=APP_NAME, session_service=svc)
    user_id = "pipeline"
    sid = "parallel-session"
    await svc.create_session(app_name=APP_NAME, user_id=user_id, session_id=sid)
    msg = types.Content(role="user", parts=[types.Part(text=prompt)])
    outputs: dict[str, str] = {}
    async for event in runner.run_async(user_id=user_id, session_id=sid, new_message=msg):
        author = getattr(event, "author", None) or ""
        if event.content and event.content.parts:
            text = event.content.parts[0].text or ""
            if text:
                outputs[author] = outputs.get(author, "") + text
    return outputs


def _parse_focus_areas(planner_output: str) -> list[FocusArea]:
    """Extract <focus_areas> from the planner's output."""
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
    """Extract text inside the outermost <tag>...</tag> from agent output."""
    m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", text, re.DOTALL)
    return m.group(0) if m else text


async def run_pipeline(model_config: ModelConfig | None = None) -> PipelineResult:
    """Execute the full four-phase audit pipeline."""
    cfg = model_config or ModelConfig()
    result = PipelineResult()

    # ── Phase 1: Planner ──────────────────────────────────────────────
    _log(result, "Phase 1: running planner (Sonnet) for reconnaissance")
    planner = create_planner(cfg)
    result.planner_output = await _run_single(
        planner,
        "Explore the target codebase and identify all files and functions "
        "that need security analysis. Output the <focus_areas> block.",
    )
    areas = _parse_focus_areas(result.planner_output)
    _log(result, f"Phase 1 complete: {len(areas)} focus areas identified")

    if not areas:
        _log(result, "No focus areas found — planner may have failed. Raw output follows.")
        result.final_report_text = result.planner_output
        return result

    # ── Phase 2: Scanners (Haiku, parallel) ───────────────────────────
    _log(result, f"Phase 2: launching {min(len(areas), MAX_PARALLEL_SCANNERS)} Haiku scanners in parallel")
    scanners = [
        create_scanner(
            file=a.file,
            functions=a.functions,
            sinks=a.sinks,
            description=a.description,
            model_config=cfg,
        )
        for a in areas[:MAX_PARALLEL_SCANNERS]
    ]
    scanner_results = await _run_parallel(
        scanners,
        "Examine the file assigned to you and output your <scanner_findings> block.",
    )
    result.scanner_outputs = scanner_results
    _log(result, f"Phase 2 complete: received output from {len(scanner_results)} scanners")

    # Collect all scanner flags for the analyzers.
    all_flags: list[tuple[str, str]] = []
    for name, output in scanner_results.items():
        flags_xml = _extract_xml_block(output, "scanner_findings")
        if "<flag " in flags_xml:
            all_flags.append((name, flags_xml))

    if not all_flags:
        _log(result, "No flags raised by any scanner — codebase may be clean")
        result.final_report_text = '```json\n{"summary": "No vulnerabilities found.", "findings": []}\n```'
        return result

    # ── Phase 3: Analyzers (Sonnet, parallel) ─────────────────────────
    _log(result, f"Phase 3: launching {len(all_flags)} Sonnet analyzers for deep data-flow tracing")
    analyzers = [
        create_analyzer(
            scanner_flags=flags_xml,
            area_id=str(i),
            model_config=cfg,
        )
        for i, (_name, flags_xml) in enumerate(all_flags)
    ]
    analyzer_results = await _run_parallel(
        analyzers,
        "Investigate each scanner flag. Confirm or reject it with full "
        "data-flow evidence. Output your <analyzer_results> block.",
    )
    result.analyzer_outputs = analyzer_results
    _log(result, f"Phase 3 complete: received output from {len(analyzer_results)} analyzers")

    confirmed_blocks = []
    for name, output in analyzer_results.items():
        block = _extract_xml_block(output, "analyzer_results")
        if "<confirmed " in block:
            confirmed_blocks.append(block)

    if not confirmed_blocks:
        _log(result, "No confirmed findings from analyzers")
        result.final_report_text = '```json\n{"summary": "No confirmed vulnerabilities.", "findings": []}\n```'
        return result

    # ── Phase 4: Reporter (Sonnet) ────────────────────────────────────
    confirmed_text = "\n\n".join(confirmed_blocks)
    _log(result, f"Phase 4: reporter synthesising {len(confirmed_blocks)} analyzer result blocks")
    reporter = create_reporter(confirmed_text, cfg)
    result.final_report_text = await _run_single(
        reporter,
        "Produce the final deduplicated JSON vulnerability report from the "
        "confirmed findings above.",
    )
    _log(result, "Phase 4 complete: final report generated")
    return result
