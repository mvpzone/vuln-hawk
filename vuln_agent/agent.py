"""ADK agent definition for `adk web` and single-agent mode.

Two modes of operation:

  1. Single-agent (root_agent): one Sonnet agent with all five tools,
     used by `adk web` and the default `run_eval.py` path. Good for
     quick interactive sessions.

  2. Multi-agent pipeline (vuln_agent.pipeline.run_pipeline): Planner →
     parallel Haiku scanners → parallel Sonnet analyzers → Sonnet
     reporter. Used by `run_eval.py --pipeline`. Better precision on
     larger codebases because each sub-agent operates within a focused
     context window.

Architecture:
    Claude (Anthropic)  ->  tool call  ->  result  ->  reasoning  ->  next tool call
                                       (no high-level static analyzers)
"""

from __future__ import annotations

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from vuln_agent.config import ModelConfig
from vuln_agent.prompts import VULN_DISCOVERY_SYSTEM_PROMPT
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    run_python_snippet,
    search_code,
)


_cfg = ModelConfig()


root_agent = Agent(
    name="vuln_discovery_agent",
    model=Claude(model=_cfg.single),
    description=(
        "A security research agent that audits Python web application codebases "
        "for exploitable vulnerabilities using systematic data flow analysis."
    ),
    instruction=VULN_DISCOVERY_SYSTEM_PROMPT,
    tools=[
        read_file,
        search_code,
        list_directory,
        analyze_python_ast,
        run_python_snippet,
    ],
)
