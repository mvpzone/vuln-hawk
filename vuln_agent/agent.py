"""ADK agent definition for the vulnerability discovery agent.

Architecture:
    LLM (Gemini)  ->  tool call  ->  result  ->  reasoning  ->  next tool call
                                 (no high-level static analyzers)

The model and tool set are deliberately minimal. All audit intelligence
lives in the system prompt (`prompts.py`) and the agent's own reasoning.
"""

from __future__ import annotations

import os

from google.adk.agents import Agent

from vuln_agent.prompts import VULN_DISCOVERY_SYSTEM_PROMPT
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    run_python_snippet,
    search_code,
)


MODEL_NAME = os.environ.get("VULN_AGENT_MODEL", "gemini-2.5-flash")


root_agent = Agent(
    name="vuln_discovery_agent",
    model=MODEL_NAME,
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
