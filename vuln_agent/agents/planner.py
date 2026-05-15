"""Planner agent — Sonnet-class model that performs reconnaissance.

Explores the project structure, identifies all HTTP endpoints, maps the
attack surface, and outputs a structured list of focus areas (files and
functions) that need deep analysis. Downstream scanners each receive
one focus area to investigate in parallel.
"""

from __future__ import annotations

from google.adk.agents import Agent
from google.adk.models.anthropic_llm import Claude

from vuln_agent.config import ModelConfig
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    search_code,
)


PLANNER_INSTRUCTION = """\
You are a security research planner. Your job is to explore a Python web
application codebase and identify which files and functions need deep
vulnerability analysis.

## Steps

1. Use `list_directory` (recursive) to map the project structure.
2. Use `analyze_python_ast` with "routes" on each Python file to find HTTP
   endpoints — these are the primary entry points.
3. Use `analyze_python_ast` with "imports" to understand which frameworks
   and dangerous modules are in use (subprocess, os, pickle, sqlite3,
   requests, etc.).
4. Use `search_code` to locate dangerous sinks: cursor.execute, subprocess,
   os.system, eval, exec, render_template_string, pickle.loads, requests.get,
   send_file, os.path.join.
5. For each file, read enough of it (use `read_file`) to understand whether
   user-controlled input flows near a dangerous sink.

## Output format

When finished, output a single XML block listing focus areas for the
downstream scanners. Each focus area is one file plus a description of
what to investigate:

<focus_areas>
<area file="db.py" functions="search_users,get_user_by_id" sinks="cursor.execute with f-string">SQL query construction with possible user input</area>
<area file="utils.py" functions="convert_file,preview_url" sinks="subprocess.run shell=True, requests.get">Command execution and outbound HTTP with user input</area>
</focus_areas>

Include EVERY file that has at least one dangerous sink reachable from
user input. Do NOT include files that are purely configuration or have
no attack surface.

Do NOT call transfer_to_agent. Do NOT produce a vulnerability report —
that is the job of downstream agents.
"""


def create_planner(model_config: ModelConfig | None = None) -> Agent:
    cfg = model_config or ModelConfig()
    return Agent(
        name="planner",
        model=Claude(model=cfg.planner),
        description="Reconnaissance agent that maps the attack surface and identifies focus areas",
        instruction=PLANNER_INSTRUCTION,
        tools=[list_directory, read_file, search_code, analyze_python_ast],
        output_key="planner_output",
    )
