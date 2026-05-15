"""Vulnerability Discovery Agent — ADK-based security research agent.

LLM + shell-like tools + systematic audit methodology, with no
high-level static analyzers.

`root_agent` is exposed lazily so the `tools` and `report` submodules
can be imported (e.g., for testing or for the `--no-run` eval path)
without requiring the `google-adk` package to be installed.
"""

from __future__ import annotations

__all__ = ["root_agent"]


def __getattr__(name: str):
    if name == "root_agent":
        from vuln_agent.agent import root_agent  # noqa: WPS433 — lazy import is the point.

        return root_agent
    raise AttributeError(f"module 'vuln_agent' has no attribute {name!r}")
