"""Sub-agent factory functions for the multi-agent audit."""

from vuln_agent.agents.scanner import create_scanner
from vuln_agent.agents.analyzer import create_analyzer

__all__ = ["create_scanner", "create_analyzer"]
