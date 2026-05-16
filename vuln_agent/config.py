"""Model and pipeline configuration.

All model strings are overridable via environment variables so you can
swap between Claude model tiers without touching code.

Set VULN_AGENT_BACKEND=vertex to route through Vertex AI, or leave it
unset / set to "anthropic" to use the direct Anthropic API.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from google.adk.models.anthropic_llm import AnthropicLlm, Claude

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


SONNET_MODEL = os.environ.get("VULN_AGENT_SONNET_MODEL", "claude-sonnet-4-6")
HAIKU_MODEL = os.environ.get("VULN_AGENT_HAIKU_MODEL", "claude-haiku-4-5-20251001")
OPUS_MODEL = os.environ.get("VULN_AGENT_OPUS_MODEL", "claude-opus-4-6")

BACKEND = os.environ.get("VULN_AGENT_BACKEND", "anthropic").lower()


def create_llm(model: str) -> AnthropicLlm:
    """Return an LLM instance for the configured backend."""
    if BACKEND == "vertex":
        return Claude(model=model)
    return AnthropicLlm(model=model)


@dataclass(frozen=True)
class ModelConfig:
    root: str = OPUS_MODEL
    scanner: str = SONNET_MODEL
    analyzer: str = SONNET_MODEL
    single: str = SONNET_MODEL


MAX_PARALLEL_SCANNERS = int(os.environ.get("VULN_AGENT_MAX_SCANNERS", "6"))
