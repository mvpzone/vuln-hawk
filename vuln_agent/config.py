"""Model and pipeline configuration.

Supports three backends:
  - anthropic: Direct Anthropic API (ANTHROPIC_API_KEY)
  - vertex:    Anthropic models via Vertex AI (GOOGLE_CLOUD_PROJECT + LOCATION)
  - gemini:    Google Gemini models (GOOGLE_API_KEY or Vertex AI)

Each agent role (root, scanner, analyzer) can use a different model
string, allowing mixed-provider setups (e.g., Gemini root + Claude
scanners).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from google.adk.models.base_llm import BaseLlm

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


# ── Default model strings per provider ───────────────────────────────

SONNET_MODEL = os.environ.get("VULN_AGENT_SONNET_MODEL", "claude-sonnet-4-6")
HAIKU_MODEL = os.environ.get("VULN_AGENT_HAIKU_MODEL", "claude-haiku-4-5-20251001")
OPUS_MODEL = os.environ.get("VULN_AGENT_OPUS_MODEL", "claude-opus-4-6")
GEMINI_PRO_MODEL = os.environ.get("VULN_AGENT_GEMINI_PRO_MODEL", "gemini-2.5-pro")
GEMINI_FLASH_MODEL = os.environ.get("VULN_AGENT_GEMINI_FLASH_MODEL", "gemini-2.5-flash")

BACKEND = os.environ.get("VULN_AGENT_BACKEND", "anthropic").lower()


# ── LLM factory ──────────────────────────────────────────────────────

def _detect_backend(model: str) -> str:
    """Infer the backend from the model string if not explicitly set."""
    if model.startswith("gemini"):
        return "gemini"
    return BACKEND


def create_llm(model: str) -> BaseLlm:
    """Return an LLM instance for the given model string.

    Auto-detects the backend from the model name:
      - gemini-*  → Gemini (Google AI / Vertex AI)
      - claude-*  → AnthropicLlm or Claude (depending on VULN_AGENT_BACKEND)

    This allows mixed configs like root=gemini-2.5-pro, scanner=claude-sonnet-4-6.
    """
    backend = _detect_backend(model)

    if backend == "gemini":
        from google.adk.models.google_llm import Gemini
        return Gemini(model=model)

    from google.adk.models.anthropic_llm import AnthropicLlm, Claude

    if backend == "vertex":
        return Claude(model=model)
    return AnthropicLlm(model=model)


# ── Per-role model config ────────────────────────────────────────────

def _env_or(key: str, default: str) -> str:
    """Read a model from env, falling back to default."""
    return os.environ.get(key, default)


@dataclass(frozen=True)
class ModelConfig:
    root: str = _env_or("VULN_AGENT_ROOT_MODEL", OPUS_MODEL)
    scanner: str = _env_or("VULN_AGENT_SCANNER_MODEL", SONNET_MODEL)
    analyzer: str = _env_or("VULN_AGENT_ANALYZER_MODEL", SONNET_MODEL)
    single: str = _env_or("VULN_AGENT_SINGLE_MODEL", SONNET_MODEL)


MAX_PARALLEL_SCANNERS = int(os.environ.get("VULN_AGENT_MAX_SCANNERS", "6"))
