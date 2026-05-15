"""Model and pipeline configuration.

All model strings are overridable via environment variables so you can
swap between Claude model tiers without touching code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


SONNET_MODEL = os.environ.get("VULN_AGENT_SONNET_MODEL", "claude-sonnet-4-6")
HAIKU_MODEL = os.environ.get("VULN_AGENT_HAIKU_MODEL", "claude-haiku-4-5-20251001")
OPUS_MODEL = os.environ.get("VULN_AGENT_OPUS_MODEL", "claude-opus-4-6")


@dataclass(frozen=True)
class ModelConfig:
    planner: str = SONNET_MODEL
    scanner: str = HAIKU_MODEL
    analyzer: str = SONNET_MODEL
    reporter: str = SONNET_MODEL
    single: str = SONNET_MODEL


MAX_PARALLEL_SCANNERS = int(os.environ.get("VULN_AGENT_MAX_SCANNERS", "6"))
