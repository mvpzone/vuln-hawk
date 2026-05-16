"""Security gateway — agent-level callbacks that enforce safety constraints.

Attached via before_tool_callback / after_tool_callback on every agent
(root + dynamically spawned sub-agents). Works natively in `adk web`
without requiring a custom Runner or plugin.

Three enforcement layers per tool call:
  1. before_tool_callback: command denylist, arg blocklist, path checks,
     turn limits
  2. Tool execution (if allowed)
  3. after_tool_callback: credential scrubbing, output truncation
"""

from __future__ import annotations

import os
import re
import sys
import time
from typing import Any, Optional

# ── Configuration ────────────────────────────────────────────────────

MAX_CALLS_PER_SESSION = int(os.environ.get("VULN_AGENT_MAX_TOOL_CALLS", "2500"))
MAX_OUTPUT_BYTES = int(os.environ.get("VULN_AGENT_MAX_OUTPUT_BYTES", "102400"))

# Commands the agent must never execute (even inside run_python_snippet).
COMMAND_DENYLIST = frozenset([
    "curl", "wget", "nc", "netcat", "ncat", "docker", "podman",
    "ssh", "scp", "sftp", "git", "pip", "pip3", "npm", "yarn",
])

# Patterns that indicate sandbox escape or credential theft attempts.
ARG_DENYLIST_PATTERNS = [
    re.compile(r"169\.254\.169\.254"),            # cloud metadata endpoint
    re.compile(r"/var/run/docker\.sock"),          # docker socket
    re.compile(r"/proc/1/root"),                   # namespace escape
    re.compile(r"/proc/sysrq"),                    # kernel sysrq
    re.compile(r"\$\(\s*(curl|wget|nc|ssh|scp)"),  # command substitution
    re.compile(r"`\s*(curl|wget|nc|ssh|scp)"),     # backtick execution
    re.compile(r"\|\s*(nc|netcat|curl|wget)\b"),   # pipe to network tool
    re.compile(r">\s*/dev/(sd|tcp|udp)"),           # redirect to device
    re.compile(r"mkfifo.*/dev/"),                   # named pipe to device
]

# Patterns scrubbed from tool output before returning to the agent.
CREDENTIAL_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                         # AWS access key
    re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"),         # PEM key
    re.compile(r"ghp_[A-Za-z0-9_]{36}"),                     # GitHub PAT
    re.compile(r"gho_[A-Za-z0-9_]{36}"),                     # GitHub OAuth
    re.compile(r"ya29\.[A-Za-z0-9_-]+"),                     # GCP OAuth token
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),                # Anthropic API key
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                      # OpenAI-style key
    re.compile(r"xox[bps]-[A-Za-z0-9-]+"),                   # Slack token
]

# ── Session state ────────────────────────────────────────────────────

_call_count = 0
_denied_count = 0
_start_time = time.time()
_token_counts: dict[str, dict[str, int]] = {}


def reset_session() -> None:
    """Reset counters for a new session."""
    global _call_count, _denied_count, _start_time
    _call_count = 0
    _denied_count = 0
    _start_time = time.time()
    _token_counts.clear()


_model_calls = 0


def get_stats() -> dict:
    """Return current session stats as a dict."""
    elapsed = time.time() - _start_time
    total_in = sum(c["input"] for c in _token_counts.values())
    total_out = sum(c["output"] for c in _token_counts.values())
    return {
        "tool_calls": _call_count,
        "denied": _denied_count,
        "model_calls": _model_calls,
        "elapsed_seconds": round(elapsed, 1),
        "tokens": {
            "total_input": total_in,
            "total_output": total_out,
            "total": total_in + total_out,
            "per_agent": dict(_token_counts),
        },
    }


def print_session_stats() -> None:
    elapsed = time.time() - _start_time
    print(
        f"\n[security_gateway] Session stats: {_call_count} tool calls, "
        f"{_model_calls} model calls, {_denied_count} denied, {elapsed:.0f}s elapsed",
        file=sys.stderr,
    )
    if _token_counts:
        print(f"[security_gateway] Token usage:", file=sys.stderr)
        total_in = total_out = 0
        for name, counts in sorted(_token_counts.items()):
            inp, out = counts["input"], counts["output"]
            total_in += inp
            total_out += out
            print(f"  {name:35s}  {inp:>8,} in  {out:>8,} out", file=sys.stderr)
        print(f"  {'TOTAL':35s}  {total_in:>8,} in  {total_out:>8,} out", file=sys.stderr)


# ── Validation helpers ───────────────────────────────────────────────

def _check_code_snippet(code: str) -> Optional[dict]:
    """Check run_python_snippet code for dangerous patterns."""
    for pattern in ARG_DENYLIST_PATTERNS:
        if pattern.search(code):
            return {"status": "error", "error": "Blocked pattern in code snippet"}

    lines = code.lower().split("\n")
    for line in lines:
        stripped = line.strip()
        for cmd in COMMAND_DENYLIST:
            if f"subprocess" in stripped and cmd in stripped:
                return {"status": "error", "error": f"Blocked command in snippet: {cmd}"}
            if f"os.system" in stripped and cmd in stripped:
                return {"status": "error", "error": f"Blocked command in snippet: {cmd}"}
            if f"os.popen" in stripped and cmd in stripped:
                return {"status": "error", "error": f"Blocked command in snippet: {cmd}"}

    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(code):
            return {"status": "error", "error": "Credential pattern detected in snippet"}

    return None


def _check_search_pattern(pattern: str) -> Optional[dict]:
    """Prevent searching for credentials in the target codebase."""
    for cred_pattern in CREDENTIAL_PATTERNS:
        if cred_pattern.search(pattern):
            return {"status": "error", "error": "Credential pattern in search query"}
    return None


def _scrub_output(result: Any) -> Optional[dict]:
    """Redact credentials and truncate oversized output."""
    output = str(result)
    modified = False

    for pattern in CREDENTIAL_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", output)
        if cleaned != output:
            output = cleaned
            modified = True

    if len(output) > MAX_OUTPUT_BYTES:
        output = output[:MAX_OUTPUT_BYTES] + "\n...[truncated]"
        modified = True

    if modified:
        return {"result": output}
    return None


# ── Agent callbacks ──────────────────────────────────────────────────

def before_tool_callback(tool, args, tool_context) -> Optional[dict]:
    """Called before every tool invocation. Returns a dict to block the
    call and use the dict as the tool result instead."""
    global _call_count, _denied_count

    _call_count += 1

    if _call_count > MAX_CALLS_PER_SESSION:
        _denied_count += 1
        return {"status": "error", "error": f"Session tool call limit exceeded ({MAX_CALLS_PER_SESSION})"}

    tool_name = tool.name if hasattr(tool, "name") else str(tool)

    if tool_name == "run_python_snippet":
        code = args.get("code", "")
        result = _check_code_snippet(code)
        if result:
            _denied_count += 1
            return result

    if tool_name == "search_code":
        pattern = args.get("pattern", "")
        result = _check_search_pattern(pattern)
        if result:
            _denied_count += 1
            return result

    return None


def after_tool_callback(tool, args, tool_context, tool_response) -> Optional[dict]:
    """Called after every tool invocation. Scrubs credentials and
    truncates oversized output."""
    return _scrub_output(tool_response)


def on_tool_error_callback(tool, args, tool_context, error) -> Optional[dict]:
    """Called when a tool raises an exception. Returns a safe error
    message instead of letting the exception propagate."""
    return {"status": "error", "error": f"Tool execution failed: {type(error).__name__}: {error}"}


# ── Model callback (token tracking) ─────────────────────────────────

def after_model_callback(callback_context, llm_response) -> Optional[Any]:
    """Called after every LLM invocation. Tracks token usage per agent."""
    global _model_calls
    _model_calls += 1

    usage = getattr(llm_response, "usage_metadata", None)
    if not usage:
        return None

    agent_name = getattr(callback_context, "agent_name", "unknown")
    inp = getattr(usage, "prompt_token_count", 0) or 0
    out = getattr(usage, "candidates_token_count", 0) or 0

    if agent_name not in _token_counts:
        _token_counts[agent_name] = {"input": 0, "output": 0}
    _token_counts[agent_name]["input"] += inp
    _token_counts[agent_name]["output"] += out

    return None
