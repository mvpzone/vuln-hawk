"""Compaction A/B experiment — does forced summarisation help audit quality?

After every N tool calls, ask the agent to summarise its own trajectory,
then start a fresh context with only the system prompt + summary.
Compare precision/recall against an uncompacted baseline. The hypothesis
under test is that a bounded context window, refreshed via the agent's
own summary, focuses attention on task-relevant evidence and improves
reasoning quality on long audits.

Run:
    python eval/compaction_experiment.py --every 10 --target targets/vulnerable_flask_app

The script spawns the agent twice — once with compaction and once
without — and prints a side-by-side comparison. Both runs share the
same ground-truth scorer (`run_eval.score`).
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

load_dotenv(REPO_ROOT / ".env")

from eval.run_eval import render_table, score  # noqa: E402
from vuln_agent.prompts import (  # noqa: E402
    INITIAL_AUDIT_REQUEST,
    TRAJECTORY_SUMMARY_PROMPT,
)
from vuln_agent.report import parse_report  # noqa: E402


async def _drive(target_root: Path, compact_every: int | None) -> str:
    """Run the agent, optionally inserting summarisation pivots."""
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    os.environ["TARGET_CODEBASE_ROOT"] = str(target_root)
    from vuln_agent.agent import root_agent  # noqa: E402

    session_service = InMemorySessionService()
    runner = Runner(agent=root_agent, app_name="vuln_eval_compact", session_service=session_service)
    user_id = "evaluator"

    async def fresh_session() -> str:
        sid = f"compact-{dt.datetime.utcnow().strftime('%Y%m%d-%H%M%S-%f')}"
        await session_service.create_session(app_name="vuln_eval_compact", user_id=user_id, session_id=sid)
        return sid

    session_id = await fresh_session()
    tool_calls = 0
    pivots = 0
    last_summary = ""
    final_text = ""

    async def send(text: str, sid: str) -> tuple[str, int]:
        """Send a user turn, return (final_text, tool_calls_seen)."""
        msg = types.Content(role="user", parts=[types.Part(text=text)])
        calls = 0
        final = ""
        async for event in runner.run_async(user_id=user_id, session_id=sid, new_message=msg):
            if event.content and event.content.parts:
                for p in event.content.parts:
                    if getattr(p, "function_call", None) is not None:
                        calls += 1
            if event.is_final_response() and event.content and event.content.parts:
                final = event.content.parts[0].text or ""
        return final, calls

    request_text = INITIAL_AUDIT_REQUEST
    while True:
        final_text, calls = await send(request_text, session_id)
        tool_calls += calls

        # If the agent produced a final report or no compaction is wanted, stop.
        if compact_every is None or "```json" in final_text or calls == 0:
            break

        if tool_calls >= compact_every * (pivots + 1):
            # Ask for a summary in the *current* session, then start fresh.
            summary, _ = await send(TRAJECTORY_SUMMARY_PROMPT, session_id)
            last_summary = summary
            pivots += 1
            session_id = await fresh_session()
            request_text = (
                "Continuing a vulnerability audit. Here is your progress so far:\n\n"
                f"{summary}\n\n"
                "Resume the audit using the methodology in your system instruction "
                "and produce the final JSON report when ready."
            )
            continue
        # No pivot needed; agent's turn ended without a report — nudge once more.
        request_text = "Continue the audit. Produce the final JSON report when complete."

    print(f"[compaction={compact_every}] tool_calls={tool_calls} pivots={pivots}", file=sys.stderr)
    return final_text


async def main_async(args: argparse.Namespace) -> int:
    truth = json.loads(args.ground_truth.read_text())
    baseline_text = await _drive(args.target, compact_every=None)
    compact_text = await _drive(args.target, compact_every=args.every)

    baseline = score(parse_report(baseline_text), truth)
    compact = score(parse_report(compact_text), truth)

    print("\n### Baseline (no compaction)\n")
    print(render_table(baseline))
    print("\n### Compaction every", args.every, "tool calls\n")
    print(render_table(compact))

    args.results_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out = {
        "compact_every": args.every,
        "baseline": {"precision": baseline["precision"], "recall": baseline["recall"], "f1": baseline["f1"]},
        "compact": {"precision": compact["precision"], "recall": compact["recall"], "f1": compact["f1"]},
    }
    (args.results_dir / f"compaction-{ts}.json").write_text(json.dumps(out, indent=2))
    print(f"\nSaved: {args.results_dir / f'compaction-{ts}.json'}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", type=Path, default=REPO_ROOT / "targets" / "vulnerable_flask_app")
    p.add_argument("--ground-truth", type=Path, default=REPO_ROOT / "eval" / "ground_truth.json")
    p.add_argument("--every", type=int, default=10, help="Compact after every N tool calls.")
    p.add_argument("--results-dir", type=Path, default=REPO_ROOT / "eval" / "results")
    return asyncio.run(main_async(p.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
