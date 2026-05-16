"""Evaluate the vulnerability discovery agent against ground truth.

Runs the agent end-to-end against the bundled vulnerable Flask app,
parses its structured JSON report, and scores it against the labelled
findings in `ground_truth.json`. Reports per-class precision/recall/F1
and flags any false-positive traps the agent fell for.

Usage:
    python eval/run_eval.py                          # single-agent (Sonnet)
    python eval/run_eval.py --pipeline               # multi-agent pipeline
    python eval/run_eval.py --target targets/vulnerable_flask_app
    python eval/run_eval.py --no-run --report-file path/to/report.json
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Make `vuln_agent` importable when running this file directly.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

load_dotenv(REPO_ROOT / ".env")

from vuln_agent.prompts import INITIAL_AUDIT_REQUEST  # noqa: E402
from vuln_agent.report import Report, parse_report  # noqa: E402


# Synonyms the agent might use for each canonical class.
CLASS_ALIASES: dict[str, set[str]] = {
    "SQL Injection": {"sql injection", "sqli", "sql-injection"},
    "Command Injection": {"command injection", "os command injection", "rce", "shell injection"},
    "Path Traversal": {"path traversal", "directory traversal", "lfi"},
    "SSTI": {"ssti", "server-side template injection", "template injection"},
    "IDOR": {"idor", "broken access control", "insecure direct object reference"},
    "Hardcoded Secret": {"hardcoded secret", "hardcoded credentials", "secret in source", "hardcoded api key"},
    "SSRF": {"ssrf", "server-side request forgery"},
}


def normalise_class(label: str) -> str | None:
    """Return the canonical class name for a free-form label, or None."""
    s = (label or "").strip().lower()
    for canon, aliases in CLASS_ALIASES.items():
        if s == canon.lower() or s in aliases:
            return canon
        for a in aliases:
            if a in s:
                return canon
    return None


def line_ranges_overlap(a: list[int], b: list[int]) -> bool:
    """Strict overlap on closed intervals [a0, a1] and [b0, b1]."""
    if not a or not b:
        return False
    a0, a1 = a[0], a[-1]
    b0, b1 = b[0], b[-1]
    return a0 <= b1 and b0 <= a1


def match_trap(finding: dict[str, Any], trap: dict[str, Any]) -> bool:
    """A finding falls for a trap if it points at the same function/file."""
    same_file = Path(finding.get("file", "")).name == Path(trap["file"]).name
    same_fn = (finding.get("function") or "").strip() == trap["function"]
    return same_file and same_fn


def match_finding(finding: dict[str, Any], truth: dict[str, Any]) -> bool:
    """True iff the reported finding matches a real vulnerability.

    Requires:
      - same file
      - same vulnerability class (alias-normalised)
      - same function name OR overlapping line range

    Function-name agreement is the strongest signal — when the agent
    names the exact handler we count it even if line numbers drift.
    """
    if normalise_class(finding.get("vuln_class", "")) != normalise_class(truth["class"]):
        return False
    if Path(finding.get("file", "")).name != Path(truth["file"]).name:
        return False
    fn = (finding.get("function") or "").strip()
    if fn and fn == truth.get("function"):
        return True
    f_range = finding.get("line_range") or []
    if isinstance(f_range, int):
        f_range = [f_range]
    if f_range and line_ranges_overlap(list(f_range), truth["line_range"]):
        # Don't credit a hit if the line range coincidentally overlaps the
        # vuln's range while the function name points at a known trap.
        if fn:
            return True
        return True
    return False


async def run_agent(target_root: Path, use_pipeline: bool = False) -> str:
    """Drive the agent to completion against `target_root`. Returns the final
    assistant text. Heavy import here so --no-run paths don't need ADK."""
    os.environ["TARGET_CODEBASE_ROOT"] = str(target_root)

    if use_pipeline:
        from vuln_agent.pipeline import run_pipeline
        result = await run_pipeline()
        for entry in result.phase_log:
            print(f"  {entry}", file=sys.stderr)
        return result.final_report_text

    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types
    from vuln_agent.agent import root_agent

    session_service = InMemorySessionService()
    runner = Runner(agent=root_agent, app_name="vuln_eval", session_service=session_service)
    user_id = "evaluator"
    session_id = f"eval-{dt.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    await session_service.create_session(app_name="vuln_eval", user_id=user_id, session_id=session_id)

    message = types.Content(role="user", parts=[types.Part(text=INITIAL_AUDIT_REQUEST)])
    final_text = ""
    tool_calls = 0
    async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=message):
        if event.content and event.content.parts:
            for p in event.content.parts:
                if getattr(p, "function_call", None) is not None:
                    tool_calls += 1
        if event.is_final_response() and event.content and event.content.parts:
            final_text = event.content.parts[0].text or ""
    print(f"[runner] tool calls: {tool_calls}", file=sys.stderr)
    return final_text


def score(report: Report, truth: dict[str, Any]) -> dict[str, Any]:
    """Score a parsed report against ground truth. Returns a metrics dict."""
    findings = [
        {
            "id": f.id,
            "vuln_class": f.vuln_class,
            "file": f.file,
            "function": f.function,
            "line_range": f.line_range,
            "severity": f.severity,
            "confidence": f.confidence,
        }
        for f in report.findings
    ]

    matched_truths: set[str] = set()
    true_positives: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    trap_hits: list[dict[str, Any]] = []

    for finding in findings:
        # Trap check first: if the agent named a function we labelled as a
        # false-positive trap, count it as FP even if the line range happens
        # to overlap a real vuln nearby.
        trap = next((t for t in truth["false_positive_traps"] if match_trap(finding, t)), None)
        if trap is not None:
            false_positives.append(finding)
            trap_hits.append({"finding": finding, "trap_id": trap["id"]})
            continue

        matched = None
        for vuln in truth["vulnerabilities"]:
            if vuln["id"] in matched_truths:
                continue
            if match_finding(finding, vuln):
                matched = vuln
                break
        if matched:
            matched_truths.add(matched["id"])
            true_positives.append({"finding": finding, "truth_id": matched["id"]})
        else:
            false_positives.append(finding)

    false_negatives = [v for v in truth["vulnerabilities"] if v["id"] not in matched_truths]

    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "counts": {"tp": tp, "fp": fp, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "trap_hits": trap_hits,
        "report_summary": report.summary,
        "parse_error": report.parse_error,
    }


def render_table(metrics: dict[str, Any]) -> str:
    """ASCII results table for stdout."""
    lines = []
    lines.append("=" * 64)
    lines.append("Vulnerability Discovery Agent — Evaluation Results")
    lines.append("=" * 64)
    c = metrics["counts"]
    lines.append(f"True positives:  {c['tp']}")
    lines.append(f"False positives: {c['fp']}")
    lines.append(f"False negatives: {c['fn']}")
    lines.append(f"Precision:       {metrics['precision']:.3f}")
    lines.append(f"Recall:          {metrics['recall']:.3f}")
    lines.append(f"F1:              {metrics['f1']:.3f}")
    lines.append(f"Traps triggered: {len(metrics['trap_hits'])}")
    lines.append("-" * 64)
    if metrics["true_positives"]:
        lines.append("Hits:")
        for tp in metrics["true_positives"]:
            f = tp["finding"]
            lines.append(f"  [{tp['truth_id']}] {f['vuln_class']:<22} {f['file']}:{f.get('line_range')}")
    if metrics["false_negatives"]:
        lines.append("Misses:")
        for fn in metrics["false_negatives"]:
            lines.append(f"  [{fn['id']}] {fn['class']:<22} {fn['file']}:{fn['line_range']}")
    if metrics["false_positives"]:
        lines.append("False positives:")
        for fp in metrics["false_positives"]:
            lines.append(f"  -  {fp['vuln_class']:<22} {fp['file']}:{fp.get('line_range')}")
    if metrics["trap_hits"]:
        lines.append("Triggered traps:")
        for t in metrics["trap_hits"]:
            f = t["finding"]
            lines.append(f"  -  {t['trap_id']}  {f['file']}::{f['function']}")
    if metrics["parse_error"]:
        lines.append(f"NOTE: report parse error: {metrics['parse_error']}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        type=Path,
        default=REPO_ROOT / "targets" / "vulnerable_flask_app",
        help="Path to the target codebase to audit.",
    )
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=REPO_ROOT / "eval" / "ground_truth.json",
    )
    parser.add_argument("--pipeline", action="store_true", help="Use multi-agent pipeline (Haiku scanners + Sonnet analyzers).")
    parser.add_argument("--no-run", action="store_true", help="Skip the agent and score an existing report.")
    parser.add_argument("--report-file", type=Path, help="Path to a saved agent report (used with --no-run).")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=REPO_ROOT / "eval" / "results",
    )
    args = parser.parse_args()

    truth = json.loads(args.ground_truth.read_text())

    if args.no_run:
        if not args.report_file or not args.report_file.exists():
            print("error: --no-run requires --report-file pointing to a saved report.", file=sys.stderr)
            return 2
        text = args.report_file.read_text()
    else:
        text = asyncio.run(run_agent(args.target, use_pipeline=args.pipeline))

    report = parse_report(text)
    metrics = score(report, truth)
    print(render_table(metrics))

    args.results_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    (args.results_dir / f"report-{ts}.txt").write_text(text)
    (args.results_dir / f"metrics-{ts}.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nSaved: {args.results_dir / f'report-{ts}.txt'}")
    print(f"Saved: {args.results_dir / f'metrics-{ts}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
