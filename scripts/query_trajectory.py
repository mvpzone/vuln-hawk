#!/usr/bin/env python3
"""Query agent trajectories from a running ADK web session.

Connects to the ADK web server's REST API and pulls the full event
log for a session — every tool call, response, transfer, and text
output from every agent (root + sub-agents).

Usage:
    # Full trajectory summary
    python scripts/query_trajectory.py --session <session-id>

    # Just token usage
    python scripts/query_trajectory.py --session <session-id> --tokens-only

    # Filter by agent
    python scripts/query_trajectory.py --session <session-id> --agent scanner_0

    # Save full trajectory to file
    python scripts/query_trajectory.py --session <session-id> --output trajectory.json

    # Custom ADK server
    python scripts/query_trajectory.py --session <session-id> --host localhost --port 8000

Examples:
    python scripts/query_trajectory.py --session c7e4ceb4-6d66-4c62-9457-155a7f8ec1f4
    python scripts/query_trajectory.py --session c7e4ceb4-6d66-4c62-9457-155a7f8ec1f4 --tokens-only
    python scripts/query_trajectory.py --session c7e4ceb4-6d66-4c62-9457-155a7f8ec1f4 --agent analyzer_0
"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.request import urlopen
from urllib.error import URLError


def fetch_session(host: str, port: int, app: str, user: str, session_id: str) -> dict:
    """Fetch session data from the ADK web server REST API."""
    url = f"http://{host}:{port}/apps/{app}/users/{user}/sessions/{session_id}"
    try:
        with urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except URLError as e:
        print(f"Error: cannot reach ADK server at {url}: {e}", file=sys.stderr)
        sys.exit(1)


def print_token_summary(data: dict) -> None:
    """Print per-agent token usage from session state."""
    tu = data.get("state", {}).get("token_usage", {})
    if not tu:
        print("No token usage data in session state.")
        return

    print("=" * 70)
    print("TOKEN USAGE")
    print("=" * 70)
    print(f"Model calls: {tu.get('model_calls', 0)}")
    print(f"Total tokens: {tu.get('total', 0):,}")
    print()
    print(f"{'Agent':35s} {'Input':>10s} {'Output':>10s} {'Total':>10s}")
    print("-" * 70)
    for name, counts in sorted(tu.get("per_agent", {}).items()):
        inp, out = counts["input"], counts["output"]
        print(f"{name:35s} {inp:>10,} {out:>10,} {inp + out:>10,}")
    print("-" * 70)
    total_in = tu.get("total_input", 0)
    total_out = tu.get("total_output", 0)
    print(f"{'TOTAL':35s} {total_in:>10,} {total_out:>10,} {total_in + total_out:>10,}")


def parse_event(ev: dict) -> dict:
    """Parse an ADK event into a structured record."""
    author = ev.get("author", "?")
    parts = ev.get("content", {}).get("parts", [])

    record = {
        "author": author,
        "tool_calls": [],
        "tool_responses": [],
        "text": [],
        "transfers": [],
    }

    for p in parts:
        if "functionCall" in p:
            fc = p["functionCall"]
            record["tool_calls"].append({
                "name": fc["name"],
                "args": fc.get("args", {}),
            })
            if fc["name"] == "transfer_to_agent":
                target = fc.get("args", {}).get("agent_name", "?")
                record["transfers"].append(target)

        elif "functionResponse" in p:
            fr = p["functionResponse"]
            record["tool_responses"].append({
                "name": fr["name"],
                "response": fr.get("response", {}),
            })

        elif "text" in p:
            text = p["text"].strip()
            if text:
                record["text"].append(text)

    return record


def print_trajectory(data: dict, agent_filter: str | None = None) -> None:
    """Print the full event trajectory."""
    events = data.get("events", [])

    print("=" * 70)
    print("AGENT TRAJECTORY")
    print("=" * 70)
    print(f"Session: {data['id']}")
    print(f"Total events: {len(events)}")
    print()

    agents_seen = set()
    tool_call_count = 0
    transfer_count = 0

    for i, ev in enumerate(events):
        record = parse_event(ev)
        author = record["author"]
        agents_seen.add(author)

        if agent_filter and author != agent_filter:
            continue

        for tc in record["tool_calls"]:
            tool_call_count += 1
            args_str = json.dumps(tc["args"])[:100]
            print(f"  [{i:3d}] {author:25s} CALL  {tc['name']}({args_str})")

        for tr in record["tool_responses"]:
            resp_str = json.dumps(tr["response"])[:120]
            print(f"  [{i:3d}] {author:25s} RESP  {tr['name']} -> {resp_str}")

        for text in record["text"]:
            print(f"  [{i:3d}] {author:25s} TEXT  {text[:150]}")

        for target in record["transfers"]:
            transfer_count += 1

    print()
    print("-" * 70)
    print(f"Agents: {', '.join(sorted(agents_seen))}")
    print(f"Tool calls: {tool_call_count}")
    print(f"Transfers: {transfer_count}")


def extract_phases(data: dict) -> list[dict]:
    """Extract phase transitions from the trajectory."""
    events = data.get("events", [])
    phases = []

    for i, ev in enumerate(events):
        record = parse_event(ev)
        for text in record["text"]:
            if "PHASE" in text.upper() or "===" in text:
                phases.append({
                    "event": i,
                    "author": record["author"],
                    "text": text[:200],
                })

        for tc in record["tool_calls"]:
            if tc["name"] in ("create_scan_team", "create_analysis_team",
                              "create_verification_team", "start_target_app",
                              "stop_target_app"):
                phases.append({
                    "event": i,
                    "author": record["author"],
                    "text": f"TOOL: {tc['name']}",
                })

    return phases


def print_phase_summary(data: dict) -> None:
    """Print a condensed phase-by-phase summary."""
    phases = extract_phases(data)
    events = data.get("events", [])

    print("=" * 70)
    print("PHASE SUMMARY")
    print("=" * 70)

    # Count agents per type
    agents = set()
    for ev in events:
        author = ev.get("author", "")
        if author and author != "user":
            agents.add(author)

    scanners = sorted(a for a in agents if a.startswith("scanner_"))
    analyzers = sorted(a for a in agents if a.startswith("analyzer_"))
    verifiers = sorted(a for a in agents if a.startswith("verifier_"))

    print(f"Root agent: vuln_discovery_agent")
    print(f"Scanners:   {len(scanners)} ({', '.join(scanners)})")
    print(f"Analyzers:  {len(analyzers)} ({', '.join(analyzers)})")
    print(f"Verifiers:  {len(verifiers)} ({', '.join(verifiers)})")
    print(f"Total agents: {len(agents)}")
    print()

    # Count send_poc_request calls per agent
    poc_calls = {}
    for ev in events:
        record = parse_event(ev)
        for tc in record["tool_calls"]:
            if tc["name"] == "send_poc_request":
                poc_calls[record["author"]] = poc_calls.get(record["author"], 0) + 1

    if poc_calls:
        print("Live PoC requests:")
        for agent, count in sorted(poc_calls.items()):
            print(f"  {agent}: {count} requests")
        print()

    for phase in phases:
        print(f"  [{phase['event']:3d}] {phase['author']:25s} {phase['text']}")


def main():
    parser = argparse.ArgumentParser(
        description="Query agent trajectories from ADK web sessions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--session", required=True, help="Session ID to query")
    parser.add_argument("--host", default="127.0.0.1", help="ADK web server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="ADK web server port (default: 8000)")
    parser.add_argument("--app", default="vuln_agent", help="ADK app name (default: vuln_agent)")
    parser.add_argument("--user", default="user", help="User ID (default: user)")
    parser.add_argument("--tokens-only", action="store_true", help="Show only token usage")
    parser.add_argument("--phases-only", action="store_true", help="Show only phase summary")
    parser.add_argument("--agent", help="Filter events by agent name")
    parser.add_argument("--output", help="Save full session JSON to file")

    args = parser.parse_args()

    data = fetch_session(args.host, args.port, args.app, args.user, args.session)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Session saved to {args.output}")

    if args.tokens_only:
        print_token_summary(data)
        return

    if args.phases_only:
        print_phase_summary(data)
        return

    print_phase_summary(data)
    print()
    print_token_summary(data)
    print()
    print_trajectory(data, agent_filter=args.agent)


if __name__ == "__main__":
    main()
