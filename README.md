# vuln-discovery-agent

A minimal vulnerability discovery agent built with [Google's Agent
Development Kit (ADK)](https://google.github.io/adk-docs/), inspired by
[depthfirst](https://depthfirst.com)'s `dfs-mini1` research model.

## What this is

A weekend project that audits Python web applications for exploitable
vulnerabilities using only shell-like primitives. The agent doesn't get
Bandit, Semgrep, or CodeQL — it gets file reads, regex search, AST
introspection, and a sandboxed Python interpreter, and it has to reason
about data flows itself.

The design mirrors four things `dfs-mini1` does:

1. **Shell-only tools.** No high-level analyzers. Higher-level analyzers
   cause the agent to tunnel-vision on false positives and collapse the
   strategy space, so we deny them on purpose.
2. **Systematic data-flow reasoning.** The system prompt forces a
   trace-from-source-to-sink methodology that transfers across vuln
   classes.
3. **Restricted context with summarisation pivots.** A stretch-goal
   experiment (`eval/compaction_experiment.py`) periodically asks the
   agent to summarise its trajectory and restarts the session with only
   that summary — a simplified version of `dfs-mini1`'s 32k-context
   compaction loop.
4. **Precision over recall.** The system prompt explicitly tells the
   agent to drop findings it can't fully justify by tracing the data
   flow. Better to miss a bug than to cry wolf.

## Architecture

```
              vuln-discovery-agent
              ====================

  user request --> Agent (Gemini 2.5 Flash)
                       |
                       v
                +------ system prompt: dfs-mini1 audit methodology ------+
                | reconnaissance -> attack surface -> data flow -> ...   |
                +------------------------------------------------+-------+
                                                                 |
                                                                 v
                                                         choose a tool
                                                                 |
       +---------------------+---------------------+-------------+--------------+
       |                     |                     |                            |
  read_file        search_code (grep)     list_directory      analyze_python_ast / run_python_snippet
       |                     |                     |                            |
       +---------------------+---------------------+----------------------------+
                                       |
                                       v
                              tool result -> agent
                                       |
                                       v
                              ... loop until report ...
                                       |
                                       v
                          ```json { findings: [...] } ```  (parsed by report.py)
                                       |
                                       v
                            eval/run_eval.py  --> precision / recall / F1
```

## Project layout

```
vuln-discovery-agent/
├── vuln_agent/
│   ├── agent.py              # ADK Agent: Gemini + 5 shell-like tools
│   ├── tools.py              # read_file, search_code, list_directory, analyze_python_ast, run_python_snippet
│   ├── prompts.py            # System instruction encoding the audit methodology
│   └── report.py             # Parser for the agent's JSON output
├── targets/
│   └── vulnerable_flask_app/ # 7 planted vulns + 10 false-positive traps
├── eval/
│   ├── ground_truth.json     # Labelled findings + traps
│   ├── run_eval.py           # End-to-end runner + precision/recall scorer
│   ├── compaction_experiment.py  # A/B compaction stretch goal
│   └── results/
├── requirements.txt
├── .env.example
└── README.md
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# put your Gemini API key into .env, then:
export $(grep -v '^#' .env | xargs)
```

You'll need a Gemini API key in the `GOOGLE_API_KEY` environment
variable. The agent defaults to `gemini-2.5-flash`; override with
`VULN_AGENT_MODEL`.

## Running the agent

**Interactive UI** (best for watching the agent reason):

```bash
adk web
# select "vuln_discovery_agent" in the UI and send:
#   Audit the target codebase for vulnerabilities.
```

**Evaluation harness** (precision/recall scoring):

```bash
python eval/run_eval.py
```

This runs the agent end-to-end against `targets/vulnerable_flask_app`,
parses its structured JSON report, and scores it against
`eval/ground_truth.json`. Results land in `eval/results/`.

**Score a previously saved report** (no API calls):

```bash
python eval/run_eval.py --no-run --report-file eval/results/report-<timestamp>.txt
```

**Compaction experiment**:

```bash
python eval/compaction_experiment.py --every 10
```

Runs the agent twice — once normally, once with a forced summarisation
pivot after every 10 tool calls — and prints both scorecards.

## Target app: planted vulnerabilities

| ID       | Class             | File         | What's wrong                                                          |
| -------- | ----------------- | ------------ | --------------------------------------------------------------------- |
| VULN-001 | SQL Injection     | `db.py`      | f-string interpolation into `cursor.execute`                          |
| VULN-002 | Command Injection | `utils.py`   | user filename interpolated into `subprocess.run(..., shell=True)`     |
| VULN-003 | Path Traversal    | `upload.py`  | `os.path.join(UPLOAD_DIR, request.args["filename"])` without sanitisation |
| VULN-004 | SSTI              | `app.py`     | `render_template_string(f"...{user_message}...")`                     |
| VULN-005 | IDOR              | `auth.py`    | `login_required` checks session, not resource ownership               |
| VULN-006 | Hardcoded Secret  | `app.py`     | `app.secret_key` and an API key embedded in source                    |
| VULN-007 | SSRF              | `utils.py`   | `requests.get(user_url)` with no allowlist                            |

## False-positive traps

Ten functions across the same files look like they should be vulnerable
but aren't — parameterized queries, `secure_filename`, hardcoded
arguments, session-derived user IDs, `render_template_string` with
Jinja2 context variables, etc. They exist to test whether the agent
actually traces data flows or just pattern-matches on scary function
names. See `eval/ground_truth.json` for the full list.

## Results

To be filled in after running evals. Run `python eval/run_eval.py` and
paste the table here.

```
True positives:  ?
False positives: ?
False negatives: ?
Precision:       ?
Recall:          ?
F1:              ?
Traps triggered: ?
```

## Lessons learned

To be filled in after experiments.

- How did the agent fare on the obvious vulns (SQLi, command injection) vs. the subtle ones (IDOR, SSTI)?
- Did the agent fall for any false-positive traps? Which ones?
- Did compaction help or hurt precision/recall?
- How did tool-call budget correlate with audit quality?
