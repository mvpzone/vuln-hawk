# vuln-discovery-agent

An LLM-based vulnerability discovery agent built with [Google's Agent
Development Kit (ADK)](https://google.github.io/adk-docs/).

## Research goals

This project investigates whether a general-purpose LLM, given only
shell-like primitives and a disciplined audit methodology, can locate
exploitable vulnerabilities in Python web applications with useful
precision. The agent is deliberately denied high-level static
analyzers (Bandit, Semgrep, CodeQL): it has file reads, regex search,
AST introspection, directory listing, and a sandboxed Python
interpreter, and must reason about data flows itself.

Four design choices anchor the experiment:

1. **Shell-only tools.** Higher-level analyzers tend to anchor the
   agent on canned tool outputs and collapse its strategy space toward
   false positives. Restricting the tool surface to low-level
   primitives forces the model to compose its own detection approach.
2. **Systematic data-flow reasoning.** The system prompt enforces a
   trace-from-source-to-sink methodology that is intended to transfer
   across vulnerability classes (injection, traversal, template
   injection, broken access control, server-side request forgery).
3. **Restricted context with summarisation pivots.** A separate
   experiment (`eval/compaction_experiment.py`) periodically asks the
   agent to summarise its own trajectory and restarts the session with
   only that summary, modelling a bounded context regime.
4. **Precision over recall.** The system prompt instructs the agent to
   drop any finding it cannot fully justify by tracing the data flow.
   We treat false positives as a more expensive error than misses.

## Architecture

```
              vuln-discovery-agent
              ====================

  user request --> Agent (Gemini 2.5 Flash)
                       |
                       v
                +------ system prompt: five-phase audit methodology -----+
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
│   ├── compaction_experiment.py  # A/B comparison of trajectory compaction
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

**Interactive UI** (step through the agent's tool calls):

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

Ten functions across the same files exhibit syntactic patterns
associated with vulnerabilities but are not exploitable: parameterized
queries, `secure_filename`-sanitised paths, hardcoded subprocess
arguments, session-derived user IDs, `render_template_string` invoked
with Jinja2 context variables, and similar. They exist to measure
whether the agent traces data flows to the source or falls back to
syntactic pattern matching on sink names. See `eval/ground_truth.json`
for the full list.

## Results

To be filled in after running the evaluation. Run
`python eval/run_eval.py` and record the scorecard here.

```
True positives:  ?
False positives: ?
False negatives: ?
Precision:       ?
Recall:          ?
F1:              ?
Traps triggered: ?
```

## Open questions

The evaluation harness is designed to answer the following:

- Per-class detection rate: does the agent perform comparably across
  straightforward sinks (SQL injection, command injection) and
  semantically subtle classes (IDOR, server-side template injection)?
- False-positive trap rate: which trap functions, if any, does the
  agent misclassify, and what reasoning pattern produced the error?
- Effect of trajectory compaction: does periodic self-summarisation
  improve, preserve, or degrade precision and recall relative to an
  uncompacted baseline?
- Tool-call efficiency: how does the number of tool invocations
  correlate with final audit quality?
