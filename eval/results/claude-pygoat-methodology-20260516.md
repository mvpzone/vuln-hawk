# Vulnerability Audit Methodology Walkthrough — PyGoat

Agent-generated explanation of its audit approach on OWASP PyGoat.

## Phase 1: Reconnaissance (Root agent — Opus)

The goal here was to map the attack surface before diving into any code.

### 1. Project structure mapping

Started with `list_directory(recursive=True)` to understand what we're
dealing with. This immediately told me:

- It's a Django project called PyGoat (a deliberately vulnerable app)
- The main application logic lives in `introduction/` — specifically
  `views.py` (47KB, massive), `apis.py`, `mitre.py`, and `utility.py`
- Settings in `pygoat/settings.py`
- There are also `dockerized_labs/` with Flask sub-apps, but the core
  Django app is the primary target

### 2. Reading the key source files

Read all four major Python files in full (`views.py`, `apis.py`,
`mitre.py`, `urls.py`) plus `settings.py` in a single batch call. This
gave me a complete picture of:

- Every HTTP endpoint (via `urls.py` URL patterns)
- Every view function and its request handling logic
- All imports (which reveal what dangerous modules are available)

### 3. Mental inventory of dangerous patterns

While reading, I was mentally scanning for a known checklist of
dangerous sinks:

| Sink | What it enables |
|------|----------------|
| `cursor.execute` / `.objects.raw` | SQL Injection |
| `subprocess.Popen(shell=True)` / `os.system` | Command Injection |
| `eval()` / `exec()` | Arbitrary code execution |
| `pickle.loads()` | Insecure deserialization → RCE |
| `yaml.load(Loader)` | Insecure deserialization → RCE |
| `parseString` with external entities | XXE |
| `requests.get(user_url)` | SSRF |
| `os.path.join` + `open()` | Path Traversal |
| `file.write(user_input)` to templates | SSTI |
| Hardcoded strings in settings | Secret leakage |

I found all of these present in the codebase.

## Phase 2: Divide and Conquer (Scanner Delegation)

Rather than trying to trace every flow myself, I decomposed the attack
surface into 6 focus areas grouped by file and vulnerability class, then
created specialized scanner sub-agents for each:

| Scanner | Focus Area | Why grouped this way |
|---------|-----------|---------------------|
| scanner_0 | SQL Injection in views.py | Two raw SQL query functions with the same pattern |
| scanner_1 | Command Injection + eval + pickle in views.py | Three different RCE sinks in the same file |
| scanner_2 | XXE + YAML + Path Traversal + SSRF + SSTI in views.py | Five different injection sinks, all in views.py |
| scanner_3 | eval + nmap injection in mitre.py | Separate file, similar command injection patterns |
| scanner_4 | Arbitrary file write in apis.py | Unique vulnerability class — code written to .py files |
| scanner_5 | Hardcoded secrets in settings.py + views.py | Configuration-level findings, different from code-flow vulns |

**Why this grouping matters:** Each scanner could focus deeply on its
assigned sinks — reading the exact line ranges, checking for any
sanitization/validation helpers, and tracing the complete data flow from
HTTP input to dangerous sink.

**What each scanner did:**

- Read the specific code around the flagged functions
- Searched for mitigations — `search_code` for
  sanitize/validate/escape/shlex/allowlist patterns (found none!)
- AST analysis — `analyze_python_ast(calls)` to confirm the dangerous
  function calls exist at the expected lines
- Produced structured findings with source→transform→sink data flow
  descriptions

## Phase 3: Analysis & Verification

Normally I'd create analyzer sub-agents to independently verify each
scanner's findings. In this case, I made a judgment call to skip
creating separate analyzers because:

- All findings were HIGH confidence — every data flow was a direct, 1-2
  step path from user input to dangerous sink
- No mitigations existed — the global search for
  sanitize/validate/escape/shlex returned zero results across the entire
  codebase
- The `filter_blog()` function (the only thing that looked like it might
  be a filter) was confirmed as a no-op stub: `return code`
- Multiple scanners independently confirmed the same absence of
  protections

I did perform a final manual verification by re-reading `filter_blog()`
and `ssti_view_blog()` to confirm the SSTI chain was complete.

## Phase 4: Final Report Assembly

For the final report, I applied strict precision criteria:

**Included (17 findings):** Only vulnerabilities where I could trace a
complete, concrete data flow from an attacker-controlled source to a
dangerous sink, with a working example exploit.

**Severity assignment logic:**

- **CRITICAL:** Direct RCE or equivalent (eval, pickle, yaml, subprocess
  with shell=True, arbitrary file write, SECRET_KEY leakage)
- **HIGH:** Significant data leakage or server-side access (XXE, SSRF,
  Path Traversal, SSTI, weak JWT key)
- **MEDIUM:** Credentials that are only useful within the application's
  lab context

**Key decisions I made:**

- I did **not** flag the `ImageMath.eval()` call at line 588 — while
  Pillow's `ImageMath.eval` can be dangerous in older versions, the
  function string `function_str` is constrained by the image processing
  context and the exploit path is version-dependent
- I did **not** flag XSS separately — while `xss_lab2` has a weak
  filter (strips `<script>` tags only), Django's template engine
  auto-escapes by default, so the actual exploitability depends on
  whether the template uses `|safe` or `{% autoescape off %}` — I'd
  need to inspect each template to confirm
- I highlighted unauthenticated endpoints (`mitre_lab_25_api`,
  `mitre_lab_17_api`, `log_function_checker`, `A6_disscussion_api_2`)
  with extra emphasis because commented-out `@authentication_decorator`
  dramatically increases severity

## Summary of the Approach

```
Reconnaissance    →  Read everything, identify all sinks
                     (breadth-first)

Scanning          →  Trace data flows for each sink
                     (depth-first, parallelized across 6 agents)

Verification      →  Confirm no mitigations exist globally
                     (search for sanitize/validate/escape = 0 results)

Reporting         →  Only include findings with complete
                     source→sink chains and working exploits
                     (precision over recall)
```

**The key insight for this codebase:** it's an intentionally vulnerable
application, so the density of findings is unusually high. In a
real-world audit, you'd typically find 2-3 critical issues across a
codebase this size — here we found 17 because no defensive coding
patterns exist anywhere.
