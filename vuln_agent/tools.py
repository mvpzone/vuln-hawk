"""Shell-like tool primitives for the vulnerability discovery agent.

Deliberately low-level — file reading, regex search, AST parsing, and a
sandboxed Python interpreter. No Semgrep, no Bandit, no CodeQL. This
mirrors dfs-mini1's shell-only design: the agent must compose its own
detection strategies from primitives rather than relying on canned
analyzers that produce false positives.

All paths are resolved relative to TARGET_CODEBASE_ROOT (env var or
config), and tool results are dictionaries shaped for stable
JSON-style consumption by the ADK function-tool wrapper.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any


def _target_root() -> Path:
    """Resolve the target codebase root from env or default."""
    root = os.environ.get("TARGET_CODEBASE_ROOT")
    if root:
        return Path(root).resolve()
    # Default: the bundled vulnerable Flask app, so `adk web` works out of the box.
    default = Path(__file__).resolve().parent.parent / "targets" / "vulnerable_flask_app"
    return default.resolve()


def _safe_resolve(rel: str) -> Path | None:
    """Resolve `rel` under the target root, refusing escapes via `..`."""
    root = _target_root()
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def read_file(filepath: str, start_line: int = 1, end_line: int = -1) -> dict:
    """Read the contents of a file with line numbers. Use this to examine source code.

    Args:
        filepath: Path to the file relative to the target codebase root.
        start_line: Starting line number (1-indexed). Defaults to 1.
        end_line: Ending line number (-1 for end of file). Defaults to -1.

    Returns:
        dict with 'status', 'content' (numbered lines), 'total_lines', and 'filepath'.
    """
    resolved = _safe_resolve(filepath)
    if resolved is None:
        return {
            "status": "error",
            "error": f"Path '{filepath}' escapes the target codebase root.",
            "filepath": filepath,
        }
    if not resolved.exists() or not resolved.is_file():
        return {
            "status": "error",
            "error": f"File '{filepath}' does not exist.",
            "filepath": filepath,
        }
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"status": "error", "error": str(exc), "filepath": filepath}

    lines = text.splitlines()
    total = len(lines)
    s = max(1, start_line)
    e = total if end_line == -1 else min(total, end_line)
    if s > total:
        return {
            "status": "ok",
            "filepath": filepath,
            "total_lines": total,
            "content": "",
            "note": f"start_line {start_line} is past EOF ({total} lines).",
        }
    width = len(str(e))
    rendered = "\n".join(
        f"{str(i + s).rjust(width)} | {lines[i + s - 1]}" for i in range(e - s + 1)
    )
    return {
        "status": "ok",
        "filepath": filepath,
        "total_lines": total,
        "content": rendered,
    }


def search_code(pattern: str, file_glob: str = "*.py", case_sensitive: bool = True) -> dict:
    """Search for a pattern across all files matching the glob in the target codebase.
    Uses grep-like matching. Essential for tracing data flows and finding sinks.

    Args:
        pattern: The search pattern (supports basic regex).
        file_glob: File glob pattern to search within. Defaults to "*.py".
        case_sensitive: Whether the search is case sensitive. Defaults to True.

    Returns:
        dict with 'status', 'matches' (list of {file, line_number, content}), and 'total_matches'.
    """
    root = _target_root()
    try:
        flags = 0 if case_sensitive else re.IGNORECASE
        regex = re.compile(pattern, flags)
    except re.error as exc:
        return {"status": "error", "error": f"Invalid regex: {exc}", "matches": []}

    matches: list[dict[str, Any]] = []
    truncated = False
    cap = 50
    # rglob handles `**` implicitly when glob has no separators; otherwise use glob.
    iterable = root.rglob(file_glob) if "/" not in file_glob else root.glob(file_glob)
    for path in sorted(iterable):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                matches.append(
                    {
                        "file": str(path.relative_to(root)),
                        "line_number": lineno,
                        "content": line.rstrip(),
                    }
                )
                if len(matches) >= cap:
                    truncated = True
                    break
        if truncated:
            break

    result: dict[str, Any] = {
        "status": "ok",
        "pattern": pattern,
        "file_glob": file_glob,
        "matches": matches,
        "total_matches": len(matches),
    }
    if truncated:
        result["note"] = f"Results capped at {cap}. Refine your pattern for fewer hits."
    return result


def list_directory(path: str = ".", recursive: bool = False) -> dict:
    """List files and directories in the target codebase. Use this first to understand project structure.

    Args:
        path: Directory path relative to target codebase root. Defaults to ".".
        recursive: If True, list all files recursively. Defaults to False.

    Returns:
        dict with 'status' and 'entries' (list of {name, type, size}).
    """
    resolved = _safe_resolve(path)
    if resolved is None or not resolved.exists():
        return {"status": "error", "error": f"Directory '{path}' not found.", "entries": []}
    if not resolved.is_dir():
        return {"status": "error", "error": f"'{path}' is not a directory.", "entries": []}

    root = _target_root()
    entries: list[dict[str, Any]] = []
    walker = resolved.rglob("*") if recursive else resolved.iterdir()
    for child in sorted(walker):
        # Skip hidden files/dirs and __pycache__ to keep output tractable.
        if any(part.startswith(".") or part == "__pycache__" for part in child.relative_to(root).parts):
            continue
        try:
            size = child.stat().st_size if child.is_file() else 0
        except OSError:
            size = 0
        entries.append(
            {
                "name": str(child.relative_to(root)),
                "type": "dir" if child.is_dir() else "file",
                "size": size,
            }
        )
    return {"status": "ok", "path": path, "entries": entries}


def _collect_routes(tree: ast.AST) -> list[dict[str, Any]]:
    """Find Flask/Django route decorators and path() calls in an AST."""
    routes: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        # Flask-style: @app.route("/path", methods=["POST"])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for deco in node.decorator_list:
                call = deco if isinstance(deco, ast.Call) else None
                if call is None:
                    continue
                deco_name = ""
                if isinstance(call.func, ast.Attribute):
                    deco_name = call.func.attr
                elif isinstance(call.func, ast.Name):
                    deco_name = call.func.id
                if deco_name not in {"route", "get", "post", "put", "delete", "patch"}:
                    continue
                url = None
                if call.args and isinstance(call.args[0], ast.Constant):
                    url = call.args[0].value
                methods = ["GET"]
                for kw in call.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [
                            elt.value
                            for elt in kw.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        ]
                routes.append(
                    {
                        "url": url,
                        "methods": methods,
                        "handler": node.name,
                        "line": node.lineno,
                    }
                )
        # Django-style: path("foo", view), url(r"...", view)
        if isinstance(node, ast.Call):
            fn = ""
            if isinstance(node.func, ast.Name):
                fn = node.func.id
            elif isinstance(node.func, ast.Attribute):
                fn = node.func.attr
            if fn in {"path", "re_path", "url"} and node.args:
                url = node.args[0].value if isinstance(node.args[0], ast.Constant) else None
                handler = None
                if len(node.args) > 1:
                    arg = node.args[1]
                    if isinstance(arg, ast.Name):
                        handler = arg.id
                    elif isinstance(arg, ast.Attribute):
                        handler = arg.attr
                if url is not None:
                    routes.append(
                        {
                            "url": url,
                            "methods": ["ANY"],
                            "handler": handler,
                            "line": node.lineno,
                        }
                    )
    return routes


def analyze_python_ast(filepath: str, analysis_type: str = "functions") -> dict:
    """Parse a Python file's AST to extract structural information.

    Args:
        filepath: Path to the Python file relative to target codebase root.
        analysis_type: What to extract. One of:
            - "functions": List all function/method definitions with args and decorators
            - "imports": List all imports
            - "calls": List all function calls (useful for finding dangerous sinks)
            - "strings": List all string literals (useful for finding hardcoded secrets)
            - "routes": Extract Flask/Django route definitions and their HTTP methods

    Returns:
        dict with 'status' and analysis results.
    """
    resolved = _safe_resolve(filepath)
    if resolved is None or not resolved.exists():
        return {"status": "error", "error": f"File '{filepath}' not found."}
    try:
        source = resolved.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(resolved))
    except SyntaxError as exc:
        return {"status": "error", "error": f"Syntax error: {exc}"}

    if analysis_type == "functions":
        funcs = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorators = []
                for deco in node.decorator_list:
                    decorators.append(ast.unparse(deco))
                args = [a.arg for a in node.args.args]
                funcs.append(
                    {
                        "name": node.name,
                        "line": node.lineno,
                        "args": args,
                        "decorators": decorators,
                    }
                )
        return {"status": "ok", "analysis_type": "functions", "functions": funcs}

    if analysis_type == "imports":
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({"module": alias.name, "alias": alias.asname, "line": node.lineno})
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imports.append(
                        {
                            "module": f"{node.module or ''}.{alias.name}".lstrip("."),
                            "alias": alias.asname,
                            "line": node.lineno,
                        }
                    )
        return {"status": "ok", "analysis_type": "imports", "imports": imports}

    if analysis_type == "calls":
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = ast.unparse(node.func)
                calls.append({"call": name, "line": node.lineno})
        return {"status": "ok", "analysis_type": "calls", "calls": calls, "total": len(calls)}

    if analysis_type == "strings":
        strings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 3:
                strings.append({"value": node.value, "line": node.lineno})
        return {"status": "ok", "analysis_type": "strings", "strings": strings}

    if analysis_type == "routes":
        return {"status": "ok", "analysis_type": "routes", "routes": _collect_routes(tree)}

    return {
        "status": "error",
        "error": (
            f"Unknown analysis_type '{analysis_type}'. "
            "Use one of: functions, imports, calls, strings, routes."
        ),
    }


_SANDBOX_PREAMBLE = textwrap.dedent(
    """
    import sys, builtins
    # Pre-import allowed modules and let them pull in their own deps before
    # the import guard activates. Without this, the first call to e.g.
    # pathlib.Path(...).read_text() tries to import `_io` at runtime and
    # gets blocked.
    import ast, re, json, os, os.path, pathlib
    import collections, itertools, functools, string

    _allowed_tops = {
        'ast', 're', 'json', 'os', 'pathlib',
        'collections', 'itertools', 'functools', 'string',
    }
    _real_import = builtins.__import__

    def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        top = name.split('.')[0]
        # Allow stdlib internals (leading underscore) — these are C extensions
        # and private helpers that the allowed modules depend on.
        if top in _allowed_tops or top.startswith('_'):
            return _real_import(name, globals, locals, fromlist, level)
        raise ImportError(f"Import of '{name}' is blocked in the sandbox.")

    builtins.__import__ = _guarded_import
    """
).strip()


def run_python_snippet(code: str) -> dict:
    """Execute a short Python snippet for custom analysis. The snippet runs in a
    restricted sandbox with access to the `ast`, `re`, `json`, `os.path` modules only.
    The target codebase root is available as the variable `TARGET_ROOT`.
    Use this for custom data flow analysis the other tools can't express.

    Args:
        code: Python code to execute. Must be under 50 lines. Print output to stdout.

    Returns:
        dict with 'status', 'stdout', and 'stderr'.
    """
    line_count = code.count("\n") + 1
    if line_count > 50:
        return {
            "status": "error",
            "stdout": "",
            "stderr": f"Snippet too long ({line_count} lines). Limit is 50.",
        }
    root = _target_root()
    full = (
        _SANDBOX_PREAMBLE
        + "\n"
        + f"TARGET_ROOT = {str(root)!r}\n"
        + "\n# --- user snippet below ---\n"
        + code
    )
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(full)
            tmp_path = fh.name
        proc = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(root),
        )
        return {
            "status": "ok" if proc.returncode == 0 else "error",
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "stdout": "", "stderr": "Snippet timed out after 10s."}
    except Exception as exc:
        return {"status": "error", "stdout": "", "stderr": f"Sandbox error: {exc}"}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
