# Target Applications

This directory holds deliberately vulnerable Flask applications used as
audit targets for the discovery agent. The bundled `vulnerable_flask_app`
contains seven exploitable vulnerabilities and ten false-positive
controls — functions that exhibit syntactic patterns associated with
vulnerabilities but are not exploitable.

## vulnerable_flask_app

| File         | Purpose                                                          |
| ------------ | ---------------------------------------------------------------- |
| `app.py`     | Flask entry point. Holds the SSTI sink and the hardcoded secret. |
| `auth.py`    | Login and profile endpoints. Contains the IDOR.                  |
| `db.py`      | SQLite layer. Contains the SQL injection alongside a safe query. |
| `upload.py`  | Up/download endpoints. Contains the path-traversal sink.         |
| `utils.py`   | Miscellaneous endpoints. Contains command injection and SSRF.    |

See `eval/ground_truth.json` for the labelled set of expected findings
and false-positive controls.

> These applications are intentionally vulnerable. Do not deploy them.
