# Target Applications

This directory holds deliberately vulnerable Flask applications used as
audit targets for the discovery agent. The bundled `vulnerable_flask_app`
contains seven real vulnerabilities and four false-positive traps that
look dangerous but are actually safe.

## vulnerable_flask_app

| File         | Purpose                                                   |
| ------------ | --------------------------------------------------------- |
| `app.py`     | Flask entry point. Holds the SSTI sink and hardcoded secret. |
| `auth.py`    | Login + profile endpoints. Contains the IDOR.             |
| `db.py`      | SQLite layer. Contains the SQLi alongside a safe query.   |
| `upload.py`  | Up/download endpoints. Contains the path traversal sink.  |
| `utils.py`   | Misc endpoints. Contains command injection and SSRF.      |

See `eval/ground_truth.json` for the labelled set of expected findings
and traps.

> Do not deploy these apps. They are intentionally broken.
