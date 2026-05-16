FROM python:3.13-slim

RUN useradd -m -s /bin/false sandbox
WORKDIR /target

# Only stdlib — no pip packages in the sandbox.
# The target codebase is mounted read-only at /target at runtime.

USER sandbox
