#!/usr/bin/env bash
# Sync this fork (mvpzone/vuln-hawk) with upstream (prashantkul/vuln-hawk).
#
# Usage:
#   ./scripts/sync_upstream.sh           # rebase main onto upstream/main (default)
#   ./scripts/sync_upstream.sh --merge   # merge instead of rebase (use if local main has commits not yet on origin)
#
# Safety:
#   - Aborts if the working tree is dirty.
#   - Aborts if not on `main` (sync only the main branch; feature branches stay local).
#   - Push to upstream is disabled at the remote level (`git remote set-url --push upstream DISABLE`).
#
# Periodic discipline: run before starting work + before opening PRs against origin/main.

set -euo pipefail

MODE="rebase"
if [[ "${1:-}" == "--merge" ]]; then
  MODE="merge"
fi

# Guardrails
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Error: working tree has uncommitted changes. Commit or stash before syncing." >&2
  exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
  echo "Error: must be on 'main' branch (currently on '$CURRENT_BRANCH')." >&2
  echo "Hint: git checkout main" >&2
  exit 1
fi

# Verify upstream remote exists
if ! git remote get-url upstream >/dev/null 2>&1; then
  echo "Error: 'upstream' remote not configured." >&2
  echo "Run: git remote add upstream git@github.com:prashantkul/vuln-hawk.git" >&2
  echo "Then: git remote set-url --push upstream DISABLE" >&2
  exit 1
fi

echo "==> Fetching upstream..."
git fetch upstream

echo "==> Showing divergence (left=local, right=upstream):"
git log --oneline --left-right --boundary HEAD...upstream/main | head -20 || true

if [[ "$MODE" == "rebase" ]]; then
  echo "==> Rebasing main onto upstream/main..."
  git rebase upstream/main
else
  echo "==> Merging upstream/main into main..."
  git merge --no-edit upstream/main
fi

echo "==> Pushing to origin/main..."
git push origin main

echo "==> Done. Local main is now aligned with upstream/main and mirrored to origin."
