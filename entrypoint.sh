#!/usr/bin/env bash
set -euo pipefail

# Inputs from action.yml (GitHub maps inputs → env: INPUT_<UPPERCASE_NAME>)
MODE="${INPUT_MODE:-auto}"                 # auto | scan | diff
BASE="${INPUT_BASE:-}"                     # base ref for diff (optional)
PROJECT="${INPUT_PROJECT:-default}"        # used in report filenames
OFFLINE="${INPUT_OFFLINE:-false}"          # true → --offline
REPORT_PATH="${INPUT_REPORT_PATH:-sbom-tm-report.md}"

WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
EVENT_NAME="${GITHUB_EVENT_NAME:-}"

cd "$WORKSPACE"

echo "[sbom-tm-action] mode=$MODE event=$EVENT_NAME base=$BASE project=$PROJECT"

OFFLINE_FLAG=()
if [ "$OFFLINE" = "true" ]; then
  OFFLINE_FLAG+=(--offline)
fi

EXIT_CODE=0

run_scan() {
  echo "[sbom-tm-action] running: sbom-tm scan . --project \"$PROJECT\" ${OFFLINE_FLAG[*]}"
  sbom-tm scan . --project "$PROJECT" "${OFFLINE_FLAG[@]}" || EXIT_CODE=$?
}

run_diff() {
  local cmd=(sbom-tm diff --git --project "$PROJECT" "${OFFLINE_FLAG[@]}")
  if [ -n "$BASE" ]; then
    cmd+=(--base "$BASE")
  fi
  echo "[sbom-tm-action] running: ${cmd[*]}"
  "${cmd[@]}" || EXIT_CODE=$?
}

case "$MODE" in
  scan)
    run_scan
    ;;
  diff)
    run_diff
    ;;
  auto)
    if [ "$EVENT_NAME" = "pull_request" ]; then
      # On PRs: compare HEAD vs base commit
      run_diff
    else
      # On pushes: just scan the tree
      run_scan
    fi
    ;;
  *)
    echo "::error::Unknown mode '$MODE' (expected auto|scan|diff)"
    exit 1
    ;;
esac

# Try to locate Markdown diff report produced by sbom-tm (for PR comment)
REPORT_SRC=""

# First: ask the Python package where it writes cache/reports (most reliable)
PY_REPORT_DIR=$(python - <<'PY'
from sbom_tm.config import get_settings
print(str(get_settings().cache_dir / 'reports'))
PY
)
if [ -n "$PY_REPORT_DIR" ]; then
  if [ -f "$PY_REPORT_DIR/${PROJECT}_sbom_diff.md" ]; then
    REPORT_SRC="$PY_REPORT_DIR/${PROJECT}_sbom_diff.md"
  elif [ -d "$PY_REPORT_DIR" ]; then
    REPORT_SRC="$(find "$PY_REPORT_DIR" -maxdepth 1 -name '*_sbom_diff.md' | head -n1 || true)"
  fi
fi

# Fallback: check legacy location under $HOME/.cache/sbom-tm/reports
if [ -z "$REPORT_SRC" ]; then
  if [ -f "$HOME/.cache/sbom-tm/reports/${PROJECT}_sbom_diff.md" ]; then
    REPORT_SRC="$HOME/.cache/sbom-tm/reports/${PROJECT}_sbom_diff.md"
  elif [ -d "$HOME/.cache/sbom-tm/reports" ]; then
    REPORT_SRC="$(find "$HOME/.cache/sbom-tm/reports" -maxdepth 1 -name '*_sbom_diff.md' | head -n1 || true)"
  fi
fi

if [ -n "$REPORT_SRC" ] && [ -f "$REPORT_SRC" ]; then
  cp "$REPORT_SRC" "$WORKSPACE/$REPORT_PATH"
  echo "[sbom-tm-action] copied markdown report to $WORKSPACE/$REPORT_PATH"
  # expose to other steps as output
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "report_path=$REPORT_PATH" >> "$GITHUB_OUTPUT"
  fi
else
  echo "[sbom-tm-action] no markdown diff report found (this is OK if scan mode only)."
fi

exit "$EXIT_CODE"
