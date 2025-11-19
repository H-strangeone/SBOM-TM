#!/usr/bin/env bash
set -euo pipefail

IN_ACTION="${GITHUB_ACTIONS:-false}"

# If running inside GitHub Actions
if [[ "$IN_ACTION" == "true" && -n "${INPUT_MODE:-}" ]]; then

  # Avoid GitHub “dubious ownership” errors
  git config --global --add safe.directory "$GITHUB_WORKSPACE" || true
  git config --global --add safe.directory /github/workspace || true

  MODE="${INPUT_MODE:-auto}"
  BASE="${INPUT_BASE:-}"
  PROJECT="${INPUT_PROJECT:-default}"
  OFFLINE="${INPUT_OFFLINE:-false}"
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
    scan)  run_scan ;;
    diff)  run_diff ;;
    auto)
      if [ "$EVENT_NAME" = "pull_request" ]; then
        run_diff
      else
        run_scan
      fi
      ;;
    *)
      echo "::error::Unknown mode '$MODE' (expected auto|scan|diff)"
      exit 1
      ;;
  esac

  # Locate report
  REPORT_SRC=""
  PY_REPORT_DIR=$(python - <<'PY'
from sbom_tm.config import get_settings
print(str(get_settings().cache_dir / 'reports'))
PY
  )

  if [ -n "$PY_REPORT_DIR" ]; then
    if [ -f "$PY_REPORT_DIR/${PROJECT}_sbom_diff.md" ]; then
      REPORT_SRC="$PY_REPORT_DIR/${PROJECT}_sbom_diff.md"
    else
      REPORT_SRC=$(find "$PY_REPORT_DIR" -maxdepth 1 -name '*_sbom_diff.md' | head -n1 || true)
    fi
  fi

  if [ -z "$REPORT_SRC" ]; then
    REPORT_SRC=$(find "$HOME/.cache/sbom-tm/reports" -maxdepth 1 -name '*_sbom_diff.md' | head -n1 || true)
  fi

  if [[ -n "$REPORT_SRC" && -f "$REPORT_SRC" ]]; then
    cp "$REPORT_SRC" "$WORKSPACE/$REPORT_PATH"
    echo "report_path=$REPORT_PATH" >> "$GITHUB_OUTPUT"
  fi

  exit "$EXIT_CODE"

else
  echo "[entrypoint] local mode: sbom-tm $*"
  exec sbom-tm "$@"
fi
