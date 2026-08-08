#!/usr/bin/env bash

set -Eeuo pipefail

finsec_repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
finsec_check_python="${FINSEC_CHECK_PYTHON:-}"
finsec_run_synthetic=false

if [[ "${1:-}" == "--synthetic" ]]; then
  finsec_run_synthetic=true
  shift
fi
if (($# > 0)); then
  printf 'Usage: ./scripts/check.sh [--synthetic]\n' >&2
  exit 2
fi

if [[ -z "$finsec_check_python" ]]; then
  if [[ -x "$finsec_repo_root/.venv/bin/python" ]]; then
    finsec_check_python="$finsec_repo_root/.venv/bin/python"
  elif command -v python3.12 >/dev/null 2>&1; then
    finsec_check_python="python3.12"
  else
    printf 'Python 3.12+ was not found; set FINSEC_CHECK_PYTHON.\n' >&2
    exit 1
  fi
fi

cd "$finsec_repo_root"
"$finsec_check_python" -m ruff format --check .
"$finsec_check_python" -m ruff check .
"$finsec_check_python" -m mypy finsec
"$finsec_check_python" -m pytest
"$finsec_check_python" scripts/check_workflow_quality_gates.py
"$finsec_check_python" scripts/check_realistic_corpus_quality_gates.py
"$finsec_check_python" -m finsec.cli --help >/dev/null
bash -n install.sh scripts/*.sh

if [[ "$finsec_run_synthetic" == true ]]; then
  finsec_hunt_bin="$(dirname -- "$finsec_check_python")/hunt"
  if [[ ! -x "$finsec_hunt_bin" ]]; then
    printf 'Synthetic validation requires hunt beside the selected Python interpreter.\n' >&2
    exit 1
  fi
  PYTHON_BIN="$finsec_check_python" HUNT_BIN="$finsec_hunt_bin" \
    ./scripts/run_synthetic_validation.sh
fi
