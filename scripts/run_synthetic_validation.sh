#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATION_ROOT="/tmp/finsec-synthetic-validation"
HAR_ROOT="$VALIDATION_ROOT/synthetic-hars"
RESULTS_ROOT="$VALIDATION_ROOT/results"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
HUNT_BIN="${HUNT_BIN:-hunt}"

if [[ "$VALIDATION_ROOT" != "/tmp/finsec-synthetic-validation" ]]; then
  echo "Refusing to clean unexpected validation path: $VALIDATION_ROOT" >&2
  exit 1
fi
if ! command -v "$HUNT_BIN" >/dev/null 2>&1; then
  echo "FinSec Hunt CLI not found: $HUNT_BIN" >&2
  echo "Activate a Python 3.12 development environment first." >&2
  exit 1
fi

echo "Synthetic validation root: $VALIDATION_ROOT"
rm -rf "$VALIDATION_ROOT"
mkdir -p "$HAR_ROOT" "$RESULTS_ROOT"
cd "$REPO_ROOT"

find workspaces -type f -print0 | sort -z | xargs -0 sha256sum \
  > "$RESULTS_ROOT/real-workspaces-before.sha256"

"$PYTHON_BIN" scripts/generate_synthetic_fintech_hars.py "$HAR_ROOT" \
  > "$RESULTS_ROOT/generated-hars.txt"

capture() {
  local output="$1"
  shift
  "$@" | tee "$RESULTS_ROOT/$output"
}

ingest_all() {
  local workspace="$1"
  "$HUNT_BIN" ingest "$HAR_ROOT/01-account-a-private-resources.har" -w "$workspace" --actor ACCOUNT_A --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/02-account-b-private-resources.har" -w "$workspace" --actor ACCOUNT_B --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/03-body-identifier-wallet.har" -w "$workspace" --actor ACCOUNT_A --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/04-state-transitions.har" -w "$workspace" --actor ACCOUNT_A --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/05-auth-code-replay.har" -w "$workspace" --actor ANONYMOUS --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/06-static-and-versioned-assets.har" -w "$workspace" --actor ANONYMOUS --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/07-telemetry-and-third-party.har" -w "$workspace" --actor ANONYMOUS --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/08-post-read-endpoints.har" -w "$workspace" --actor ACCOUNT_A --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/09-duplicate-route-instances.har" -w "$workspace" --actor ACCOUNT_A --channel WEB
  "$HUNT_BIN" ingest "$HAR_ROOT/10-incomplete-evidence.har" -w "$workspace" --actor ACCOUNT_A --channel WEB
}

build_run() {
  local run_name="$1"
  local run_root="$VALIDATION_ROOT/$run_name"
  local workspace="$run_root/workspaces/syntheticpay"
  mkdir -p "$run_root"
  "$HUNT_BIN" init syntheticpay --workspace-root "$run_root/workspaces"
  "$PYTHON_BIN" scripts/validate_synthetic_workspace.py configure "$workspace"
  ingest_all "$workspace" > "$RESULTS_ROOT/$run_name-ingest.txt"
  capture "$run_name-classify.txt" "$HUNT_BIN" classify -w "$workspace"
  capture "$run_name-inventory.txt" "$HUNT_BIN" inventory -w "$workspace"
  capture "$run_name-model.txt" "$HUNT_BIN" model -w "$workspace"
  "$PYTHON_BIN" scripts/validate_synthetic_workspace.py annotate "$workspace"
  capture "$run_name-invariants.txt" "$HUNT_BIN" invariants -w "$workspace"
  capture "$run_name-hypotheses.txt" "$HUNT_BIN" hypotheses -w "$workspace"
  capture "$run_name-status.txt" "$HUNT_BIN" status -w "$workspace"
  "$PYTHON_BIN" scripts/validate_synthetic_workspace.py snapshot \
    "$workspace" "$RESULTS_ROOT/$run_name-snapshot.json"
}

build_run run-1
build_run run-2

RUN1_WORKSPACE="$VALIDATION_ROOT/run-1/workspaces/syntheticpay"
PRESERVE_ID="$("$PYTHON_BIN" scripts/validate_synthetic_workspace.py prepare-preservation "$RUN1_WORKSPACE")"
capture "run-1-plan.txt" "$HUNT_BIN" plan "$PRESERVE_ID" -w "$RUN1_WORKSPACE"
capture "run-1-regenerated-inventory.txt" "$HUNT_BIN" inventory -w "$RUN1_WORKSPACE"
capture "run-1-regenerated-model.txt" "$HUNT_BIN" model -w "$RUN1_WORKSPACE"
capture "run-1-regenerated-invariants.txt" "$HUNT_BIN" invariants -w "$RUN1_WORKSPACE"
capture "run-1-regenerated-hypotheses.txt" "$HUNT_BIN" hypotheses -w "$RUN1_WORKSPACE"

explain_endpoint() {
  local label="$1"
  local method="$2"
  local path="$3"
  local endpoint_id
  endpoint_id="$("$PYTHON_BIN" scripts/validate_synthetic_workspace.py endpoint-id "$RUN1_WORKSPACE" "$method" "$path")"
  capture "explain-$label.txt" "$HUNT_BIN" explain "$endpoint_id" -w "$RUN1_WORKSPACE"
}

explain_endpoint payment GET '/api/v2/payments/{paymentId}'
explain_endpoint wallet POST '/api/v2/wallet/payment-history'
explain_endpoint auth-code POST '/api/v2/auth/code/consume'
explain_endpoint static GET '/web/v3/loader_v3.12.3.js'
explain_endpoint telemetry POST '/api/5/envelope/'
explain_endpoint read-post POST '/api/v2/search'

capture "final-status.txt" "$HUNT_BIN" status -w "$RUN1_WORKSPACE"
capture "active-hypotheses.txt" "$HUNT_BIN" hypotheses -w "$RUN1_WORKSPACE"
capture "research-tasks.txt" "$HUNT_BIN" hypotheses --research-tasks -w "$RUN1_WORKSPACE"
capture "suppressed-candidates.txt" "$HUNT_BIN" hypotheses --include-suppressed -w "$RUN1_WORKSPACE"
capture "grouped-hypotheses.txt" "$HUNT_BIN" hypotheses --grouped -w "$RUN1_WORKSPACE"
capture "noise.txt" "$HUNT_BIN" noise -w "$RUN1_WORKSPACE"

find workspaces -type f -print0 | sort -z | xargs -0 sha256sum \
  > "$RESULTS_ROOT/real-workspaces-after.sha256"

"$PYTHON_BIN" scripts/validate_synthetic_workspace.py validate "$VALIDATION_ROOT"

echo
echo "Synthetic validation passed."
echo "Workspace: $RUN1_WORKSPACE"
echo "Report: $RESULTS_ROOT/VALIDATION_REPORT.md"
