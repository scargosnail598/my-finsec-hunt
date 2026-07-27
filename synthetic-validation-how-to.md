# Synthetic Validation How-To

The SyntheticPay harness exercises FinSec Hunt end to end using deterministic fake traffic. It is
offline, creates isolated workspaces under `/tmp`, and never executes a security test.

## Prerequisites

```bash
./install.sh --dev
source .venv/bin/activate
```

## Standard Validation

Run all repository checks:

```bash
./scripts/check.sh
```

Include the full isolated validation:

```bash
./scripts/check.sh --synthetic
```

The second command runs formatting, lint, strict typing, tests, CLI and shell smoke checks, then
invokes `scripts/run_synthetic_validation.sh` with the selected virtual environment.

You can also run the harness directly:

```bash
./scripts/run_synthetic_validation.sh
```

When calling it directly, activate the environment first or choose explicit executables:

```bash
PYTHON_BIN=/path/to/python3.12 \
HUNT_BIN=/path/to/hunt \
./scripts/run_synthetic_validation.sh
```

## What It Verifies

The runner:

1. Guards and recreates only `/tmp/finsec-synthetic-validation`.
2. Records checksums for tracked files under the repository's real `workspaces/` directory.
3. Generates ten deterministic SyntheticPay HAR files.
4. Builds two isolated workspaces and imports actor/channel-labeled traffic.
5. Runs classification, inventory, modeling, invariants, hypotheses, planning, explainability, and
   status commands.
6. Verifies deterministic semantic snapshots across both runs.
7. Verifies redaction, noise suppression, evidence gates, stable IDs, and edit preservation.
8. Confirms that the real workspace checksums are unchanged.
9. Writes a Markdown validation report and exits non-zero on any failed assertion.

## Inspect Results

Primary workspace:

```text
/tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay
```

Validation report:

```text
/tmp/finsec-synthetic-validation/results/VALIDATION_REPORT.md
```

Useful follow-up commands:

```bash
hunt status -w /tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay
hunt classify -w /tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay
hunt noise -w /tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay
hunt hypotheses -w /tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay
hunt hypotheses --research-tasks \
  -w /tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay
hunt hypotheses --include-suppressed \
  -w /tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay
```

Command output, snapshots, checksums, and endpoint explanations are in the same `results/`
directory.

## Run Components Separately

Generate only the synthetic HAR fixtures:

```bash
python scripts/generate_synthetic_fintech_hars.py /tmp/synthetic-hars
```

Inspect validator helper commands:

```bash
python scripts/validate_synthetic_workspace.py --help
```

The final `validate` subcommand expects the complete two-run directory layout, so normal use should
go through the full shell runner.

For a smaller, non-destructive demo that never recreates a fixed directory:

```bash
python scripts/run_demo_workflow.py
```

## CI

`.github/workflows/ci.yml` runs the standard checks and verifies wheel packaging on pushes and pull
requests. `.github/workflows/synthetic-validation.yml` runs weekly and on manual dispatch, then
uploads `/tmp/finsec-synthetic-validation/results` as an artifact. Both workflows use read-only
repository permissions.

## Troubleshooting

- `FinSec Hunt CLI not found`: activate `.venv` or set `HUNT_BIN` explicitly.
- `Python 3.12+ was not found`: set `FINSEC_CHECK_PYTHON` for `scripts/check.sh`, or `PYTHON_BIN`
  for the direct synthetic runner.
- Validation failure: inspect `results/VALIDATION_REPORT.md` and the matching `results/*.txt` file.
- Stale synthetic output: rerun the complete harness; it recreates only its fixed guarded `/tmp`
  directory.

To remove the generated synthetic data manually, target exactly:

```bash
rm -rf /tmp/finsec-synthetic-validation
```

Never substitute a real workspace path into that cleanup command.
