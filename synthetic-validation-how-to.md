# Synthetic Validation How-To

The SyntheticPay scripts exercise FinSec Hunt end to end using deterministic, fake HAR traffic. They run entirely offline, create temporary workspaces under `/tmp`, and never execute security tests or contact a target.

## Prerequisites

Install the project with development dependencies and activate the environment:

```bash
cd /home/saeed/bb/my-finsec-hunt
./install.sh --dev
source .venv/bin/activate
```

Confirm that the required commands are available:

```bash
python --version
hunt --help
```

Python 3.12 or newer is required.

## Run the Complete Validation

From the repository root, run:

```bash
./scripts/run_synthetic_validation.sh
```

The runner performs the following steps:

1. Recreates only `/tmp/finsec-synthetic-validation`.
2. Generates ten deterministic SyntheticPay HAR files.
3. Builds two clean workspaces and ingests traffic with actor/channel labels.
4. Runs classification, inventory, modeling, invariants, and hypotheses.
5. Checks determinism, redaction, safety gates, and edit preservation.
6. Confirms that existing repository workspaces retain identical checksums.
7. Writes a Markdown report and exits non-zero if an assertion fails.

To use explicit executables:

```bash
PYTHON_BIN=/path/to/python \
HUNT_BIN=/path/to/hunt \
./scripts/run_synthetic_validation.sh
```

## Inspect the Results

The primary workspace is:

```text
/tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay
```

Useful commands include:

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

Open the complete assertion report at:

```text
/tmp/finsec-synthetic-validation/results/VALIDATION_REPORT.md
```

Other command output, semantic snapshots, checksum files, and explainability examples are stored in the same `results/` directory.

## Run the Scripts Separately

Generate only the HAR fixtures:

```bash
python scripts/generate_synthetic_fintech_hars.py /tmp/synthetic-hars
```

The validator supports helper subcommands used by the runner:

```bash
python scripts/validate_synthetic_workspace.py --help
python scripts/validate_synthetic_workspace.py validate \
  /tmp/finsec-synthetic-validation
```

Normally, use the complete runner because validation expects both clean runs, snapshots, preservation artifacts, and checksum files to exist.

## Run Automated Tests

Run the focused integration coverage:

```bash
pytest tests/integration/test_synthetic_fintech_workspace.py
```

Run all project checks:

```bash
ruff format --check .
ruff check .
mypy finsec
pytest
```

## Troubleshooting

- `FinSec Hunt CLI not found`: activate the virtual environment or set `HUNT_BIN` explicitly.
- `python3.12: command not found`: set `PYTHON_BIN` to a Python 3.12+ executable.
- Validation failure: read `results/VALIDATION_REPORT.md` and the corresponding `results/*.txt` output.
- Stale temporary output: rerun the complete script; it safely recreates its fixed `/tmp/finsec-synthetic-validation` directory.

To remove generated validation data manually:

```bash
rm -rf /tmp/finsec-synthetic-validation
```

Do not point the runner or cleanup command at `workspaces/divar` or another real research workspace.
