# FinSec Hunt Quick Install

FinSec Hunt requires Python 3.12 or newer. It runs locally and needs no database, browser, LLM
provider, or external service.

## Linux And macOS

Install the CLI and development tools:

```bash
./install.sh --dev
source .venv/bin/activate
```

Runtime-only install:

```bash
./install.sh
source .venv/bin/activate
```

Installer options:

```text
--dev             install pytest, Ruff, mypy, and type stubs
--python COMMAND  choose a Python 3.12+ interpreter
--venv PATH       choose the virtual-environment directory
--offline         use only packages already installed/available locally
```

Examples:

```bash
./install.sh --python python3.12 --venv .venv-dev --dev
./install.sh --offline
./install.sh --help
```

Offline mode is intended for a previously prepared virtual environment. It disables index access
and requires setuptools 69+ plus the project dependencies to already be available.

## Manual Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Windows PowerShell

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Verify

```bash
hunt --help
python -c "import finsec; print(finsec.__version__)"
./scripts/check.sh
```

## First Run

For a safe synthetic demonstration:

```bash
python scripts/run_demo_workflow.py
```

For a real authorized target:

```bash
hunt setup
```

The demo creates a unique temporary workspace and never overwrites an existing one. The setup
wizard creates explicit scope, researcher-owned account labels, capture directories, and a
`workflow.yaml` manifest without collecting credentials. The manifest normally starts with
`captures: []`; after exporting a HAR, place it in `captures/<slug>/incoming/` and explicitly assign
its actor and channel before running `hunt workflow`. See `how-to-use.md` for the complete first-run
sequence.

## Troubleshooting

### Python version error

```bash
python --version
./install.sh --python /path/to/python3.12 --dev
```

### `hunt` not found

Activate the environment and reinstall:

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

### Build dependency download failure

If compatible build tools are already installed locally:

```bash
python -m pip install -e ".[dev]" --no-build-isolation
```

### Multiple workspaces found

Pass the target explicitly:

```bash
hunt status --workspace workspaces/example-fintech
```

Installation does not enable active testing. The bounded request runner is disabled by default,
requires an explicitly enabled target policy and checksum-bound human approval, and supports only
sequential read-only comparisons. FinSec Hunt contains no browser
automation, denial-of-service tooling, or credential attack functionality.
