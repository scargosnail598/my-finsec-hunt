# FinSec Hunt Quick Install

FinSec Hunt requires Python 3.12 or newer. It runs locally and does not require a database, browser, LLM provider, or external service.

## Automatic Installation

On Linux or macOS, run:

```bash
./install.sh
source .venv/bin/activate
```

Install the development tools as well:

```bash
./install.sh --dev
source .venv/bin/activate
```

Useful options:

```bash
./install.sh --python python3.12
./install.sh --venv .venv-dev --dev
./install.sh --offline
./install.sh --help
```

`--offline` disables package-index access. Run the normal installer once first so the virtual environment contains setuptools 69+ and the project dependencies.

The manual installation steps remain available below.

## Linux and macOS

From the project directory:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Verify the installation:

```bash
hunt --help
python -c "import finsec; print(finsec.__version__)"
```

The expected version is `0.5.0`.

## Windows PowerShell

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Verify the installation:

```powershell
hunt --help
python -c "import finsec; print(finsec.__version__)"
```

## Development Install

Install test and quality-check dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the checks:

```bash
ruff format --check .
ruff check .
mypy finsec
pytest
```

## First Run

Create a workspace and import the included synthetic HAR:

```bash
hunt init demo
hunt ingest examples/demo.har \
  --workspace workspaces/demo \
  --actor ACCOUNT_A \
  --channel WEB
hunt inventory --workspace workspaces/demo
hunt status --workspace workspaces/demo
```

## Troubleshooting

### Python version error

Confirm that the active interpreter is Python 3.12 or newer:

```bash
python --version
```

### `hunt` command not found

Activate the virtual environment, then reinstall the project:

```bash
source .venv/bin/activate
python -m pip install -e .
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
```

### Build dependency download fails

Check network access to the Python package index. If compatible build dependencies are already installed locally, try:

```bash
python -m pip install -e . --no-build-isolation
```

### Multiple workspaces found

Pass the target explicitly:

```bash
hunt status --workspace workspaces/example-fintech
```

## Safety Reminder

FinSec Hunt is for explicitly authorized research. Installation does not enable active testing: the project contains no request executor, autonomous exploitation, browser automation, denial-of-service tooling, or credential attack functionality.
