#!/usr/bin/env bash

set -Eeuo pipefail

finsec_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
finsec_venv_path="$finsec_script_dir/.venv"
finsec_python_command=""
finsec_install_dev=false
finsec_offline=false

usage() {
  cat <<'EOF'
Install FinSec Hunt into a local Python virtual environment.

Usage:
  ./install.sh [OPTIONS]

Options:
  --dev             Install development tools: pytest, Ruff, mypy, and type stubs.
  --python COMMAND  Use a specific Python interpreter or executable path.
  --venv PATH       Use a custom virtual environment path (default: .venv).
  --offline         Disable package-index access and use installed/cached packages only.
  -h, --help        Show this help message.

Examples:
  ./install.sh
  ./install.sh --dev
  ./install.sh --python python3.12 --venv .venv-dev --dev
EOF
}

fail() {
  printf 'Installation failed: %s\n' "$1" >&2
  exit 1
}

resolve_venv_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$finsec_script_dir" "$1" ;;
  esac
}

python_is_supported() {
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' \
    >/dev/null 2>&1
}

offline_build_tools_available() {
  "$1" -c '
import re
from importlib.metadata import PackageNotFoundError, version

try:
    match = re.match(r"[0-9]+", version("setuptools"))
except PackageNotFoundError:
    raise SystemExit(1)
raise SystemExit(0 if match is not None and int(match.group()) >= 69 else 1)
' >/dev/null 2>&1
}

select_python() {
  if [[ -n "$finsec_python_command" ]]; then
    command -v "$finsec_python_command" >/dev/null 2>&1 \
      || fail "Python interpreter not found: $finsec_python_command"
    python_is_supported "$finsec_python_command" \
      || fail "FinSec Hunt requires Python 3.12 or newer: $finsec_python_command"
    return
  fi

  local finsec_candidate
  for finsec_candidate in python3.12 python3 python; do
    if command -v "$finsec_candidate" >/dev/null 2>&1 \
      && python_is_supported "$finsec_candidate"; then
      finsec_python_command="$finsec_candidate"
      return
    fi
  done
  fail "Python 3.12 or newer was not found. Install it or pass --python COMMAND."
}

while (($# > 0)); do
  case "$1" in
    --dev)
      finsec_install_dev=true
      shift
      ;;
    --offline)
      finsec_offline=true
      shift
      ;;
    --python)
      (($# >= 2)) || fail "--python requires a command or executable path."
      finsec_python_command="$2"
      shift 2
      ;;
    --venv)
      (($# >= 2)) || fail "--venv requires a path."
      finsec_venv_path="$(resolve_venv_path "$2")"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1. Run ./install.sh --help for usage."
      ;;
  esac
done

select_python

printf 'FinSec Hunt installer\n'
printf 'Project: %s\n' "$finsec_script_dir"
printf 'Python:  %s\n' "$finsec_python_command"
printf 'Venv:    %s\n' "$finsec_venv_path"

if [[ ! -x "$finsec_venv_path/bin/python" ]]; then
  printf 'Creating virtual environment...\n'
  "$finsec_python_command" -m venv "$finsec_venv_path" \
    || fail "Could not create the virtual environment."
else
  printf 'Reusing existing virtual environment...\n'
fi

finsec_venv_python="$finsec_venv_path/bin/python"
finsec_hunt_command="$finsec_venv_path/bin/hunt"

python_is_supported "$finsec_venv_python" \
  || fail "The existing virtual environment does not use Python 3.12 or newer."

if [[ "$finsec_offline" == true ]]; then
  printf 'Installing in offline mode...\n'
  offline_build_tools_available "$finsec_venv_python" \
    || fail "Offline installation requires setuptools 69+ in the virtual environment. Run ./install.sh once with network access first."
  finsec_pip_options=(--no-index --no-build-isolation)
else
  printf 'Updating installation tools...\n'
  "$finsec_venv_python" -m pip install --upgrade pip 'setuptools>=69' \
    || fail "Could not install current pip/setuptools build tools."
  finsec_pip_options=(--no-build-isolation)
fi

if [[ "$finsec_install_dev" == true ]]; then
  finsec_install_target="$finsec_script_dir[dev]"
  printf 'Installing FinSec Hunt with development tools...\n'
else
  finsec_install_target="$finsec_script_dir"
  printf 'Installing FinSec Hunt...\n'
fi

"$finsec_venv_python" -m pip install "${finsec_pip_options[@]}" -e "$finsec_install_target" \
  || fail "Package installation failed."

[[ -x "$finsec_hunt_command" ]] || fail "The hunt command was not installed."
"$finsec_hunt_command" --help >/dev/null \
  || fail "The installed hunt command did not start successfully."

finsec_version="$($finsec_venv_python -c 'import finsec; print(finsec.__version__)')"

printf '\nInstallation complete: FinSec Hunt %s\n' "$finsec_version"
printf 'Activate the environment with:\n'
printf '  source %q\n' "$finsec_venv_path/bin/activate"
printf 'Then run:\n'
printf '  hunt --help\n'
printf '  hunt init demo\n'
