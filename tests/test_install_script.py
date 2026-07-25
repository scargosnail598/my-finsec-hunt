"""Contract tests for the Unix installation wrapper."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def test_install_script_is_executable_and_valid_bash() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash is not available on this platform.")

    script = Path(__file__).parents[1] / "install.sh"
    assert script.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n")
    assert os.access(script, os.X_OK)

    syntax = subprocess.run(
        [bash, "-n", str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert syntax.returncode == 0, syntax.stderr

    help_result = subprocess.run(
        [bash, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "--dev" in help_result.stdout
    assert "--python COMMAND" in help_result.stdout
    assert "--venv PATH" in help_result.stdout
    assert "--offline" in help_result.stdout
