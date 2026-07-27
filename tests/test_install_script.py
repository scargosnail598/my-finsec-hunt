"""Contract tests for the Unix installation wrapper."""

import os
import shutil
import subprocess
import sys
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


def test_automation_scripts_are_safe_and_start_successfully(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash is not available on this platform.")
    root = Path(__file__).parents[1]
    check_script = root / "scripts/check.sh"
    demo_script = root / "scripts/run_demo_workflow.py"
    driver = root / ".claude/skills/run-finsec-hunt/driver.py"

    assert os.access(check_script, os.X_OK)
    assert os.access(demo_script, os.X_OK)
    syntax = subprocess.run(
        [bash, "-n", str(check_script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert syntax.returncode == 0, syntax.stderr
    help_result = subprocess.run(
        [sys.executable, str(demo_script), "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=root,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "never deleted or overwritten" in help_result.stdout
    assert "rmtree" not in driver.read_text(encoding="utf-8")

    run = subprocess.run(
        [sys.executable, str(demo_script), "--root", str(tmp_path / "demo-output")],
        check=False,
        capture_output=True,
        text=True,
        cwd=root,
    )
    assert run.returncode == 0, run.stderr
    assert "Synthetic demo completed" in run.stdout
