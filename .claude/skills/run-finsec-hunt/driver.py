#!/usr/bin/env python3
"""
Driver harness for driving FinSec Hunt on a target workspace.
Applies the full deterministic pipeline from workspace init -> ingest -> inventory -> model -> invariants -> hypotheses -> plan -> status.
"""

import sys
import subprocess
import shutil
from pathlib import Path

def run_cmd(cmd: list[str]) -> str:
    print(f"==> Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error output:\n{res.stderr}")
        sys.exit(res.returncode)
    print(res.stdout)
    return res.stdout

def main() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    venv_python = repo_root / ".myvenv2" / "bin" / "python"
    if not venv_python.is_file():
        venv_python = Path(sys.executable)

    target_name = sys.argv[1] if len(sys.argv) > 1 else "demo-target"
    workspace_dir = repo_root / "workspaces" / target_name
    har_path = repo_root / "examples" / "demo.har"

    if workspace_dir.exists():
        print(f"Removing existing workspace at {workspace_dir}")
        shutil.rmtree(workspace_dir)

    print(f"--- 1. Initialize Workspace '{target_name}' ---")
    run_cmd([str(venv_python), "-m", "finsec.cli", "init", target_name])

    print("--- 2. Ingest Traffic Capture ---")
    run_cmd([
        str(venv_python), "-m", "finsec.cli", "ingest", str(har_path),
        "-w", str(workspace_dir), "--actor", "ACCOUNT_A", "--channel", "WEB"
    ])

    print("--- 3. Build Endpoint Inventory ---")
    run_cmd([str(venv_python), "-m", "finsec.cli", "inventory", "-w", str(workspace_dir)])

    print("--- 4. Build Domain Model ---")
    run_cmd([str(venv_python), "-m", "finsec.cli", "model", "-w", str(workspace_dir)])

    print("--- 5. Extract Invariants ---")
    run_cmd([str(venv_python), "-m", "finsec.cli", "invariants", "-w", str(workspace_dir)])

    print("--- 6. Generate Hypotheses ---")
    run_cmd([str(venv_python), "-m", "finsec.cli", "hypotheses", "-w", str(workspace_dir)])

    print("--- 7. Generate Test Plan ---")
    run_cmd([str(venv_python), "-m", "finsec.cli", "plan", "HYP-001", "-w", str(workspace_dir)])

    print("--- 8. Display Workspace Status ---")
    run_cmd([str(venv_python), "-m", "finsec.cli", "status", "-w", str(workspace_dir)])

    print("Pipeline driver executed successfully.")

if __name__ == "__main__":
    main()
