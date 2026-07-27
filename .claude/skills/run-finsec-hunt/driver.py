#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

def main() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    command = [
        sys.executable,
        str(repo_root / "scripts" / "run_demo_workflow.py"),
        *sys.argv[1:],
    ]
    result = subprocess.run(command, check=False)
    raise SystemExit(result.returncode)

if __name__ == "__main__":
    main()
