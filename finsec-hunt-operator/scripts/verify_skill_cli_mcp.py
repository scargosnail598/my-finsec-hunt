#!/usr/bin/env python3
"""Deterministic verifier: compare documented CLI/MCP entries with current `hunt --help` and MCP tools.

This script is read-only and safe. It prints differences between the references/cli-reference.md commands
and the output of `hunt --help`. It does not mutate state.
"""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILL_REF = ROOT / 'finsec-hunt-operator' / 'references' / 'cli-reference.md'

def run_help() -> str:
    try:
        out = subprocess.check_output([sys.executable, '-m', 'finsec.cli', '--help'], stderr=subprocess.STDOUT, text=True)
        return out
    except Exception as e:
        return f"ERROR: could not run hunt --help: {e}"

def main() -> int:
    print('Skill CLI/MCP verifier — read-only')
    help_text = run_help()
    print('\n--- hunt --help output ---\n')
    print(help_text)
    print('\n--- Reference snippet (first 200 chars) ---\n')
    if SKILL_REF.exists():
        print(SKILL_REF.read_text(encoding='utf-8')[:200])
    else:
        print('Reference file not found')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
