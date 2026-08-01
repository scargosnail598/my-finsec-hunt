Troubleshooting (decision-oriented)

Use the code and tests as authoritative sources for each branch.

Common checks:
- CLI command not found: ensure virtualenv active and `python -m pip install -e ".[dev]"` completed.
- Wrong virtual environment: confirm `python -V` and `which hunt` point to `.venv`.
- Workspace not found: ensure `workspaces/<slug>/target.yaml` exists or run `hunt setup`.
- Capture imported zero observations: check file format and `ingest` error messages; run tests in `tests/test_phase5_ingest.py`.
- Sanitized HAR missing authentication: review `detect_burp_authentication` logic in `finsec/auth/capture.py` and test fixtures.
- Credential available but not execution-ready: ensure ownership baseline and approval exist.

If an error message appears, map it to the code location and tests to propose smallest fix.
