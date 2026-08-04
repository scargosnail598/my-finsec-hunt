Implementation Status (summary)

Inspected version: project version from `pyproject.toml` (0.5.0).

Summary table (family: status — evidence):
- Burp XML import: Implemented — `finsec/ingest/traffic.py`, tests in `tests/test_phase5_ingest.py`.
- Burp HTTP history parsing: Implemented (history export parsing) — `load_burp_xml`.
- Burp Repeater export: Implemented (export-only) — `finsec/testing/burp.py`, tests `tests/test_burp_export.py`.
- Sending requests via Burp MCP: Not implemented — no code to open Burp proxy or MCP connection.
- Authentication extraction from captures: Implemented (detection and capture functions) — `finsec/auth/*`, tests `tests/test_authentication.py`.
- Token expiry/refresh handling: Partial — detection exists; automated refresh flows are not generically implemented unless observed and handled in code paths.
- Approval and execution gates: Implemented — `finsec/execution/policy.py`, approvals are checksum-bound.
- Automatic evidence collection and before/after scaffolding: Partial — evidence manager exists, but state snapshots require actual execution to produce.
- Offline Business Logic Analysis Engine: Implemented — deterministic workflow reconstruction,
  graphs, states, business invariants, 12 mutation families, blockers, canonical planning adapter,
  and skeptical state-evidence validation are available. Automated state-changing execution is
  intentionally unsupported.
- MCP tools: Implemented (readonly tools listed in `finsec/mcp/` and `finsec/mcp_server.py`).

For full provenance, see file headers and tests referenced above.
