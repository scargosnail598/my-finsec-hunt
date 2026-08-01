MCP Reference (verified)

Sources: `finsec/mcp_server.py`, `finsec/mcp/service.py`, `finsec/mcp/models.py`, `docs/mcp-server.md`.

Entry point:
- `hunt-mcp` script maps to `finsec.mcp_server:main` (see `pyproject.toml` project.scripts).

Implemented MCP tools (read-only / non-executing):
- `hunt_setup_workspace` — create the exact configured workspace without overwriting.
- `hunt_ingest_har` — import one allowlisted HAR child filename from configured import root.
- `hunt_generate_hypotheses` — run inventory, modeling, invariant extraction, hypothesis generation.
- `hunt_workspace_summary`, `hunt_list_hypotheses`, `hunt_get_hypothesis_context`, `hunt_get_evidence_summary` — read-only summary/tools.

Safety: the MCP server cannot send HTTP requests, accept arbitrary file paths, or return raw capture contents.
