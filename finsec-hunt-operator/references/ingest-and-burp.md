Ingest and Burp integration (verified)

Sources: `finsec/ingest/traffic.py`, `finsec/auth/service.py`, `finsec/cli.py`, tests under `tests/`.

Supported formats (implemented):
- Burp XML history export — handled by `load_burp_xml` and `ingest_burp_xml`.
  - Requirements: a Burp XML file with <item> entries; files with DOCTYPE entity declarations are rejected.
  - Actor/channel assignment: CLI `--actor` and `--channel` required for import; `recommend_burp_authentication` can suggest an auth candidate.
  - Deduplication: imports use document digest to avoid duplicate redacted captures.
  - Credentials: authentication candidates are captured in redacted form via `capture_from_burp` and stored as credential metadata (secrets externalized).
  - Sanitization: DTDs and entity declarations are rejected; bodies and headers are redacted before writing into workspace.

- HAR import — implemented in `finsec/ingest/har.py` and CLI `ingest` command.
  - Requirements: standard HAR structure; actor/channel must be specified or assigned.

What is not automatic/verified:
- Live sending of requests via Burp (there is an export facility only). The code provides `export-burp` to write Repeater requests, but sending is manual outside FinSec Hunt.
- Connecting to a remote Burp MCP server, or importing from Burp via network APIs is not implemented.

Side effects and files:
- Redacted JSON derivatives are written under workspace observations (e.g., `observations/raw/` and normalized stores).
- Burp-derived redacted captures use `-redacted.burp.json` naming and are linked into observation metadata.

Common errors and diagnostics:
- "Burp XML contains an unterminated DOCTYPE declaration." — file rejected for safety.
- "Burp item X has no usable request host." — an item lacks host metadata and is skipped/aborts.
