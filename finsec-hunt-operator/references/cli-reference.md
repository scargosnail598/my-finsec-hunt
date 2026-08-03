CLI Reference (verified)

Source of truth: `finsec/cli.py` and `pyproject.toml` (`hunt` entry point).

Group: Workspace and Setup
- `hunt setup` — interactive or non-interactive workspace creation.
  - Inputs: `--name`, `--slug`, `--host`, `--account`, `--anonymous-actor`, `--yes` for non-interactive.
  - Preconditions: target host(s) provided; creates `workspaces/<slug>/target.yaml`.
  - Safety: creates workspace only; does not overwrite existing workspace.
  - Example: `hunt setup --name "Example" --slug example-fintech --host api.example.test --account ACCOUNT_A --yes`

Group: Ingestion
- `hunt ingest <file.har> -w workspaces/<slug> --actor ACCOUNT --channel WEB` — import HAR (see `finsec/ingest/har.py`)
- `hunt ingest-burp <file.xml> -w workspaces/<slug> --actor ACCOUNT --channel WEB` — import Burp XML (`finsec/ingest/traffic.py`).
  - Inputs: file path, workspace path, actor id, channel label.
  - Preconditions: workspace exists and capture directory writable.
  - Outputs: redacted captures under workspace observations (JSON), updated observation store.
  - Safety: imports are passive; secrets are redacted. `--capture-auth` may capture an auth candidate without echoing secrets.

Group: Modeling & Workflow
- `hunt workflow --workspace workspaces/<slug>` — run offline inventory, modeling, and hypothesis generation (`finsec/workflow.py`).
  - Writes derived model artifacts (model/, hypotheses/) into the workspace.

Group: Actor Authentication
- `hunt actor auth refresh <ACTOR_ID> --burp <file>` — accept Burp or HAR-based refresh candidate (see `finsec/auth/service.py` and CLI hooks).
  - Does not send network requests; captures candidate for researcher review.

Group: Burp Export
- `hunt export-burp HYP-001 -w workspaces/<slug>` — export approved plan as Burp Repeater requests (`finsec/testing/burp.py`).
  - Preconditions: hypothesis approved with checksum-bound approval; export refuses unsafe requests.

Group: MCP
- CLI provides `hunt-mcp` and `finsec-hunt-operator` entry points (module `finsec.mcp_server:main`). MCP tools and schemas are implemented in `finsec/mcp/`.

Always verify exact flags with `hunt <command> --help` before use; do not assume flags not present in current install.
