# FinSec Hunt MCP Server

The FinSec Hunt MCP server exposes sanitized, structured research context to MCP-compatible LLM
hosts. It is a local, safety-bounded adapter over one configured workspace path. It can perform
three passive local mutations: create that exact workspace, import an allowlisted HAR by basename,
and run the deterministic offline pipeline through hypothesis generation. The FinSec Hunt files
remain the source of truth; the connected model is an analyst, not a scanner or test executor.

## Threat Model And Boundary

The server assumes the local machine and selected workspace are controlled by the researcher, but
the MCP host and its model may be remote or cloud-operated. It therefore exposes only explicit
allowlisted fields from validated Pydantic stores.

The server can:

- create the exact startup-configured workspace without overwriting an existing path;
- import one HAR from an operator-configured directory with an explicit actor and channel;
- generate inventory, models, expected invariants, hypotheses, and research tasks offline;
- summarize the configured workspace;
- list hypotheses and research tasks;
- return sanitized, evidence-linked context for one hypothesis;
- summarize execution outcomes and evidence metadata;
- provide a skeptical hypothesis-review prompt.

The server cannot:

- send or replay HTTP requests;
- approve or execute plans;
- create plans, evidence, validations, reports, or execution records;
- overwrite an existing workspace;
- accept a workspace path from a tool caller;
- accept an arbitrary HAR path or a filename containing directories;
- read arbitrary files or artifact paths supplied by a model;
- return raw HAR entries, requests, responses, bodies, cookies, tokens, or credential values;
- generate attack payloads.

`FINSEC_HUNT_WORKSPACE` selects the exact workspace path and is read when the server starts. The
path may be absent only when `hunt_setup_workspace` will create it. `FINSEC_HUNT_IMPORT_ROOT`
optionally selects the only directory from which `hunt_ingest_har` can read direct-child `.har`
files. Tool callers cannot supply either directory.

Target-controlled names, fields, paths, and stored text are treated as untrusted data. The MCP
responses explicitly remind the host not to interpret them as instructions.

## Install

Python 3.12 or newer is required. The official Python MCP SDK is installed with FinSec Hunt and is
bounded to the stable v1 line:

```bash
./install.sh --dev
source .venv/bin/activate
python -c "import importlib.metadata; print(importlib.metadata.version('mcp'))"
```

The stdio server does not provide an interactive `--help` screen. MCP stdio reserves standard
output for JSON-RPC, so start the server through an MCP host or Inspector instead.

## Start Over Stdio

Set one absolute workspace path and, when HAR import is needed, one absolute import directory:

```bash
FINSEC_HUNT_WORKSPACE=/absolute/path/to/workspace \
FINSEC_HUNT_IMPORT_ROOT=/absolute/path/to/sanitized-hars \
  /absolute/path/to/.venv/bin/hunt-mcp
```

Equivalent module form:

```bash
FINSEC_HUNT_WORKSPACE=/absolute/path/to/workspace \
  /absolute/path/to/.venv/bin/python -m finsec.mcp_server
```

The process waits for MCP JSON-RPC on stdin. It should not be launched in an interactive terminal
unless an MCP client is connected.

## Public MCP Interface

### Tools

- `hunt_setup_workspace`: creates the exact configured workspace with explicit authorized hosts,
  researcher-owned account labels, default-deny restrictions, human approval required, and active
  execution disabled. It requires `authorization_confirmed: true` and never overwrites a path.
- `hunt_ingest_har`: imports one direct-child `.har` filename from
  `FINSEC_HUNT_IMPORT_ROOT`. The actor and channel are mandatory and are never inferred from the
  filename. The original remains in place and only redacted derivatives enter the workspace.
- `hunt_generate_hypotheses`: runs inventory, modeling, invariant extraction, and hypothesis
  generation over existing observations. It performs no network I/O and creates no plans.
- `hunt_workspace_summary`: target, scope, policy, restrictions, safe counts, and authentication
  fidelity.
- `hunt_list_hypotheses`: stable backlog summaries with filters for active records and research
  tasks.
- `hunt_get_hypothesis_context`: sanitized observations, endpoints, invariants, execution
  comparisons, evidence state, scope constraints, and interpretation rules for one `HYP-nnn` ID.
- `hunt_get_evidence_summary`: artifact index metadata, checklist progress, validation disposition,
  and report readiness without paths or contents.

Review tools are annotated read-only. HAR import and offline generation are non-destructive,
idempotent, and closed-world. Workspace setup is non-destructive and closed-world but intentionally
create-once rather than idempotent.

### Prompt

`review_hypothesis` instructs the model to call `hunt_get_hypothesis_context`, cite source IDs,
separate `OBSERVED`, `INFERRED`, and `ASSUMED` claims, choose exactly one of `KEEP`, `DOWNGRADE`,
`SPLIT`, or `DISMISS`, and propose one minimal single-dimension test with stop conditions.

## MCP Inspector

Install Node.js, then launch the Inspector with the workspace variable inherited by the server:

```bash
FINSEC_HUNT_WORKSPACE=/absolute/path/to/workspace \
  npx -y @modelcontextprotocol/inspector \
  /absolute/path/to/.venv/bin/hunt-mcp
```

In the Inspector:

1. List tools and verify the seven `hunt_*` tools appear.
2. For a missing configured workspace, call `hunt_setup_workspace` with explicit authorized hosts
   and non-secret account labels.
3. Call `hunt_ingest_har` once per capture with a basename, actor, and channel.
4. Call `hunt_generate_hypotheses`, then `hunt_workspace_summary`.
5. Call `hunt_list_hypotheses` with `active_only: true`.
6. Call `hunt_get_hypothesis_context` with a workspace-owned `HYP-nnn` ID.
7. Retrieve the `review_hypothesis` prompt.

## Linux MCP Host Configuration

Use absolute paths because MCP hosts commonly start outside the repository:

```json
{
  "mcpServers": {
    "finsec-hunt": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "finsec.mcp_server"],
      "env": {
        "FINSEC_HUNT_WORKSPACE": "/absolute/path/to/workspace",
        "FINSEC_HUNT_IMPORT_ROOT": "/absolute/path/to/sanitized-hars"
      }
    }
  }
}
```

Restart or reload the host after changing the configuration.

## Windows Host With A WSL Workspace

Run the Linux Python environment through `wsl.exe`. Replace the distribution and Linux paths:

```json
{
  "mcpServers": {
    "finsec-hunt": {
      "command": "wsl.exe",
      "args": [
        "--distribution",
        "Ubuntu",
        "--exec",
        "/usr/bin/env",
        "FINSEC_HUNT_WORKSPACE=/home/user/project/workspaces/example-target",
        "FINSEC_HUNT_IMPORT_ROOT=/home/user/project/sanitized-hars",
        "/home/user/project/.venv/bin/python",
        "-m",
        "finsec.mcp_server"
      ]
    }
  }
}
```

Use WSL paths for both Python and the workspace. A Windows path such as `C:\\project` is not a
valid Linux workspace path unless explicitly mounted and translated.

## Example Model Request

```text
Use the review_hypothesis prompt for HYP-002. Separate observed facts, inferences, and
assumptions; cite every source ID; identify contradicting evidence; and propose only one minimal
test using researcher-controlled accounts. Do not claim approval or execution occurred.
```

An anonymous request returning `401` is evidence about the credential-absent branch only. It does
not establish whether an authenticated non-owner can access another account's object. The MCP
context records the tested authentication state and whether a comparison request completed so the
model can split mixed claims without hard-coded verdicts.

## Authentication And Sanitization

Authentication uses three states:

- `PRESENT`: the source or checksum-matched execution plan records a credential mechanism.
- `ABSENT_CONFIRMED`: a runtime capture or fully specified executed request confirms no credential
  mechanism was present.
- `UNKNOWN_OR_REDACTED`: documentation, missing plan fidelity, or redacted metadata cannot prove
  presence or absence.

Credential values are never retained or returned. Execution reference fingerprints are one-way
and stable only within the configured workspace context; they identify a credential reference,
not the underlying secret or equality of raw credentials.

The centralized sanitizer removes or replaces authorization values, cookies, CSRF tokens, API
keys, session identifiers, passwords, OTPs, email addresses, phone numbers, payment/banking data,
query values, request/response bodies, source capture paths, and parameter examples. Concrete
object identifiers are removed from public route summaries when they are not required.

## Data That May Leave The Machine

The MCP server runs locally, but the MCP host decides where model inference occurs. When connected
to a cloud model, sanitized target names, in-scope hosts, endpoint templates, field names,
hypothesis text, source IDs, execution status codes, evidence metadata, and validation summaries
may be transmitted to that provider.

Local MCP does not guarantee local inference. Review the host's privacy, retention, and training
settings before connecting a sensitive workspace. Do not assume the sanitizer recognizes every
business secret or personal identifier.

## Troubleshooting

`Set FINSEC_HUNT_WORKSPACE ... before startup`:

- Configure an absolute exact workspace path. It may be missing only until
  `hunt_setup_workspace` creates it.

`Set FINSEC_HUNT_IMPORT_ROOT ... before importing captures`:

- Configure an absolute directory containing sanitized HAR files as direct children. Tool callers
  provide only the basename, not a path.

`... store is malformed or unreadable`:

- Run the normal FinSec Hunt command that validates that stage, or inspect the corresponding YAML
  locally. MCP errors intentionally omit absolute paths and stack traces.

The host reports invalid JSON or disconnects immediately:

- Ensure no wrapper script, shell profile, debugger, or application code writes banners or logs to
  stdout. Stdio stdout is reserved exclusively for MCP JSON-RPC. Send diagnostics to stderr.

The server starts in a terminal and appears idle:

- This is expected. It is waiting for an MCP client on stdin.

The host cannot find `hunt-mcp`:

- Use the absolute `.venv/bin/python` module configuration shown above, or reinstall the editable
  package after activating the virtual environment.

An execution is listed but authentication is `UNKNOWN_OR_REDACTED`:

- The current plan no longer checksum-matches the execution audit, or the structured request
  cannot establish credential presence. Do not reinterpret that state as anonymous access.

## Current Limitations

- Version one exposes exactly one startup-configured workspace path and one optional HAR import
  directory.
- It does not expose resources, raw artifacts, report bodies, or arbitrary researcher files.
- It does not attest that stored evidence came from a remote server; checksums establish local
  integrity only.
- It summarizes existing executions but cannot launch, approve, or modify them. Passive write tools
  stop at hypothesis generation.
- Sanitization is defense in depth, not a complete data-loss-prevention system.

The safest next extension is an explicit operator-configured workspace allowlist with opaque
workspace IDs. Do not add arbitrary path arguments or active execution tools.
