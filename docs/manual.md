# THE FINSEC HUNT COMPREHENSIVE ENGINEERING & OPERATIONAL MANUAL
#### Complete Architectural Specification, Pipeline Mechanics, Security Policies, User Interfaces, and Developer Guide
**Version:** 0.5.0  
**Target Platform:** Linux / macOS / WSL2 (Python >= 3.12)  
**System Classification:** Local-First Authorized Fintech Security Research Workspace  

---

## TABLE OF CONTENTS

1. [SYSTEM OVERVIEW & DESIGN PHILOSOPHY](#1-system-overview--design-philosophy)
   - 1.1 Objective and Purpose
   - 1.2 Core Architectural Principles
   - 1.3 The Default-Deny Security Model
   - 1.4 Knowledge State Separation
   - 1.5 Redaction and Privacy Guarantees
   - 1.6 Edit Preservation and Stable Identity Engine
2. [DIRECTORY ANATOMY & WORKSPACE ARCHITECTURE](#2-directory-anatomy--workspace-architecture)
   - 2.1 Codebase Package Structure (`finsec/`)
   - 2.2 Target Workspace Layout (`workspaces/<slug>/`)
   - 2.3 External Capture Layout (`captures/<slug>/`)
   - 2.4 Isolated Credential Store (`.finsec-secrets/`)
   - 2.5 Schema & Auxiliary Storage
3. [DOMAIN TYPE SYSTEM & PYDANTIC CONTRACTS](#3-domain-type-system--pydantic-contracts)
   - 3.1 Strict Base Models (`StrictModel`)
   - 3.2 Observation Models (`Observation`, `ObservationStore`)
   - 3.3 Endpoint & Normalization Models (`Endpoint`, `EndpointStore`)
   - 3.4 Inferred Model Domain (`ActorStore`, `ResourceStore`, `InvariantStore`)
   - 3.5 Security Hypotheses Domain (`HypothesisRecord`, `HypothesisStore`)
   - 3.6 Test Planning & Approval Models (`TestPlanRecord`, `PlanApproval`)
   - 3.7 Evidence & Validation Models (`EvidenceMetadata`, `ValidationResult`)
4. [THE 12-STAGE DETERMINISTIC RESEARCH PIPELINE](#4-the-12-stage-deterministic-research-pipeline)
   - 4.1 Stage 1: Workspace Setup & Target Configuration
   - 4.2 Stage 2: Actor Authentication & Secret Binding
   - 4.3 Stage 3: Passive Multi-Format Capture Ingestion
   - 4.4 Stage 4: Traffic Classification & Noise Suppression
   - 4.5 Stage 5: Structural Path Normalization & Parameterization
   - 4.6 Stage 6: Inferred Domain & Architectural Modeling
   - 4.7 Stage 7: Invariants Extraction & Security Properties
   - 4.8 Stage 8: Evidence-Gated Security Hypothesis Generation
   - 4.9 Stage 9: Bounded Test Planning & Safety Checks
   - 4.10 Stage 10: Dual-Checksum Approval & Bounded Execution
   - 4.11 Stage 11: Evidence Indexing & Skeptical Validation Engine
   - 4.12 Stage 12: Immutable Jinja2 Markdown Report Generation
5. [EXECUTION SAFETY ENGINE & POLICY CONTROLS](#5-execution-safety-engine--policy-controls)
   - 5.1 Dual-Checksum Human Approval Gate
   - 5.2 Host Scope Matching & Subdomain Logic
   - 5.3 DNS Preflight Verification & Metadata Blocking
   - 5.4 Redirect Policy & Scope Containment
   - 5.5 Execution Runner Budget & Sequential Rate Enforcement
   - 5.6 Transport Audit Logging & Traceability
6. [SKEPTICAL VALIDATION ENGINE: THE 15 CHECKS](#6-skeptical-validation-engine-the-15-checks)
   - 6.1 Validation Design Principles
   - 6.2 Detailed Breakdown of the 15 Checks
   - 6.3 Validation Dispositions and Decision Logic
7. [COMPLETE CLI USER MANUAL & COMMAND REFERENCE](#7-complete-cli-user-manual--command-reference)
   - 7.1 Setup and Workspace Initialization Commands
   - 7.2 Ingestion & Provenance Management Commands
   - 7.3 Authentication and Secret Storage Commands
   - 7.4 Offline Workflow and Inspection Commands
   - 7.5 Test Planning, Approval, and Execution Commands
   - 7.6 Evidence, Validation, and Reporting Commands
   - 7.7 Workspace Lifecycle and Deletion Commands
8. [LOCAL WEB COCKPIT ARCHITECTURE (`hunt web`)](#8-local-web-cockpit-architecture-hunt-web)
   - 8.1 Server Architecture and Loopback Binding
   - 8.2 Security Constraints and Headers
   - 8.3 Operation Surface and Views
   - 8.4 Web Danger Zone & Deletion Integrity
9. [MODEL CONTEXT PROTOCOL (MCP) SERVER (`hunt-mcp`)](#9-model-context-protocol-mcp-server-hunt-mcp)
   - 9.1 Threat Model and Client-Server Boundaries
   - 9.2 Environment Configurations (`FINSEC_HUNT_WORKSPACE`)
   - 9.3 Exposed Tools Reference
   - 9.4 Exposed Prompts Reference (`review_hypothesis`)
   - 9.5 IDE & Windows / WSL Integration Setup
10. [DEVELOPER GUIDE & MAINTENANCE](#10-developer-guide--maintenance)
    - 10.1 Environment Setup and Dependencies
    - 10.2 Code Style, Typing, and Linting Standards
    - 10.3 Test Suite Execution (`pytest`)
    - 10.4 Synthetic Validation Harness (`scripts/run_synthetic_validation.sh`)
    - 10.5 Workspace Deletion & Purging Guard System
11. [TROUBLESHOOTING & EDGE CASE RESOLUTION](#11-troubleshooting--edge-case-resolution)
    - 11.1 Missing Workflow Manifests
    - 11.2 Invalidated Plan Approvals
    - 11.3 Unassigned HAR File Import Failures
    - 11.4 Host Scope Resolution Mismatches
    - 11.5 Preserved Researcher Edit Conflicts

---

# 1. SYSTEM OVERVIEW & DESIGN PHILOSOPHY

### 1.1 Objective and Purpose

**FinSec Hunt** is a local-first, deterministic research workspace designed for authorized security analysis of financial technology (Fintech) Web, API, and Mobile applications. 

Modern Fintech environments possess complex state machines, strict multi-tenant authorization boundaries, regulatory requirements (PCI-DSS, PSD2, SOC2), and custom business logic. Traditional vulnerability scanners (DAST, SAST) fail in these environments because they operate blindly: they inject generic payloads, trigger rate limits, generate excessive log noise, or fail due to complex multi-step authentication. Conversely, manual security research often struggles with organization, evidence preservation, scope compliance, and systematic coverage tracking.

FinSec Hunt solves this challenge by serving as an **analyst assistant and deterministic knowledge engine**. It converts researcher-supplied passive artifacts (HTTP traffic captures, OpenAPI specs, GraphQL schemas, mobile APK strings) into structured, reviewable models. It automatically derives actors, resources, and security invariants; formulates evidence-gated security hypotheses; generates bounded, safe test plans; indexes evidence; and skeptically validates findings before generating revisioned audit reports.

### 1.2 Core Architectural Principles

1. **Passive by Default**: The entire core pipeline (ingestion, classification, normalization, domain modeling, invariant extraction, hypothesis generation, evidence management, validation, and reporting) is **100% passive** and executes offline. Zero network traffic is generated.
2. **Explicit Human Approval**: Active execution is disabled by default in every new workspace. Automated testing is restricted to bounded, read-only HTTP calls (`GET`, `HEAD`, `OPTIONS`) and requires explicit human approval via a dual-checksum validation gate.
3. **Traceability and Reproducibility**: Every observation, endpoint, model, invariant, hypothesis, plan, evidence file, and report maintains strict provenance links back to the original redacted input artifact.
4. **Deterministic Processing**: Given the same input captures and configuration, FinSec Hunt produces identical normalized paths, models, invariants, and hypotheses every time.
5. **Separation of Concerns**: Machine learning models and LLMs are treated as analytical assistants, never as autonomous execution agents or authoritative judges of security findings.

### 1.3 The Default-Deny Security Model

FinSec Hunt enforces a default-deny security model across all configurations:

- **Target Scope**: Endpoints are treated as third-party or out-of-scope unless their host explicitly matches the target's configured exact or wildcard host patterns (`target.scope.hosts`).
- **Active Execution**: `testing.active_execution_enabled` defaults to `false` in `target.yaml`.
- **Destructive Testing**: `testing.destructive_testing` defaults to `false`.
- **Human Approval**: `testing.human_approval_required` defaults to `true`.
- **Read-Only Enforcements**: Execution runners reject any HTTP method that can alter remote server state (`POST`, `PUT`, `DELETE`, `PATCH`).

---

### 1.4 Knowledge State Separation

To prevent false positives, hallucinated vulnerability claims, and premature reporting, FinSec Hunt enforces strict boundaries between six fundamental knowledge states:

```
[FACT] ──> [INFERENCE] ──> [PROPERTY/INVARIANT] ──> [HYPOTHESIS] ──> [EVIDENCE] ──> [FINDING]
```

1. **Fact (`OBS-xxxxxx`)**: Direct, empirical evidence extracted from incoming passive captures (e.g. HAR files, Burp XML history, Caido JSON). Facts capture HTTP methods, paths, status codes, query parameter names, header fields, and JSON structure—never raw credentials or PII.
2. **Inference (`EP-xxx`, `ACT-xxx`, `RES-xxx`)**: A normalized structural model derived from facts, such as a parameterized endpoint path (`/api/v1/accounts/{accountId}`), an actor role (`ACCOUNT_A`), or a business resource (`Payment`).
3. **Property / Invariant (`INV-xxx`)**: A security rule or policy expectation that *should* hold on the target system (e.g., *"An authenticated actor must not read another actor's account resources"*).
4. **Hypothesis (`HYP-xxx`)**: An active, testable security research question gated by explicit evidence requirements. If required runtime evidence is missing, the candidate remains a **Research Task** rather than an active hypothesis.
5. **Evidence (`EVI-xxx`)**: Researcher-supplied proofs, baseline HTTP transcripts, state comparison snapshots (before/after JSON), or transport execution logs indexed with SHA-256 digests.
6. **Finding**: A hypothesis promoted to reportable status **only** after passing all 15 automated skeptical validation checks.

---

### 1.5 Redaction and Privacy Guarantees

Passive traffic captures frequently contain sensitive data, including session tokens, passwords, API keys, credit card numbers, and PII. FinSec Hunt enforces defense-in-depth redaction (`finsec/utils/redaction.py`):

- **Header Redaction**: Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Session-Token`, `X-CSRF-Token`) have their values replaced with `[REDACTED]`.
- **Query Parameter Redaction**: Values of parameters matching sensitive names (`token`, `auth`, `key`, `secret`, `password`, `session`, `jwt`, `bearer`) are masked.
- **Body & Text Redaction**: Regex patterns scan JSON keys and raw body text for secret formats (JWT signatures, Bearer tokens, basic auth strings, credit card numbers, private keys).
- **External Secret Storage**: Credentials extracted via `--capture-auth` are stripped from the workspace directory and saved in an isolated file under `workspaces/.finsec-secrets/` with strict `0600` file permissions. `target.yaml` stores only profile references and non-secret metadata.

---

### 1.6 Edit Preservation and Stable Identity Engine

FinSec Hunt treats the workspace directory as a **shared human/tool memory space**. Generated files are not treated as disposable build output:

- **Stable Semantic Identifiers**: Entities are assigned deterministic keys based on stable properties (e.g., `METHOD:HOST:PATH_TEMPLATE` for endpoints). Rerunning ingestion or modeling maintains stable `EP-xxx`, `INV-xxx`, and `HYP-xxx` identifiers.
- **Preservation of Explicit Human Edits**: When a researcher updates explicit lifecycle fields (such as `hypothesis.status`, `plan.approval_status`, custom notes, or manual classification overrides), those changes persist across pipeline regenerations.
- **Conflict Tracking**: If updated passive evidence directly contradicts a human-modified record, FinSec Hunt preserves the human edit and flags a conflict in `workflow.yaml` or CLI status reports.
- **Suppression over Deletion**: When an endpoint or invariant is no longer present in incoming traffic, it is marked with a `SUPPRESSED` disposition rather than deleted, ensuring historical research state is never lost.

---

# 2. DIRECTORY ANATOMY & WORKSPACE ARCHITECTURE

FinSec Hunt maintains a clean physical separation between codebase modules, target workspaces, external capture directories, and secret storage.

```
my-finsec-hunt/
├── finsec/                            # Core Python Package (Python 3.12+)
│   ├── auth/                          # Authentication, secret resolution, & JWT handling
│   ├── config/                        # Workspace paths, target document models, & scope logic
│   ├── evidence/                      # Evidence package management & artifact indexing
│   ├── execution/                     # Bounded HTTP execution runner & policy engine
│   ├── hypotheses/                    # Rule-based hypothesis & research task generator
│   ├── ingest/                        # Parsers for HAR, Burp XML, Caido JSON, OpenAPI
│   ├── mcp/                           # Model Context Protocol (MCP) server implementation
│   ├── modeling/                      # Inferred models (Actors, Resources, Invariants)
│   ├── normalization/                 # Classification & path parameterization engine
│   ├── recon/                         # GraphQL schema & static mobile string analysis
│   ├── reporting/                     # Report generator & Jinja2 Markdown templates
│   ├── testing/                       # Test plan generator & approval verification
│   ├── utils/                         # Global redaction, YAML storage, network helpers
│   ├── validation/                    # Skeptical 15-check validation engine
│   ├── web/                           # Starlette/Uvicorn local web cockpit server
│   ├── cli.py                         # Primary Typer CLI entry point (`hunt`)
│   ├── mcp_server.py                  # Stdio MCP server entry point (`hunt-mcp`)
│   └── workflow.py                    # Offline passive workflow pipeline orchestrator
│
├── captures/                          # External Capture Storage Root
│   └── <slug>/
│       ├── incoming/                  # Original HAR / Burp XML / Caido files
│       └── workflow.yaml              # Capture provenance & actor/channel manifest
│
├── workspaces/                        # Target Workspace Storage Root
│   └── <slug>/
│       ├── target.yaml                # Target specification, accounts, & safety policies
│       ├── scope/                     # Markdown scope & restriction files
│       │   ├── program.md
│       │   ├── scope.md
│       │   └── restrictions.md
│       ├── observations/
│       │   ├── raw/                   # Redacted JSON capture derivatives
│       │   └── normalized/
│       │       └── observations.yaml  # Fact ObservationStore (OBS-xxxxxx)
│       ├── api/
│       │   └── endpoints.yaml         # Normalized EndpointStore (EP-xxx)
│       ├── model/                     # Derived domain architecture & invariants
│       │   ├── architecture.md
│       │   ├── authorization.md
│       │   ├── workflows.md
│       │   ├── state-machines.md
│       │   └── invariants.yaml        # InvariantStore (INV-xxx)
│       ├── hypotheses/
│       │   └── hypotheses.yaml        # HypothesisStore (HYP-xxx)
│       ├── tests/
│       │   ├── plans/
│       │   │   └── plans.yaml         # TestPlanStore (PLN-xxx)
│       │   └── executions/            # Transport audit logs & execution dumps
│       ├── approved_plans.yaml        # Dual-checksum human approval records
│       ├── evidence/
│       │   └── HYP-xxx/               # Evidence metadata, artifacts, & conclusions
│       └── reports/                   # Immutable Markdown reports (HYP-xxx-report-vN.md)
│
└── workspaces/.finsec-secrets/        # Isolated Secret Storage (Directory permissions: 0700)
    └── <slug>.json                    # Actor secrets file (File permissions: 0600)
```

---

# 3. DOMAIN TYPE SYSTEM & PYDANTIC CONTRACTS

All data structures in FinSec Hunt are defined using **Pydantic v2** models located across sub-packages.

### 3.1 Strict Base Models (`StrictModel`)
To prevent typos, schema drift, and unvalidated parameters, all data structures inherit from `StrictModel` (`finsec/modeling/models.py`):

```python
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
```

### 3.2 Key Enumerations

```python
AuthenticationType = Literal["none", "bearer", "basic", "cookie", "api_key", "mixed"]
ParameterType = Literal["string", "integer", "uuid", "ulid", "hash", "date", "version"]
ParameterSemanticType = Literal[
    "object_identifier", "monetary_value", "state", "authentication", "pagination", "unknown"
]
EndpointDisposition = Literal[
    "ACTIVE",
    "SUPPRESSED_STATIC_ASSET",
    "SUPPRESSED_TELEMETRY",
    "SUPPRESSED_ANALYTICS",
    "SUPPRESSED_THIRD_PARTY",
    "SUPPRESSED_PUBLIC_RESOURCE",
    "SUPPRESSED_INSUFFICIENT_EVIDENCE",
]
ChannelType = Literal["WEB", "MOBILE", "PARTNER_API", "PUBLIC_API", "UNKNOWN"]
ObservationSource = Literal["HAR", "BURP_XML", "CAIDO_JSON", "OPENAPI"]
KnowledgeStatus = Literal["OBSERVED", "INFERRED", "ASSUMED"]
```

---

# 4. THE 12-STAGE DETERMINISTIC RESEARCH PIPELINE

```
[1. SETUP] ──> [2. AUTH] ──> [3. INGEST] ──> [4. CLASSIFY] ──> [5. NORMALIZE] ──> [6. MODEL]
                                                                                      │
[12. REPORT] <── [11. VALIDATE] <── [10. EXECUTE] <── [9. PLAN] <── [8. HYPOTHESIZE] <── [7. INVARIANTS]
```

### Stage 1: Workspace Setup & Target Configuration
- **Module**: `finsec/setup.py`, `finsec/config/workspace.py`
- **CLI**: `hunt setup`
- **Operation**: Creates workspace folder structure, writes default-deny `target.yaml`, initializes `scope/` Markdown templates, and creates `captures/<slug>/workflow.yaml`.

### Stage 2: Actor Authentication & Secret Binding
- **Module**: `finsec/auth/service.py`, `finsec/auth/store.py`
- **CLI**: `hunt ingest --capture-auth`, `hunt actor auth import`, `hunt actor auth check`
- **Operation**: Extracts session headers/cookies from captures, securely persists them in `.finsec-secrets/<slug>.json` with `0600` permissions, and updates actor profile references in `target.yaml`.

### Stage 3: Passive Multi-Format Capture Ingestion
- **Module**: `finsec/ingest/har.py`, `traffic.py`, `openapi.py`
- **CLI**: `hunt ingest`, `hunt ingest-burp`, `hunt ingest-caido`, `hunt ingest-openapi`
- **Operation**: Parses input files, redacts sensitive headers/values, generates a redacted JSON capture under `observations/raw/`, and appends factual `Observation` entries (`OBS-xxxxxx`) to `observations.yaml`.

### Stage 4: Traffic Classification & Noise Suppression
- **Module**: `finsec/normalization/classification.py`
- **CLI**: `hunt classify`, `hunt noise`
- **Operation**: Evaluates observation paths, headers, extensions, and content-types against policy rules. Tag static assets, analytics, telemetry, and out-of-scope third-party traffic with `SUPPRESSED` dispositions.

### Stage 5: Structural Path Normalization & Parameterization
- **Module**: `finsec/normalization/paths.py`, `inventory.py`
- **CLI**: `hunt workflow`
- **Operation**: Collapses concrete URL paths into normalized endpoint families (`EP-xxx`):
  - UUIDs, ULIDs, long hex strings, and opaque IDs are parameterized as `{uuid}`, `{opaqueId}`.
  - Repeated numeric segments across distinct observations are parameterized as `{resourceId}`.
  - Consecutive dynamic parameters derive camelCase names from preceding path segments (e.g. `/users/123/orders/456` $\rightarrow$ `/users/{userId}/orders/{orderId}`).

### Stage 6: Inferred Domain & Architectural Modeling
- **Module**: `finsec/modeling/generator.py`, `merge.py`
- **CLI**: `hunt workflow`
- **Operation**: Groups endpoints by semantic path families to derive business resources (`Payment`, `Account`), actor permissions, operation types (`READ`, `CREATE`, `MODIFY`, `DELETE`, `FINANCIAL_MUTATION`), and state transition candidates. Renders human-readable Markdown diagrams under `model/`.

### Stage 7: Invariants Extraction & Security Properties
- **Module**: `finsec/modeling/invariants.py`
- **CLI**: `hunt workflow`
- **Operation**: Derives explicit security rules (`INV-xxx`) stored in `model/invariants.yaml`:
  - `INV-AUTHENTICATION`: Endpoints requiring authentication.
  - `INV-OBJECT-AUTHORIZATION`: Operations on client-controlled identifiers requiring specific object authorization.
  - `INV-STATE-INTEGRITY`: Operations constrained by resource lifecycle state.

### Stage 8: Evidence-Gated Security Hypothesis Generation
- **Module**: `finsec/hypotheses/generator.py`
- **CLI**: `hunt hypotheses`
- **Operation**: Generates active hypotheses (`HYP-xxx`) in `hypotheses/hypotheses.yaml` only when runtime evidence satisfies threshold rules:
  - **BOLA / IDOR**: Requires authenticated baseline + client-controlled parameter + observed multi-actor access.
  - **Research Tasks**: Incomplete leads or documentation-only operations (from OpenAPI) are routed to research tasks rather than active hypotheses.

### Stage 9: Bounded Test Planning & Safety Checks
- **Module**: `finsec/testing/planner.py`
- **CLI**: `hunt plan <hyp-id>`
- **Operation**: Drafts structured test plan (`PLN-xxx`) in `tests/plans/plans.yaml`. Performs static policy checks:
  - If method is non-read-only, target host is out of scope, or accounts are insufficient, status is set to `BLOCKED`.
  - If all checks pass, status is set to `READY_FOR_REVIEW`.

### Stage 10: Dual-Checksum Approval & Bounded Execution
- **Module**: `finsec/execution/policy.py`, `runner.py`
- **CLI**: `hunt approve <hyp-id>`, `hunt execute <hyp-id>`
- **Operation**: 
  1. `hunt approve` prompts for explicit confirmation and writes an approval record to `approved_plans.yaml` linking `plan_checksum` and `target_policy_checksum`.
  2. `hunt execute` validates approvals, scope, and DNS, then executes bounded, sequential read-only requests. Writes redacted execution evidence and append-only transport audit logs.

### Stage 11: Evidence Indexing & Skeptical Validation Engine
- **Module**: `finsec/evidence/manager.py`, `finsec/validation/validator.py`
- **CLI**: `hunt evidence <hyp-id>`, `hunt validate <hyp-id>`
- **Operation**: Indexes researcher-provided artifacts (requests, responses, before/after JSON) with SHA-256 hashes. Evaluates **15 deterministic skeptical checks** to determine finding validity (`CONFIRMED`, `REFUTED`, `NEEDS_MORE_EVIDENCE`, `OUT_OF_SCOPE`, `EXPECTED_BEHAVIOR`).

### Stage 12: Immutable Jinja2 Markdown Report Generation
- **Module**: `finsec/reporting/generator.py`
- **CLI**: `hunt report <hyp-id>`
- **Operation**: Renders final audit reports using Jinja2 templates (`report.md.j2`). Requires `CONFIRMED` validation disposition; refuses unvalidated findings. Produces versioned, immutable Markdown reports (`reports/HYP-xxx-report-v1.md`).

---

# 5. EXECUTION SAFETY ENGINE & POLICY CONTROLS

The execution safety engine (`finsec/execution/`) guarantees that FinSec Hunt can never be misused as an aggressive scanner or unauthorized attack tool.

### 5.1 Dual-Checksum Human Approval Gate
To execute a plan, `approved_plans.yaml` must contain a record matching both checksums:

$$\text{Plan Checksum} = \text{SHA256}(\text{Structured Requests} \parallel \text{Budget} \parallel \text{Stop Conditions})$$
$$\text{Policy Checksum} = \text{SHA256}(\text{Target Scope Hosts} \parallel \text{Testing Policies})$$

If the researcher edits the plan or modifies `target.yaml`, the checksums change, instantly invalidating approval and halting execution.

### 5.2 Host Scope Matching & Subdomain Logic
Host matching (`finsec/config/scope.py`) uses strict exact and wildcard logic:
- `api.example.test` matches ONLY `api.example.test`.
- `*.example.test` matches `sub.api.example.test` AND `example.test` apex domain.
- Unlisted third-party hosts cause execution policy rejection.

### 5.3 DNS Preflight Verification & Metadata Blocking
Before opening a TCP socket, `policy.py` resolves domain names and verifies IP addresses:
- **Private IP Ranges Blocked**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`.
- **Cloud Metadata Blocked**: `169.254.169.254` (AWS/GCP), `100.100.100.200` (Alibaba), `fd00:ec2::254`.

### 5.4 Redirect Policy & Scope Containment
If an executed HTTP request returns a `301`, `302`, `307`, or `308` redirect:
- The runner intercepts the `Location` header.
- If the redirect host is not explicitly covered by `target.scope.hosts`, execution halts immediately with `REDIRECT_OUT_OF_SCOPE`.

---

# 6. SKEPTICAL VALIDATION ENGINE: THE 15 CHECKS

The validator (`finsec/validation/validator.py`) evaluates 15 deterministic checks before allowing a report to be generated:

1. `SCOPE-ENDPOINTS`: Every target endpoint host matches in-scope host patterns.
2. `PLAN-APPROVAL`: Plan is `READY_FOR_REVIEW` with valid checksum approval.
3. `EVIDENCE-FILES`: Required request/response evidence artifacts exist on disk.
4. `EVIDENCE-INTEGRITY`: Artifact SHA-256 hashes match stored metadata.
5. `STATE-EVIDENCE`: State-changing endpoints contain valid `before.json` and `after.json` artifacts.
6. `CONTROLLED-ACCOUNTS`: All accounts involved are explicitly configured researcher accounts.
7. `BOUNDARY`: Response evidence demonstrates distinct ownership/tenant boundary signals.
8. `SECURE-CONTROL`: Expected secure rejection (e.g. 403 Forbidden) is verified.
9. `ATTACKER-GAIN`: Demonstrated unauthorized resource access or state change.
10. `ACTUAL-BEHAVIOR`: Direct HTTP server verification (not client-side mock).
11. `AUTHORITATIVE-RESULT`: Evidence derived from authoritative API response.
12. `NEGATIVE-CONTROL`: Negative control baseline executed and verified.
13. `CLEAN-SESSION`: Behavior verified in clean, unpolluted session.
14. `ALTERNATIVES`: Researcher has explicitly ruled out alternative causes (caching, UI race conditions).
15. `SERVER-BOUNDARY`: Issue is a server-side enforcement flaw, not client-side-only rendering.

---

# 7. COMPLETE CLI USER MANUAL & COMMAND REFERENCE

| Command | Arguments / Flags | Purpose |
|---|---|---|
| `hunt setup` | `--name`, `--slug`, `--host`, `--account`, `--yes` | Interactive/non-interactive workspace setup wizard. |
| `hunt ingest` | `<file.har> -w <workspace> --actor <actor> --channel <channel> [--capture-auth]` | Ingest HAR capture with optional credential extraction. |
| `hunt ingest-burp` | `<file.xml> -w <workspace> --actor <actor> --channel <channel> [--capture-auth]` | Ingest Burp XML history file. |
| `hunt ingest-caido` | `<file.json> -w <workspace> --actor <actor> --channel <channel>` | Ingest Caido JSON export. |
| `hunt ingest-openapi` | `<file.yaml> -w <workspace> [--base-url <url>]` | Ingest OpenAPI specification document. |
| `hunt ingest-wizard` | `-w <workspace>` | Interactive wizard to assign actor/channel to incoming captures. |
| `hunt workflow` | `-w <workspace> [--manifest <path>] [--no-ingest]` | Run full passive offline analysis pipeline. |
| `hunt classify` | `-w <workspace>` | Display endpoint classification inventory. |
| `hunt noise` | `-w <workspace>` | Display suppressed static, telemetry, & third-party endpoints. |
| `hunt hypotheses` | `-w <workspace> [--priority P1] [--research-tasks]` | List active hypotheses & research tasks. |
| `hunt explain` | `<EP-xxx|HYP-xxx> -w <workspace>` | Display full provenance & details for entity. |
| `hunt plan` | `<HYP-xxx> -w <workspace>` | Draft structured test plan for hypothesis. |
| `hunt approve` | `<HYP-xxx> -w <workspace> --approved-by <name>` | Record checksum-bound human approval. |
| `hunt execute` | `<HYP-xxx> -w <workspace> [--dry-run]` | Execute read-only test plan over network. |
| `hunt evidence` | `<HYP-xxx> -w <workspace> [--add <file> --kind <kind>]` | Manage evidence artifacts for hypothesis. |
| `hunt validate` | `<HYP-xxx> -w <workspace>` | Run 15 skeptical validation checks. |
| `hunt report` | `<HYP-xxx> -w <workspace>` | Render versioned Markdown report. |
| `hunt workspace delete` | `-w <workspace> [--purge] [--confirm <slug>]` | Safely delete or purge workspace & data. |

---

# 8. LOCAL WEB COCKPIT ARCHITECTURE (`hunt web`)

The FinSec Hunt Web UI (`finsec/web/`) provides a browser-based research cockpit:

```bash
hunt web --workspace-root workspaces --capture-root captures
```

- **Loopback Binding**: Listens exclusively on `127.0.0.1:8765`.
- **Zero Credentials in UI**: Raw tokens, secrets, cookies, and raw request bodies are never served to the browser.
- **CSRF & Traversal Protection**: State-changing endpoints require custom headers. Workspace deletion requires path containment checks (`is_relative_to(workspace_root)`) and exact string confirmation.

---

# 9. MODEL CONTEXT PROTOCOL (MCP) SERVER (`hunt-mcp`)

FinSec Hunt includes an official stdio MCP server (`finsec/mcp/`) allowing AI assistants (such as Claude Code) to inspect sanitized research state:

```bash
FINSEC_HUNT_WORKSPACE=/absolute/path/to/workspace \
FINSEC_HUNT_IMPORT_ROOT=/absolute/path/to/captures \
  hunt-mcp
```

### Exposed MCP Tools
- `hunt_setup_workspace`: Create workspace with explicit scope and accounts.
- `hunt_ingest_har`: Import HAR capture from import root.
- `hunt_generate_hypotheses`: Run passive offline analysis workflow.
- `hunt_workspace_summary`: Summarize target policies and counts.
- `hunt_list_hypotheses`: List active hypotheses and research tasks.
- `hunt_get_hypothesis_context`: Retrieve sanitized context for `HYP-xxx`.
- `hunt_get_evidence_summary`: Retrieve evidence checklist & validation status.

---

# 10. DEVELOPER GUIDE & MAINTENANCE

### 10.1 Environment Setup
```bash
./install.sh --dev
source .venv/bin/activate
```

### 10.2 Code Style & Linting Standards
- Line length: 100 characters.
- Format & Lint: `ruff check .` and `ruff format --check .`
- Type checking: `mypy finsec` (strict mode).

### 10.3 Running Tests
```bash
.venv/bin/pytest
```

### 10.4 Synthetic Validation Harness
Run isolated end-to-end integration tests using synthetic traffic fixtures:
```bash
./scripts/run_synthetic_validation.sh
```

---

# 11. TROUBLESHOOTING & EDGE CASE RESOLUTION

1. **`No workflow manifest was found`**: Create `captures/<slug>/workflow.yaml` or run `hunt workflow --no-ingest`.
2. **`Execution refused: plan does not have complete approval record`**: Run `hunt plan HYP-xxx` followed by `hunt approve HYP-xxx`.
3. **`Preserved researcher-edited records`**: Standard behavior when regenerated pipeline data encounters custom human edits.
4. **`AttributeError: 'Endpoint' object has no attribute 'channel'`**: Fixed in v0.5.0 (`endpoint.channels` list is used).

---
*Manual compiled for FinSec Hunt v0.5.0.*
