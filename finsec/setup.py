"""Interactive, safety-first workspace setup orchestration."""

from __future__ import annotations

import difflib
import ipaddress
import os
import re
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from finsec.auth.capture import detect_har_authentication
from finsec.auth.service import (
    capture_from_har,
    capture_from_raw_request,
    ensure_authentication_defaults,
    set_manual_authentication,
)
from finsec.config.models import (
    AccountAttributes,
    AccountConfig,
    AnalysisConfig,
    HypothesisGateConfig,
    RestrictionsConfig,
    ScopeConfig,
    SuppressionConfig,
    TargetDocument,
    TargetIdentity,
    TestingConfig,
)
from finsec.config.scope import host_is_covered
from finsec.config.workspace import WorkspacePaths, create_workspace, validate_target_name
from finsec.errors import FinsecError, WorkspaceError
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.workflow import ensure_workflow_manifest

ACCOUNT_LABEL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
FOCUS_AREAS = (
    "authorization",
    "authentication",
    "business_logic",
    "financial_workflows",
    "state_transitions",
    "replay_and_idempotency",
    "api_version_differences",
    "channel_differences",
)
DEFAULT_FOCUS = list(FOCUS_AREAS[:4])
GITIGNORE_ENTRIES = (
    "captures/",
    "workspaces/*/observations/raw/",
    "workspaces/.finsec-secrets/",
    ".finsec-secrets/",
    "*.har",
)


@dataclass(frozen=True)
class AccountInput:
    """Non-sensitive account information collected by the wizard."""

    label: str
    role: str = "user"
    authenticated: bool = True
    verification_level: str = "unknown"
    channel: Literal["web", "mobile", "api", "unknown"] = "web"
    tier: str | None = None
    merchant_customer_role: str | None = None
    notes: str | None = None

    def to_config(self) -> AccountConfig:
        """Convert wizard input into the validated target account model."""

        actor_type = (
            "anonymous"
            if not self.authenticated
            else "privileged_user"
            if self.role.lower() in {"admin", "administrator", "privileged", "staff"}
            else "authenticated_user"
        )
        return AccountConfig(
            id=self.label,
            ownership="researcher",
            role=self.role,
            authenticated=self.authenticated,
            actor_type=cast(Any, actor_type),
            attributes=AccountAttributes(
                verification_level=self.verification_level,
                channel=self.channel,
                tier=self.tier,
                merchant_customer_role=self.merchant_customer_role,
                notes=self.notes,
            ),
        )


@dataclass(frozen=True)
class SetupConfig:
    """Complete validated configuration awaiting user confirmation."""

    target: TargetDocument
    capture_relative: Path

    @property
    def slug(self) -> str:
        """Return the required path-safe slug."""

        slug = self.target.target.slug
        if slug is None:
            raise WorkspaceError("Setup configuration is missing a workspace slug.")
        return slug


@dataclass(frozen=True)
class SetupResult:
    """Paths created by a completed setup."""

    workspace: WorkspacePaths
    capture_root: Path


def slugify_project_name(name: str) -> str:
    """Create a conservative editable slug suggestion from a display name."""

    lowered = name.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return slug[:64].rstrip("-")


def validate_project_name(name: str) -> str:
    """Reject empty display names and control characters."""

    normalized = " ".join(name.strip().split())
    if not normalized:
        raise FinsecError("Project name cannot be empty.")
    if len(normalized) > 100 or any(ord(character) < 32 for character in normalized):
        raise FinsecError("Project name must be 1-100 printable characters.")
    return normalized


def validate_slug(value: str) -> str:
    """Validate the slug through the existing workspace path rules."""

    return validate_target_name(value)


def _credential_reason(value: str) -> str | None:
    lowered = value.lower()
    words = set(re.findall(r"[a-z0-9]+", lowered.replace("_", " ")))
    credential_words = {
        "bearer",
        "cookie",
        "jwt",
        "otp",
        "password",
        "passwd",
        "secret",
        "session",
        "token",
    }
    if words & credential_words or "apikey" in words or {"api", "key"}.issubset(words):
        return "credential-related text"
    if re.search(
        r"\b(bearer|password|passwd|cookie|session|api[_ -]?key|secret|otp|jwt)\b", lowered
    ):
        return "credential-related text"
    if re.search(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", value):
        return "a JWT"
    if re.search(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        return "an email address"
    if re.fullmatch(r"\+?[0-9][0-9() -]{7,}[0-9]", value.strip()):
        return "a phone number or OTP-like numeric value"
    compact = re.sub(r"[^A-Za-z0-9]", "", value)
    if len(compact) >= 32 and re.fullmatch(r"[A-Za-z0-9]+", compact):
        return "a long token-like value"
    return None


def validate_account_label(value: str) -> str:
    """Validate a unique non-secret actor label."""

    normalized = value.strip()
    if reason := _credential_reason(normalized):
        raise FinsecError(f"Account labels cannot contain {reason}.")
    if not ACCOUNT_LABEL_PATTERN.fullmatch(normalized):
        raise FinsecError(
            "Account labels must start with a letter and use only letters, digits, '_' or '-'."
        )
    return normalized


def validate_account_metadata(value: str, field_name: str) -> str:
    """Reject secrets and identifiers from optional account metadata."""

    normalized = " ".join(value.strip().split())
    if reason := _credential_reason(normalized):
        raise FinsecError(f"{field_name} cannot contain {reason}.")
    if (
        not normalized
        or len(normalized) > 200
        or any(ord(character) < 32 for character in normalized)
    ):
        raise FinsecError(f"{field_name} must be 1-200 printable characters.")
    return normalized


def _hostname_from_input(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise FinsecError("Host cannot be empty.")
    if "@" in cleaned or any(character.isspace() for character in cleaned):
        raise FinsecError("Host must not contain credentials or whitespace.")
    parsed = urlsplit(cleaned if "://" in cleaned else f"//{cleaned}")
    try:
        port = parsed.port
    except ValueError as error:
        raise FinsecError(f"Invalid host or port: {value}") from error
    del port
    hostname = parsed.hostname
    if hostname is None:
        raise FinsecError(f"Invalid hostname: {value}")
    return hostname.lower().rstrip(".")


def normalize_host(value: str, *, allow_localhost: bool = False) -> str:
    """Normalize an exact or leading-wildcard hostname without broadening it."""

    hostname = _hostname_from_input(value)
    wildcard = hostname.startswith("*.")
    base = hostname[2:] if wildcard else hostname
    if not base or "/" in base or ".." in base:
        raise FinsecError(f"Invalid hostname: {value}")
    if base == "localhost" or base.endswith(".localhost"):
        if not allow_localhost:
            raise FinsecError(
                "localhost is allowed only for an explicit synthetic/local workspace."
            )
        return hostname
    if "/" in value and "://" not in value:
        # urlsplit safely discards a path from scheme-less input; CIDR notation must not pass.
        suffix = value.strip().split("/", 1)[1]
        if suffix.isdigit():
            try:
                ipaddress.ip_network(value.strip(), strict=False)
            except ValueError:
                pass
            else:
                raise FinsecError("IP ranges are not supported as scope hosts.")
    try:
        ipaddress.ip_address(base)
    except ValueError:
        pass
    else:
        raise FinsecError("IP addresses are not supported as scope hosts.")
    labels = base.split(".")
    if (
        len(base) > 253
        or len(labels) < 2
        or any(not HOST_LABEL_PATTERN.fullmatch(label) for label in labels)
    ):
        raise FinsecError(f"Invalid hostname: {value}")
    return f"*.{base}" if wildcard else base


def normalize_hosts(values: list[str], *, allow_localhost: bool = False) -> list[str]:
    """Normalize, de-duplicate, and require one or more hosts."""

    normalized: list[str] = []
    for value in values:
        host = normalize_host(value, allow_localhost=allow_localhost)
        if host not in normalized:
            normalized.append(host)
    if not normalized:
        raise FinsecError("At least one in-scope host is required.")
    return normalized


def validate_capture_relative(value: str) -> Path:
    """Keep an advanced capture location underneath the configured capture root."""

    path = Path(value.strip())
    if not value.strip() or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise FinsecError("Capture directory must be a relative path without '.' or '..'.")
    if any(not part or part in {os.sep, os.altsep} for part in path.parts):
        raise FinsecError("Invalid capture directory.")
    return path


def build_setup_config(
    *,
    project_name: str,
    slug: str,
    hosts: list[str],
    accounts: list[AccountInput],
    production: bool,
    analysis: AnalysisConfig | None = None,
    focus: list[str] | None = None,
    capture_relative: Path | None = None,
    target_type: str = "web_api",
    base_url: str | None = None,
) -> SetupConfig:
    """Build and immediately validate the complete target document."""

    display_name = validate_project_name(project_name)
    safe_slug = validate_slug(slug)
    safe_hosts = normalize_hosts(hosts, allow_localhost=not production)
    labels = [validate_account_label(account.label) for account in accounts]
    if not labels:
        raise FinsecError("At least one researcher-owned test account is required.")
    if len(set(labels)) != len(labels):
        raise FinsecError("Account labels must be unique.")
    for account in accounts:
        validate_account_metadata(account.role, "Role")
        validate_account_metadata(account.verification_level, "Verification level")
        for field_name, value in (
            ("Account tier", account.tier),
            ("Merchant/customer role", account.merchant_customer_role),
            ("Notes", account.notes),
        ):
            if value is not None:
                validate_account_metadata(value, field_name)
        if account.channel not in {"web", "mobile", "api", "unknown"}:
            raise FinsecError(f"Unsupported account channel: {account.channel}")
    account_configs = [account.to_config() for account in accounts]
    selected_analysis = analysis or AnalysisConfig(include_hosts=safe_hosts)
    if not selected_analysis.include_hosts:
        selected_analysis = selected_analysis.model_copy(update={"include_hosts": safe_hosts})
    selected_focus = focus or DEFAULT_FOCUS
    unsupported = sorted(set(selected_focus) - set(FOCUS_AREAS))
    if unsupported:
        raise FinsecError(f"Unsupported analysis focus: {', '.join(unsupported)}")
    selected_base_url = base_url or (f"{'https' if production else 'http'}://{safe_hosts[0]}")
    parsed_base = urlsplit(selected_base_url)
    if (
        parsed_base.scheme not in {"http", "https"}
        or parsed_base.hostname is None
        or parsed_base.username is not None
        or parsed_base.password is not None
        or not host_is_covered(
            normalize_host(parsed_base.hostname, allow_localhost=not production), safe_hosts
        )
    ):
        raise FinsecError("Target base URL must use HTTP(S) and an explicitly scoped host.")
    document = TargetDocument(
        target=TargetIdentity(
            name=display_name,
            slug=safe_slug,
            type=target_type,
            base_url=selected_base_url.rstrip("/"),
        ),
        scope=ScopeConfig(hosts=safe_hosts),
        accounts=account_configs,
        testing=TestingConfig(
            production=production,
            synthetic=not production,
            local_lab=not production,
            human_approval_required=True,
            destructive_testing=False,
            active_execution_enabled=False,
            maximum_parallel_requests=1,
            maximum_requests_per_plan=3,
            read_only_only=True,
        ),
        restrictions=RestrictionsConfig(),
        analysis=selected_analysis,
        focus=selected_focus,
    )
    validated = TargetDocument.model_validate(document.model_dump(mode="json"))
    ensure_authentication_defaults(validated)
    return SetupConfig(validated, capture_relative or Path(safe_slug))


def _safe_child(root: Path, relative: Path) -> Path:
    resolved_root = root.expanduser().resolve()
    candidate = (resolved_root / relative).resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError as error:
        raise WorkspaceError(f"Path escapes configured root: {candidate}") from error
    return candidate


def _scope_documents(config: SetupConfig) -> dict[str, str]:
    hosts = "\n".join(f"- {host}" for host in config.target.scope.hosts)
    program = (
        "# Program Information\n\n"
        f"Program name: {config.target.target.name}\n\n"
        "Program URL:\nNot recorded.\n\n"
        "Bug bounty platform:\nNot recorded.\n\n"
        f"Last scope review:\n{date.today().isoformat()}\n\n"
        "Notes:\nAdd the official program rules before testing.\n"
    )
    scope = (
        "# In-Scope Assets\n\n"
        f"{hosts}\n\n"
        "## Out-of-Scope Assets\n\n"
        "Not recorded.\n\n"
        "## Notes\n\n"
        "Confirm the official scope before active testing.\n"
    )
    restrictions = (
        "# Testing Restrictions\n\n"
        "- No denial-of-service testing\n"
        "- No brute-force testing\n"
        "- No social engineering\n"
        "- No spam\n"
        "- No destructive actions\n"
        "- No testing of unrelated user accounts\n"
        "- Use only researcher-owned accounts\n"
        "- Human approval is required before active tests\n"
    )
    return {
        "scope/program.md": program,
        "scope/scope.md": scope,
        "scope/restrictions.md": restrictions,
    }


def _capture_readme() -> str:
    return (
        "# Session Capture Directory\n\n"
        "Place authorized HAR or Burp XML files in `incoming/`; originals stay outside the "
        "workspace.\n\n"
        "Recommended structure:\n\n"
        "- `01-account-a-login.har`\n"
        "- `02-account-a-create-dns.har`\n"
        "- `03-account-b-create-dns.xml`\n"
        "- `04-account-b-probe-account-a-dns.har`\n\n"
        "Recommended capture rules:\n\n"
        "- One controlled actor per capture\n"
        "- One primary business journey per capture\n"
        "- Record normal behavior before security probes\n"
        "- Keep researcher probes separate from baseline traffic\n"
        "- Prefer Fetch/XHR traffic\n"
        "- Broad captures are accepted but produce quality warnings\n"
        "- Remove personal data and review unrelated traffic\n"
        "- Do not commit capture files\n"
        "- Keep credential-bearing originals outside the repository\n"
        "- Review files before ingestion\n\n"
        "Actor, capture mode, high-level intent, and channel are security-relevant metadata. "
        "Correcting an assignment and rerunning keeps stable observation IDs while refreshing "
        "those labels.\n\n"
        "`workflow.yaml` starts with `captures: []` because the tool cannot safely infer an actor "
        "or trust a filename as capture intent. Assign and import new files with:\n\n"
        "```bash\n"
        "hunt ingest-wizard --workspace workspaces/<slug>\n"
        "```\n\n"
        "The wizard proposes actor, mode, and intent from credential-free HTTP structure, asks "
        "only for missing confirmation, can update authentication from a reviewed candidate, and "
        "offers to run the passive offline workflow. It never sends target requests.\n"
    )


def _write_capture_layout(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(_capture_readme(), encoding="utf-8", newline="\n")
    ensure_workflow_manifest(root / "workflow.yaml")


def _project_root(workspace_root: Path, capture_root: Path) -> Path:
    del capture_root
    return workspace_root.expanduser().resolve().parent


def _gitignore_covers(lines: list[str], entry: str) -> bool:
    stripped = {line.strip() for line in lines}
    if entry == "workspaces/*/observations/raw/":
        return bool(
            stripped
            & {
                "workspaces/*/observations/raw/",
                "workspaces/*/observations/raw/*",
            }
        )
    return entry in stripped


def update_gitignore(path: Path) -> None:
    """Append sensitive artifact ignores without removing or duplicating entries."""

    existing = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    additions = [entry for entry in GITIGNORE_ENTRIES if not _gitignore_covers(existing, entry)]
    if not additions:
        return
    lines = list(existing)
    if lines and lines[-1]:
        lines.append("")
    lines.extend(additions)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def create_setup_workspace(
    config: SetupConfig, workspace_root: Path, capture_root: Path
) -> SetupResult:
    """Create a configured workspace through the existing factory and atomic staging."""

    resolved_workspace_root = workspace_root.expanduser().resolve()
    resolved_capture_root = capture_root.expanduser().resolve()
    final_workspace = _safe_child(resolved_workspace_root, Path(config.slug))
    final_capture = _safe_child(resolved_capture_root, config.capture_relative)
    if final_workspace.exists():
        raise WorkspaceError(f"Workspace already exists: {final_workspace}")

    token = uuid.uuid4().hex
    workspace_stage_root = resolved_workspace_root / f".finsec-setup-{token}"
    capture_stage = resolved_capture_root / f".finsec-setup-{token}"
    staged_workspace: Path | None = None
    capture_was_staged = not final_capture.exists()
    moved_workspace = False
    moved_capture = False
    try:
        staged = create_workspace(config.slug, workspace_stage_root)
        staged_workspace = staged.root
        write_yaml(staged.target, config.target.model_dump(mode="json", exclude_none=True))
        TargetDocument.model_validate(load_yaml(staged.target))
        for relative, content in _scope_documents(config).items():
            (staged.root / relative).write_text(content, encoding="utf-8", newline="\n")
        if capture_was_staged:
            _write_capture_layout(capture_stage)

        resolved_workspace_root.mkdir(parents=True, exist_ok=True)
        final_workspace.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged.root, final_workspace)
        moved_workspace = True
        if capture_was_staged:
            final_capture.parent.mkdir(parents=True, exist_ok=True)
            os.replace(capture_stage, final_capture)
            moved_capture = True
        else:
            _write_capture_layout(final_capture)
        update_gitignore(_project_root(workspace_root, capture_root) / ".gitignore")
    except Exception:
        if moved_workspace and final_workspace.exists():
            shutil.rmtree(final_workspace)
        if moved_capture and final_capture.exists():
            shutil.rmtree(final_capture)
        raise
    finally:
        if staged_workspace is not None and workspace_stage_root.exists():
            shutil.rmtree(workspace_stage_root)
        if capture_stage.exists():
            shutil.rmtree(capture_stage)

    paths = WorkspacePaths(final_workspace)
    TargetDocument.model_validate(load_yaml(paths.target))
    return SetupResult(paths, final_capture)


def _yaml_text(document: TargetDocument) -> str:
    return yaml.safe_dump(
        document.model_dump(mode="json", exclude_none=True),
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )


def update_existing_workspace(
    console: Console,
    config: SetupConfig,
    workspace: WorkspacePaths,
    capture_root: Path,
    *,
    assume_yes: bool = False,
) -> SetupResult | None:
    """Diff and back up target.yaml before an explicit configuration update."""

    current = workspace.target.read_text(encoding="utf-8")
    proposed = _yaml_text(config.target)
    diff = "".join(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            proposed.splitlines(keepends=True),
            fromfile="target.yaml (current)",
            tofile="target.yaml (proposed)",
        )
    )
    if not diff:
        console.print("No target.yaml changes are required.")
    else:
        console.print("\n[bold]Proposed target.yaml diff[/bold]")
        console.print(diff, markup=False)
        if not assume_yes and not typer.confirm("Apply this update?", default=False):
            console.print("Update cancelled; the existing workspace was not modified.")
            return None
        timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        backup = workspace.target.with_name(f"target.yaml.backup-{timestamp}")
        sequence = 2
        while backup.exists():
            backup = workspace.target.with_name(f"target.yaml.backup-{timestamp}-{sequence}")
            sequence += 1
        shutil.copy2(workspace.target, backup)
        write_yaml(workspace.target, config.target.model_dump(mode="json", exclude_none=True))
        console.print(f"Backup created: {backup}")

    capture = _safe_child(capture_root.expanduser().resolve(), config.capture_relative)
    _write_capture_layout(capture)
    update_gitignore(_project_root(workspace.root.parent, capture_root) / ".gitignore")
    return SetupResult(workspace, capture)


def _prompt_text(label: str, *, default: str | None = None) -> str:
    return str(typer.prompt(label, default=default, show_default=default is not None))


def _prompt_validated(label: str, validator: Any, *, default: str | None = None) -> str:
    while True:
        try:
            return cast(str, validator(_prompt_text(label, default=default)))
        except FinsecError as error:
            typer.echo(f"Error: {error}")


def _prompt_integer(
    label: str, *, default: int, minimum: int = 0, maximum: int | None = None
) -> int:
    while True:
        value = typer.prompt(label, default=default, type=int)
        if value >= minimum and (maximum is None or value <= maximum):
            return int(value)
        if maximum is None:
            typer.echo(f"Error: value must be at least {minimum}.")
        else:
            typer.echo(f"Error: value must be between {minimum} and {maximum}.")


def _collect_hosts(
    console: Console, *, production: bool, current: list[str] | None = None
) -> list[str]:
    if current:
        console.print("Current scope hosts: " + ", ".join(current), markup=False)
        if not typer.confirm("Replace the current scope hosts?", default=False):
            return current
    console.print("\nEnter in-scope hosts, one per line. Submit an empty line when finished.")
    values: list[str] = []
    while True:
        value = _prompt_text("Host", default="")
        if not value.strip():
            break
        try:
            normalized = normalize_host(value, allow_localhost=not production)
        except FinsecError as error:
            console.print(f"[red]Error:[/red] {error}")
            continue
        if normalized not in values:
            values.append(normalized)
    if not values:
        raise FinsecError("At least one in-scope host is required.")
    return values


def _default_account_label(index: int) -> str:
    if index < 26:
        return f"ACCOUNT_{chr(ord('A') + index)}"
    return f"ACCOUNT_{index + 1}"


def _account_from_config(account: AccountConfig) -> AccountInput:
    return AccountInput(
        label=account.id,
        role=account.role,
        authenticated=account.authenticated,
        verification_level=account.attributes.verification_level,
        channel=account.attributes.channel,
        tier=account.attributes.tier,
        merchant_customer_role=account.attributes.merchant_customer_role,
        notes=account.attributes.notes,
    )


def _metadata_validator(field_name: str) -> Any:
    def validate(value: str) -> str:
        return validate_account_metadata(value, field_name)

    return validate


def _collect_accounts(
    console: Console,
    *,
    labels: list[str] | None = None,
    current: list[AccountConfig] | None = None,
) -> list[AccountInput]:
    console.print(
        "\n[bold yellow]Do not enter account credentials or personal data.[/bold yellow]\n"
        "Only use labels and non-sensitive account attributes."
    )
    existing = [_account_from_config(account) for account in current or []]
    if labels is not None:
        count = len(labels)
    else:
        count = _prompt_integer(
            "How many researcher-owned test accounts will be used?",
            default=len(existing) or 2,
            minimum=1,
        )
    if count < 1:
        raise FinsecError("At least one researcher-owned test account is required.")

    accounts: list[AccountInput] = []
    for index in range(count):
        prior = existing[index] if index < len(existing) else None
        proposed_label = labels[index] if labels is not None else None
        label = (
            validate_account_label(proposed_label)
            if proposed_label is not None
            else _prompt_validated(
                f"Account {index + 1} label",
                validate_account_label,
                default=prior.label if prior else _default_account_label(index),
            )
        )
        role = (
            (prior.role if prior else "user")
            if labels is not None
            else _prompt_validated(
                f"Account {index + 1} role",
                _metadata_validator("Role"),
                default=prior.role if prior else "user",
            )
        )
        authenticated = (
            (prior.authenticated if prior else True)
            if labels is not None
            else typer.confirm(
                f"Account {index + 1} authenticated?",
                default=prior.authenticated if prior else True,
            )
        )
        verification = (
            (prior.verification_level if prior else "unknown")
            if labels is not None
            else _prompt_validated(
                f"Account {index + 1} verification level",
                _metadata_validator("Verification level"),
                default=prior.verification_level if prior else "unknown",
            )
        )
        default_channel = prior.channel if prior else "web"
        if labels is not None:
            channel = prior.channel if prior else "web"
        else:
            while True:
                channel_value = _prompt_text(
                    f"Account {index + 1} channel (web/mobile/api/unknown)",
                    default=default_channel,
                ).lower()
                if channel_value in {"web", "mobile", "api", "unknown"}:
                    channel = cast(Literal["web", "mobile", "api", "unknown"], channel_value)
                    break
                console.print("[red]Error:[/red] Unsupported account channel.")
        accounts.append(
            AccountInput(
                label=label,
                role=role,
                authenticated=authenticated,
                verification_level=verification,
                channel=channel,
                tier=prior.tier if prior else None,
                merchant_customer_role=prior.merchant_customer_role if prior else None,
                notes=prior.notes if prior else None,
            )
        )
    labels_seen = [account.label for account in accounts]
    if len(labels_seen) != len(set(labels_seen)):
        raise FinsecError("Account labels must be unique.")
    return accounts


def _optional_metadata(label: str, current: str | None = None) -> str | None:
    while True:
        value = _prompt_text(label, default=current or "").strip()
        if not value:
            return None
        try:
            return validate_account_metadata(value, label)
        except FinsecError as error:
            typer.echo(f"Error: {error}")


def _comma_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _collect_advanced(
    console: Console,
    *,
    hosts: list[str],
    accounts: list[AccountInput],
    production: bool,
    current: TargetDocument | None,
    slug: str,
) -> tuple[AnalysisConfig, list[str], list[AccountInput], Path]:
    base = current.analysis.model_copy(deep=True) if current else AnalysisConfig()
    scoped_set = set(hosts)
    previous_scope = set(current.scope.hosts) if current else scoped_set
    existing_additional = [host for host in base.include_hosts if host not in previous_scope]
    included_raw = _prompt_text(
        "Additional included hosts (comma-separated)", default=", ".join(existing_additional)
    )
    excluded_raw = _prompt_text(
        "Excluded hosts (comma-separated)", default=", ".join(base.exclude_hosts)
    )
    additional = [
        normalize_host(value, allow_localhost=not production)
        for value in _comma_values(included_raw)
    ]
    excluded = [
        normalize_host(value, allow_localhost=not production)
        for value in _comma_values(excluded_raw)
    ]

    console.print("\n[bold]Noise suppression[/bold]")
    suppress = SuppressionConfig(
        static_assets=typer.confirm("Suppress static assets?", default=base.suppress.static_assets),
        telemetry=typer.confirm("Suppress telemetry?", default=base.suppress.telemetry),
        analytics=typer.confirm("Suppress analytics?", default=base.suppress.analytics),
        third_party=typer.confirm(
            "Suppress third-party traffic?", default=base.suppress.third_party
        ),
    )

    console.print("Current excluded path patterns:")
    console.print("\n".join(f"- {item}" for item in base.excluded_path_patterns), markup=False)
    added_paths = _comma_values(
        _prompt_text("Additional excluded path patterns (comma-separated)", default="")
    )
    console.print("Current excluded extensions:")
    console.print(", ".join(base.excluded_extensions), markup=False)
    added_extensions = [
        value.lower().lstrip(".")
        for value in _comma_values(
            _prompt_text("Additional excluded extensions (comma-separated)", default="")
        )
    ]

    enriched_accounts = accounts
    if typer.confirm("Configure advanced account attributes?", default=False):
        enriched_accounts = []
        for account in accounts:
            console.print(f"\n[bold]{account.label}[/bold]")
            enriched_accounts.append(
                replace(
                    account,
                    tier=_optional_metadata("Account tier", account.tier),
                    merchant_customer_role=_optional_metadata(
                        "Merchant/customer role", account.merchant_customer_role
                    ),
                    notes=_optional_metadata("Notes", account.notes),
                )
            )

    console.print(
        "\nSafety restrictions remain prohibited: denial of service, brute force, "
        "social engineering, spam, destructive actions, and unrelated-user testing."
    )
    selected_focus = list(current.focus if current else DEFAULT_FOCUS)

    console.print("\n[bold]Current hypothesis gates[/bold]")
    gates = HypothesisGateConfig(
        bola_minimum_score=_prompt_integer(
            "BOLA minimum score",
            default=base.hypothesis_gates.bola_minimum_score,
            maximum=10,
        ),
        state_transition_minimum_score=_prompt_integer(
            "State-transition minimum score",
            default=base.hypothesis_gates.state_transition_minimum_score,
            maximum=10,
        ),
        financial_minimum_score=_prompt_integer(
            "Financial minimum score",
            default=base.hypothesis_gates.financial_minimum_score,
            maximum=10,
        ),
    )
    capture_relative = validate_capture_relative(
        _prompt_text("Capture directory under the configured capture root", default=slug)
    )
    analysis = AnalysisConfig(
        include_hosts=list(dict.fromkeys([*hosts, *additional])),
        exclude_hosts=list(dict.fromkeys(excluded)),
        suppress=suppress,
        excluded_extensions=list(dict.fromkeys([*base.excluded_extensions, *added_extensions])),
        excluded_path_patterns=list(dict.fromkeys([*base.excluded_path_patterns, *added_paths])),
        hypothesis_gates=gates,
        ownership_inference=base.ownership_inference,
        function_authorization_rules=base.function_authorization_rules,
        jwt_algorithm_rules=base.jwt_algorithm_rules,
        classification_overrides=base.classification_overrides,
    )
    return analysis, selected_focus, enriched_accounts, capture_relative


def _print_summary(
    console: Console, config: SetupConfig, workspace_root: Path, capture_root: Path
) -> None:
    workspace = _safe_child(workspace_root.expanduser().resolve(), Path(config.slug))
    capture = _safe_child(capture_root.expanduser().resolve(), config.capture_relative)
    console.print("\n[bold]Workspace summary[/bold]")
    table = Table(show_header=False, box=None, pad_edge=False)
    rows = [
        ("Project", config.target.target.name),
        ("Slug", config.slug),
        ("Workspace", str(workspace)),
        ("Capture input", str(capture / "incoming")),
        ("Scope hosts", ", ".join(config.target.scope.hosts)),
        ("Target URL", config.target.target.base_url or "not configured"),
        (
            "Accounts",
            "; ".join(
                f"{account.id} - {account.role} - "
                f"{'authenticated' if account.authenticated else 'unauthenticated'} - "
                f"{account.attributes.verification_level} - {account.attributes.channel}"
                for account in config.target.accounts
            ),
        ),
        ("Production", "yes" if config.target.testing.production else "no (synthetic)"),
        ("Bounded execution", "disabled by default"),
        ("Human approval", "required"),
        ("Destructive testing", "disabled"),
        ("Maximum parallel requests", "1"),
        ("Maximum requests per approved plan", "3"),
        ("Unsafe test categories", "all prohibited"),
    ]
    for label, value in rows:
        table.add_row(label, value)
    console.print(table)
    suppress = config.target.analysis.suppress
    console.print("\n[bold]Analysis[/bold]")
    for label, enabled in (
        ("Static suppression", suppress.static_assets),
        ("Telemetry suppression", suppress.telemetry),
        ("Analytics suppression", suppress.analytics),
        ("Third-party suppression", suppress.third_party),
    ):
        console.print(f"{label}: {'enabled' if enabled else 'disabled'}")
    console.print("Included hosts: " + ", ".join(config.target.analysis.include_hosts))
    console.print("Excluded hosts: " + (", ".join(config.target.analysis.exclude_hosts) or "none"))
    console.print("Excluded extensions: " + ", ".join(config.target.analysis.excluded_extensions))
    console.print(
        "Excluded path patterns: " + ", ".join(config.target.analysis.excluded_path_patterns)
    )
    gates = config.target.analysis.hypothesis_gates
    console.print(
        "Hypothesis gates: "
        f"BOLA {gates.bola_minimum_score}, "
        f"state transition {gates.state_transition_minimum_score}, "
        f"financial {gates.financial_minimum_score}"
    )


def _existing_action(console: Console, workspace: Path, *, assume_yes: bool) -> str:
    if assume_yes:
        raise WorkspaceError(f"Workspace already exists: {workspace}")
    console.print(f"\n[yellow]Workspace already exists:[/yellow] {workspace}")
    console.print("1. Abort")
    console.print("2. Show existing configuration")
    console.print("3. Add missing capture directories only")
    console.print("4. Update configuration interactively")
    console.print("5. Resume onboarding (ingestion, then actor authentication)")
    while True:
        choice = _prompt_text("Choose an action", default="1")
        if choice in {"1", "2", "3", "4", "5"}:
            return choice
        console.print("[red]Error:[/red] Choose 1, 2, 3, 4, or 5.")


def _run_onboarding_steps(
    console: Console,
    result: SetupResult,
    ingest_captures: Callable[[SetupResult], None] | None,
) -> None:
    """Run interactive onboarding stages in their required order."""

    if ingest_captures is not None:
        ingest_captures(result)
    target = TargetDocument.model_validate(load_yaml(result.workspace.target))
    authenticated = [
        actor
        for actor in target.accounts
        if actor.authenticated and actor.actor_type != "anonymous"
    ]
    pending = [
        actor
        for actor in authenticated
        if actor.authentication is None or actor.authentication.status != "READY"
    ]
    if not authenticated:
        console.print("No actor authentication configuration is required.")
        return
    if not pending:
        console.print("[green]Actor authentication is READY for all authenticated actors.[/green]")
        return
    prompt = (
        "Configure remaining actor authentication now?"
        if len(pending) < len(authenticated)
        else "Configure actor authentication now?"
    )
    if typer.confirm(prompt, default=False):
        _configure_actor_authentication(console, result, {actor.id for actor in pending})


def _print_completion(console: Console, result: SetupResult) -> None:
    workspace = result.workspace.root
    incoming = result.capture_root / "incoming"
    console.print("\n[bold green]Workspace setup completed.[/bold green]")
    console.print(f"\nWorkspace:\n{workspace}")
    console.print(f"\nCapture input directory:\n{incoming}")
    console.print(
        "\nRecommended naming:\n\n"
        "01-account-a-login.har\n"
        "02-account-a-create-dns.har\n"
        "03-account-b-create-dns.xml"
    )
    console.print(
        "\nNext steps:\n\n"
        "1. Export one authorized, focused HAR or Burp XML journey and keep the original out of "
        "Git.\n"
        f"2. Place it in {incoming}.\n"
        "3. Setup will offer to assign existing captures or pause while you add and rescan.\n"
        "4. To import files added later, run:\n"
        f"   hunt ingest-wizard --workspace {workspace}\n"
        "5. If the wizard did not run analysis, start the offline workflow:\n"
        f"   hunt workflow --workspace {workspace}\n"
        "6. Review:\n"
        f"   hunt hypotheses --research-tasks --workspace {workspace}"
    )


def run_setup_wizard(
    console: Console,
    *,
    name: str | None,
    slug: str | None,
    hosts: list[str] | None,
    account_labels: list[str] | None,
    workspace_root: Path,
    capture_root: Path,
    assume_yes: bool,
    synthetic: bool,
    base_url: str | None = None,
    anonymous_labels: set[str] | None = None,
    privileged_labels: set[str] | None = None,
    ingest_captures: Callable[[SetupResult], None] | None = None,
) -> SetupResult | None:
    """Collect setup input, preview it, and create only after confirmation."""

    console.print("[bold]FinSec Hunt Workspace Setup[/bold]")
    if assume_yes and name is None:
        raise FinsecError("--name is required with --yes.")
    if assume_yes and not hosts:
        raise FinsecError("At least one --host is required with --yes.")
    if assume_yes and not account_labels:
        raise FinsecError("At least one --account is required with --yes.")
    project_name = (
        validate_project_name(name)
        if name is not None
        else _prompt_validated("Project display name", validate_project_name)
    )
    suggested = slugify_project_name(project_name)
    if not suggested and slug is None:
        raise FinsecError("Project name does not produce a safe slug; enter --slug explicitly.")
    console.print(f"Suggested slug: {suggested}", markup=False)
    if slug is not None:
        workspace_slug = validate_slug(slug)
    elif assume_yes:
        workspace_slug = validate_slug(suggested)
    else:
        workspace_slug = _prompt_validated("Workspace slug", validate_slug, default=suggested)
    workspace_path = _safe_child(workspace_root.expanduser().resolve(), Path(workspace_slug))

    existing_target: TargetDocument | None = None
    existing_action: str | None = None
    if workspace_path.exists():
        existing_action = _existing_action(console, workspace_path, assume_yes=assume_yes)
        if existing_action == "1":
            console.print("Setup aborted; the existing workspace was not modified.")
            return None
        if not (workspace_path / "target.yaml").is_file():
            raise WorkspaceError(f"Existing path is not a FinSec Hunt workspace: {workspace_path}")
        if existing_action == "2":
            console.print(
                (workspace_path / "target.yaml").read_text(encoding="utf-8"), markup=False
            )
            return None
        if existing_action == "3":
            capture = _safe_child(capture_root.expanduser().resolve(), Path(workspace_slug))
            if not typer.confirm("Create missing capture directories?", default=False):
                console.print("No files were changed.")
                return None
            _write_capture_layout(capture)
            update_gitignore(_project_root(workspace_root, capture_root) / ".gitignore")
            console.print(f"Capture directories are ready: {capture}")
            return SetupResult(WorkspacePaths(workspace_path), capture)
        try:
            existing_target = TargetDocument.model_validate(
                load_yaml(workspace_path / "target.yaml")
            )
        except (OSError, ValidationError) as error:
            raise WorkspaceError(f"Cannot update invalid target.yaml: {error}") from error
        if existing_action == "5":
            capture = _safe_child(capture_root.expanduser().resolve(), Path(workspace_slug))
            _write_capture_layout(capture)
            resumed = SetupResult(WorkspacePaths(workspace_path), capture)
            _run_onboarding_steps(console, resumed, ingest_captures)
            return resumed

    if assume_yes:
        production = not synthetic
    elif synthetic:
        production = False
    else:
        production = typer.confirm(
            "Is this a real production bug-bounty target?",
            default=existing_target.testing.production if existing_target else True,
        )

    scope_hosts = (
        normalize_hosts(hosts, allow_localhost=not production)
        if hosts is not None
        else _collect_hosts(
            console,
            production=production,
            current=existing_target.scope.hosts if existing_target else None,
        )
    )
    selected_base_url = base_url or (
        existing_target.target.base_url if existing_target is not None else None
    )
    if not assume_yes and base_url is None:
        default_base_url = selected_base_url or (
            f"{'https' if production else 'http'}://{scope_hosts[0]}"
        )
        selected_base_url = _prompt_text("Target base URL", default=default_base_url)
    accounts = _collect_accounts(
        console,
        labels=account_labels,
        current=existing_target.accounts if existing_target else None,
    )
    anonymous = anonymous_labels or set()
    privileged = privileged_labels or set()
    overlap = anonymous & privileged
    if overlap:
        raise FinsecError(
            "Actor labels cannot be both anonymous and privileged: " + ", ".join(sorted(overlap))
        )
    accounts = [
        replace(account, authenticated=False, role="anonymous")
        if account.label in anonymous
        else replace(account, authenticated=True, role="admin")
        if account.label in privileged
        else account
        for account in accounts
    ]

    configure_advanced = (
        False if assume_yes else typer.confirm("Configure advanced settings?", default=False)
    )
    if configure_advanced:
        analysis, focus, accounts, capture_relative = _collect_advanced(
            console,
            hosts=scope_hosts,
            accounts=accounts,
            production=production,
            current=existing_target,
            slug=workspace_slug,
        )
    else:
        if existing_target:
            analysis = existing_target.analysis.model_copy(deep=True)
            additional = [
                host
                for host in analysis.include_hosts
                if host not in set(existing_target.scope.hosts)
            ]
            analysis.include_hosts = list(dict.fromkeys([*scope_hosts, *additional]))
            focus = existing_target.focus
        else:
            analysis = AnalysisConfig(include_hosts=scope_hosts)
            focus = DEFAULT_FOCUS
        capture_relative = Path(workspace_slug)

    config = build_setup_config(
        project_name=project_name,
        slug=workspace_slug,
        hosts=scope_hosts,
        accounts=accounts,
        production=production,
        analysis=analysis,
        focus=focus,
        capture_relative=capture_relative,
        target_type=existing_target.target.type if existing_target else "web_api",
        base_url=selected_base_url,
    )
    if existing_target is not None:
        existing_by_id = {item.id: item for item in existing_target.accounts}
        for configured_actor in config.target.accounts:
            previous_actor = existing_by_id.get(configured_actor.id)
            if previous_actor is None:
                continue
            configured_actor.actor_type = previous_actor.actor_type or configured_actor.actor_type
            configured_actor.authentication = (
                previous_actor.authentication or configured_actor.authentication
            )
    _print_summary(console, config, workspace_root, capture_root)

    if existing_action == "4":
        result = update_existing_workspace(
            console,
            config,
            WorkspacePaths(workspace_path),
            capture_root,
            assume_yes=assume_yes,
        )
    else:
        if not assume_yes and not typer.confirm(
            "Create workspace with these settings?", default=True
        ):
            console.print("Setup cancelled; no workspace files were created.")
            return None
        result = create_setup_workspace(config, workspace_root, capture_root)

    if result is None:
        return None
    _print_completion(console, result)
    if not assume_yes:
        _run_onboarding_steps(console, result, ingest_captures)
    return result


def _setup_authentication_file(value: str, result: SetupResult) -> Path:
    """Resolve bare filenames from the capture directory advertised by setup."""

    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    direct = path.resolve()
    if direct.is_file() or len(path.parts) != 1:
        return direct
    return (result.capture_root / "incoming" / path.name).resolve()


def _configure_actor_authentication(
    console: Console,
    result: SetupResult,
    actor_ids: set[str] | None = None,
) -> None:
    """Collect one explicit authentication source for each setup actor."""

    target = TargetDocument.model_validate(load_yaml(result.workspace.target))
    for actor in target.accounts:
        if actor_ids is not None and actor.id not in actor_ids:
            continue
        if actor.actor_type == "anonymous" or not actor.authenticated:
            console.print(f"{actor.id}: anonymous authentication is explicitly NONE.")
            continue
        console.print(f"\n[bold]Authentication for {actor.id}[/bold]")
        console.print("1. Extract from HAR")
        console.print("2. Extract from raw HTTP request")
        console.print("3. Enter credential securely")
        console.print("4. Leave incomplete for now")
        choice = _prompt_text("Authentication source", default="1")
        if choice == "1":
            path = _setup_authentication_file(_prompt_text("HAR file"), result)
            candidates = detect_har_authentication(path)
            if not candidates:
                console.print(
                    "No replay authentication candidate was detected. The HAR may have been "
                    "exported with Authorization headers and cookies sanitized. Re-export an "
                    "authenticated request with sensitive headers included, import a raw HTTP "
                    "request, or use secure manual entry."
                )
                continue
            for index, candidate in enumerate(candidates, start=1):
                console.print(f"[{index}] {candidate.redacted_summary()}")
            selected = _prompt_integer(
                "Select replay authentication",
                default=1,
                minimum=1,
                maximum=len(candidates),
            )
            authentication, _ = capture_from_har(
                result.workspace, actor.id, path, candidate_number=selected
            )
        elif choice == "2":
            path = _setup_authentication_file(_prompt_text("Raw request file"), result)
            authentication = capture_from_raw_request(result.workspace, actor.id, path)
        elif choice == "3":
            auth_type = _prompt_text("Authentication type", default="bearer")
            header = _prompt_text("Header name", default="Authorization")
            value = str(typer.prompt("Credential", hide_input=True, confirmation_prompt=True))
            authentication = set_manual_authentication(
                result.workspace,
                actor.id,
                auth_type=auth_type,
                header_name=header,
                secret_value=value,
            )
        else:
            console.print(f"{actor.id}: authentication remains MISSING.")
            continue
        console.print(f"Credential stored for {actor.id}.")
        console.print(f"Authentication status: {authentication.status}")
