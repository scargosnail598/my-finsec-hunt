"""Creation and discovery of independent target workspaces."""

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from finsec.config.models import TargetDocument, TargetIdentity
from finsec.errors import WorkspaceError
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.utils.yaml_store import load_yaml, write_yaml

TARGET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$")
DEFAULT_WORKSPACE_FILENAME = "default-workspace"


@dataclass(frozen=True)
class WorkspacePaths:
    """Frequently used paths within one target workspace."""

    root: Path

    @property
    def target(self) -> Path:
        return self.root / "target.yaml"

    @property
    def observations(self) -> Path:
        return self.root / "observations" / "normalized" / "observations.yaml"

    @property
    def captures(self) -> Path:
        return self.root / "captures" / "captures.yaml"

    @property
    def redacted_har(self) -> Path:
        return self.root / "observations" / "har"

    @property
    def endpoints(self) -> Path:
        return self.root / "api" / "endpoints.yaml"

    @property
    def graphql(self) -> Path:
        return self.root / "api" / "graphql.yaml"

    @property
    def mobile_discoveries(self) -> Path:
        return self.root / "observations" / "mobile" / "discoveries.yaml"

    @property
    def actors(self) -> Path:
        return self.root / "model" / "actors.yaml"

    @property
    def resources(self) -> Path:
        return self.root / "model" / "resources.yaml"

    @property
    def controlled_ownership(self) -> Path:
        return self.root / "model" / "controlled-ownership.yaml"

    @property
    def invariants(self) -> Path:
        return self.root / "model" / "invariants.yaml"

    @property
    def behavior_actions(self) -> Path:
        return self.root / "behavior" / "actions.yaml"

    @property
    def behavior_resources(self) -> Path:
        return self.root / "behavior" / "resource-instances.yaml"

    @property
    def workflow_instances(self) -> Path:
        return self.root / "behavior" / "workflow-instances.yaml"

    @property
    def workflow_families(self) -> Path:
        return self.root / "behavior" / "workflow-families.yaml"

    @property
    def behavior_states(self) -> Path:
        return self.root / "behavior" / "states.yaml"

    @property
    def behavior_transitions(self) -> Path:
        return self.root / "behavior" / "transitions.yaml"

    @property
    def propagation_links(self) -> Path:
        return self.root / "behavior" / "propagation-links.yaml"

    @property
    def workflow_graphs(self) -> Path:
        return self.root / "behavior" / "graphs"

    @property
    def business_invariants(self) -> Path:
        return self.root / "model" / "business-invariants.yaml"

    @property
    def business_logic_hypotheses(self) -> Path:
        return self.root / "hypotheses" / "business-logic.yaml"

    @property
    def hypotheses(self) -> Path:
        return self.root / "hypotheses" / "backlog.yaml"

    @property
    def test_plans(self) -> Path:
        return self.root / "tests" / "plans" / "plans.yaml"

    def executions_for(self, hypothesis_id: str) -> Path:
        """Return the immutable execution-audit directory for one hypothesis."""

        return self.root / "tests" / "executions" / hypothesis_id.upper()

    def burp_exports_for(self, hypothesis_id: str) -> Path:
        """Return the revisioned Burp-export directory for one hypothesis."""

        return self.root / "tests" / "burp" / hypothesis_id.upper()

    @property
    def validations(self) -> Path:
        return self.root / "findings" / "validations.yaml"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def readiness_provenance(self) -> Path:
        """Return the internal, non-secret readiness provenance store."""

        return self.root / ".finsec" / "readiness-provenance.yaml"

    def evidence_for(self, hypothesis_id: str) -> Path:
        """Return the evidence directory for a validated hypothesis ID."""

        return self.root / "evidence" / hypothesis_id.upper()


@dataclass(frozen=True)
class WorkspaceDeletionTarget:
    """Validated workspace identity approved for an explicit deletion prompt."""

    root: Path
    slug: str
    display_name: str


@dataclass(frozen=True)
class CaptureDeletionTarget:
    """Validated project-specific capture directory approved for deletion."""

    root: Path
    slug: str


WORKSPACE_DIRECTORIES = (
    "scope",
    "captures",
    "observations/raw",
    "observations/normalized",
    "observations/har",
    "observations/mobile",
    "api",
    "model",
    "behavior/graphs",
    "tests/burp",
    "tests/plans",
    "tests/executions",
    "evidence",
    "findings",
    "reports",
)


TEXT_SCAFFOLDS = {
    "scope/program.md": (
        "# Program Rules\n\nRecord the authoritative bug bounty rules and source.\n"
    ),
    "scope/scope.md": "# Scope\n\nRecord authorized hosts, APIs, and applications.\n",
    "scope/restrictions.md": (
        "# Testing Restrictions\n\nRecord rate, account, transaction, and technique restrictions.\n"
    ),
}


EMPTY_YAML_SCAFFOLDS = {
    "captures/captures.yaml": {"version": 1, "captures": []},
    "api/graphql.yaml": {"version": 1, "operations": []},
    "model/actors.yaml": {"version": 1, "actors": []},
    "model/resources.yaml": {"version": 1, "resources": []},
    "model/controlled-ownership.yaml": {
        "version": 1,
        "generator": "controlled-ownership-boundary-v1",
        "source_fingerprint": "",
        "resources": [],
        "relationships": [],
        "controlled_baselines": [],
        "identity_assumptions": [],
    },
    "model/invariants.yaml": {"version": 1, "invariants": []},
    "model/business-invariants.yaml": {"version": 2, "business_invariants": []},
    "behavior/actions.yaml": {"version": 1, "actions": []},
    "behavior/resource-instances.yaml": {"version": 1, "resource_instances": []},
    "behavior/workflow-instances.yaml": {"version": 2, "workflow_instances": []},
    "behavior/workflow-families.yaml": {"version": 2, "workflow_families": []},
    "behavior/states.yaml": {"version": 1, "states": []},
    "behavior/transitions.yaml": {"version": 1, "transitions": []},
    "behavior/propagation-links.yaml": {"version": 2, "propagation_links": []},
    "hypotheses/backlog.yaml": {"version": 2, "hypotheses": []},
    "hypotheses/business-logic.yaml": {
        "version": 3,
        "hypotheses": [],
        "rejections": [],
        "clusters": [],
    },
    "findings/validations.yaml": {"version": 1, "validations": []},
    "observations/mobile/discoveries.yaml": {"version": 1, "discoveries": []},
}


def validate_target_name(name: str) -> str:
    """Validate a portable, path-safe workspace name."""

    normalized = name.strip().lower()
    if name != normalized or not TARGET_NAME_PATTERN.fullmatch(normalized):
        raise WorkspaceError("Target name must use 1-64 lowercase letters, digits, or hyphens.")
    return normalized


def create_workspace(name: str, workspace_root: Path) -> WorkspacePaths:
    """Create a complete, non-overwriting target workspace."""

    target_name = validate_target_name(name)
    root = (workspace_root / target_name).resolve()
    if root.exists():
        raise WorkspaceError(f"Workspace already exists: {root}")

    root.mkdir(parents=True)
    for relative in WORKSPACE_DIRECTORIES:
        (root / relative).mkdir(parents=True, exist_ok=True)

    paths = WorkspacePaths(root)
    target = TargetDocument(target=TargetIdentity(name=target_name, slug=target_name))
    write_yaml(paths.target, target.model_dump(mode="json"))
    write_yaml(paths.observations, ObservationStore().model_dump(mode="json"))
    write_yaml(paths.endpoints, EndpointStore().model_dump(mode="json"))

    for relative, content in TEXT_SCAFFOLDS.items():
        (root / relative).write_text(content, encoding="utf-8", newline="\n")
    for relative, yaml_content in EMPTY_YAML_SCAFFOLDS.items():
        write_yaml(root / relative, yaml_content)

    return paths


def default_workspace_config_path() -> Path:
    """Return the per-user file that stores the selected default workspace."""

    configured_root = os.environ.get("FINSEC_HUNT_CONFIG_DIR")
    if configured_root:
        root = Path(configured_root).expanduser()
    else:
        xdg_root = os.environ.get("XDG_CONFIG_HOME")
        root = (
            Path(xdg_root).expanduser() / "finsec-hunt"
            if xdg_root
            else Path.home() / ".config" / "finsec-hunt"
        )
    return (root / DEFAULT_WORKSPACE_FILENAME).absolute()


def load_default_workspace(config_path: Path | None = None) -> WorkspacePaths | None:
    """Load and validate the configured default workspace, if one is selected."""

    path = (config_path or default_workspace_config_path()).expanduser()
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise WorkspaceError(
            f"Default workspace configuration is not a safe regular file: {path}. "
            "Run 'hunt workspace clear' and select it again."
        )
    try:
        stored = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise WorkspaceError(f"Cannot read default workspace configuration: {path}") from error
    selected = Path(stored).expanduser() if stored else None
    if selected is None or not selected.is_absolute():
        raise WorkspaceError(
            f"Default workspace configuration is invalid: {path}. "
            "Run 'hunt workspace clear' and select it again."
        )
    root = selected.resolve()
    if not (root / "target.yaml").is_file():
        raise WorkspaceError(
            f"Configured default workspace is unavailable: {root}. "
            "Run 'hunt workspace use PATH' or 'hunt workspace clear'."
        )
    return WorkspacePaths(root)


def set_default_workspace(path: Path, config_path: Path | None = None) -> WorkspacePaths:
    """Validate and atomically persist one default workspace selection."""

    workspace = resolve_workspace(path)
    destination = (config_path or default_workspace_config_path()).expanduser()
    directory = destination.parent
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise WorkspaceError(f"Default workspace configuration directory is not safe: {directory}")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(directory, 0o700)
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise WorkspaceError(
            f"Default workspace configuration is not a safe regular file: {destination}"
        )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.tmp-",
        dir=directory,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(f"{workspace.root}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        if os.name == "posix":
            os.chmod(destination, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return workspace


def clear_default_workspace(config_path: Path | None = None) -> bool:
    """Remove the configured default workspace selection if it exists."""

    path = (config_path or default_workspace_config_path()).expanduser()
    if not path.exists() and not path.is_symlink():
        return False
    if path.exists() and not path.is_file() and not path.is_symlink():
        raise WorkspaceError(f"Default workspace configuration is not a file: {path}")
    path.unlink()
    return True


def resolve_workspace(
    explicit: Path | None = None,
    start: Path | None = None,
    *,
    default_config: Path | None = None,
) -> WorkspacePaths:
    """Resolve an explicit, ancestor, configured default, or single local workspace."""

    if explicit is not None:
        root = explicit.expanduser().resolve()
        if not (root / "target.yaml").is_file():
            raise WorkspaceError(f"Not a FinSec Hunt workspace: {root}")
        return WorkspacePaths(root)

    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "target.yaml").is_file():
            return WorkspacePaths(candidate)

    configured = load_default_workspace(default_config)
    if configured is not None:
        return configured

    workspace_root = current / "workspaces"
    matches = sorted(workspace_root.glob("*/target.yaml")) if workspace_root.is_dir() else []
    if len(matches) == 1:
        return WorkspacePaths(matches[0].parent)
    if len(matches) > 1:
        raise WorkspaceError(
            "Multiple workspaces found; pass --workspace PATH or run 'hunt workspace use PATH'."
        )
    raise WorkspaceError(
        "No workspace found; run 'hunt setup', pass --workspace PATH, or run "
        "'hunt workspace use PATH'."
    )


def resolve_workspace_deletion_target(
    explicit: Path,
    *,
    current_directory: Path | None = None,
) -> WorkspaceDeletionTarget:
    """Validate an explicit workspace path against destructive-operation guardrails."""

    selected = explicit.expanduser().absolute()
    if any(candidate.is_symlink() for candidate in (selected, *selected.parents)):
        raise WorkspaceError("Refusing to delete a workspace selected through a symbolic link.")

    root = selected.resolve()
    current = (current_directory or Path.cwd()).resolve()
    filesystem_root = Path(root.anchor)
    protected = {filesystem_root, Path.home().resolve()}
    if root in protected or root.parent == filesystem_root:
        raise WorkspaceError(f"Refusing to delete a broad protected path: {root}")
    if root == current or root in current.parents:
        raise WorkspaceError(
            "Refusing to delete the current directory or one of its parents. "
            "Change to a directory outside the workspace and retry."
        )
    if (root / ".git").exists():
        raise WorkspaceError("Refusing to delete a directory that contains a .git repository.")
    if not root.is_dir() or not (root / "target.yaml").is_file():
        raise WorkspaceError(f"Not a FinSec Hunt workspace: {root}")

    required_directories = ("scope", "observations", "api", "model", "hypotheses")
    missing = [name for name in required_directories if not (root / name).is_dir()]
    if missing:
        raise WorkspaceError(
            "Refusing to delete an incomplete workspace; missing expected directories: "
            + ", ".join(missing)
        )

    try:
        target = TargetDocument.model_validate(load_yaml(root / "target.yaml"))
        slug = validate_target_name(target.target.slug or root.name)
    except (OSError, ValidationError, WorkspaceError) as error:
        raise WorkspaceError(f"Cannot validate workspace identity at {root}: {error}") from error

    return WorkspaceDeletionTarget(
        root=root,
        slug=slug,
        display_name=target.target.name,
    )


def resolve_capture_deletion_target(
    workspace: WorkspaceDeletionTarget,
    explicit: Path | None = None,
    *,
    current_directory: Path | None = None,
) -> CaptureDeletionTarget | None:
    """Resolve one project capture directory without broadening the deletion boundary."""

    inferred = explicit is None
    if explicit is None:
        if workspace.root.parent.name != "workspaces":
            raise WorkspaceError(
                "Cannot infer the capture directory for this workspace layout; pass "
                "--capture-directory PATH when using --purge."
            )
        selected = workspace.root.parent.parent / "captures" / workspace.slug
    else:
        selected = explicit.expanduser().absolute()

    if any(candidate.is_symlink() for candidate in (selected, *selected.parents)):
        raise WorkspaceError(
            "Refusing to delete a capture directory selected through a symbolic link."
        )

    root = selected.resolve()
    if not root.exists():
        if inferred:
            return None
        raise WorkspaceError(f"Capture directory does not exist: {root}")
    if not root.is_dir():
        raise WorkspaceError(f"Capture path is not a directory: {root}")
    if root.name != workspace.slug:
        raise WorkspaceError(
            f"Capture directory name must exactly match workspace slug '{workspace.slug}'."
        )

    current = (current_directory or Path.cwd()).resolve()
    filesystem_root = Path(root.anchor)
    protected = {filesystem_root, Path.home().resolve()}
    if root in protected or root.parent == filesystem_root:
        raise WorkspaceError(f"Refusing to delete a broad protected capture path: {root}")
    if root == current or root in current.parents:
        raise WorkspaceError(
            "Refusing to delete the current directory or one of its parents as a capture path."
        )
    if (root / ".git").exists():
        raise WorkspaceError("Refusing to delete a capture directory containing a .git repository.")
    if not (root / "incoming").is_dir() or not (root / "workflow.yaml").is_file():
        raise WorkspaceError(
            "Refusing to delete an unrecognized capture directory; expected incoming/ and "
            "workflow.yaml markers."
        )
    return CaptureDeletionTarget(root=root, slug=workspace.slug)


def delete_workspace(target: WorkspaceDeletionTarget) -> None:
    """Permanently remove one previously validated workspace directory."""

    if (
        target.root.is_symlink()
        or not target.root.is_dir()
        or not (target.root / "target.yaml").is_file()
    ):
        raise WorkspaceError(f"Workspace changed before deletion: {target.root}")
    if (target.root / ".git").exists():
        raise WorkspaceError("Workspace became a .git repository before deletion; refusing.")
    try:
        current_target = TargetDocument.model_validate(load_yaml(target.root / "target.yaml"))
        current_slug = validate_target_name(current_target.target.slug or target.root.name)
    except (OSError, ValidationError, WorkspaceError) as error:
        raise WorkspaceError(f"Workspace identity changed before deletion: {error}") from error
    if current_slug != target.slug:
        raise WorkspaceError("Workspace slug changed before deletion; refusing.")
    shutil.rmtree(target.root)


def delete_capture_directory(target: CaptureDeletionTarget) -> None:
    """Permanently remove one previously validated project capture directory."""

    if target.root.is_symlink() or not target.root.is_dir() or target.root.name != target.slug:
        raise WorkspaceError(f"Capture directory changed before deletion: {target.root}")
    if (target.root / ".git").exists():
        raise WorkspaceError(
            "Capture directory became a .git repository before deletion; refusing."
        )
    if not (target.root / "incoming").is_dir() or not (target.root / "workflow.yaml").is_file():
        raise WorkspaceError("Capture directory markers changed before deletion; refusing.")
    shutil.rmtree(target.root)
