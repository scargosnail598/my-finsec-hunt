"""Permission-restricted local secret-store abstraction."""

from __future__ import annotations

import json
import os
import re
from contextlib import suppress
from pathlib import Path
from typing import Any

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError

SECRET_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")


class SecretStore:
    """Store actor-bound secrets outside the workspace with restrictive permissions."""

    def __init__(self, workspace: WorkspacePaths) -> None:
        self.workspace = workspace
        self.root = workspace.root.parent / ".finsec-secrets"
        self.path = self.root / f"{workspace.root.name}.json"

    @property
    def backend_name(self) -> str:
        return "permission_restricted_file"

    def _ensure_root(self) -> None:
        if self.root.is_symlink() or (self.root.exists() and not self.root.is_dir()):
            raise FinsecError("Credential-store directory is not safe.")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)

    def _load(self) -> dict[str, Any]:
        if self.root.is_symlink() or (self.root.exists() and not self.root.is_dir()):
            raise FinsecError("Credential-store directory is not safe.")
        if self.root.exists() and self.root.stat().st_mode & 0o077:
            raise FinsecError("Credential-store directory permissions are too broad.")
        if self.path.is_symlink():
            raise FinsecError("Credential store is not a safe regular file.")
        if not self.path.exists():
            return {"version": 1, "secrets": {}}
        if not self.path.is_file():
            raise FinsecError("Credential store is not a safe regular file.")
        if self.path.stat().st_mode & 0o077:
            raise FinsecError("Credential store permissions are too broad.")
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise FinsecError("Credential store cannot be read safely.") from error
        if (
            not isinstance(document, dict)
            or document.get("version") != 1
            or not isinstance(document.get("secrets"), dict)
        ):
            raise FinsecError("Credential store has an unsupported format.")
        return document

    def _write(self, document: dict[str, Any]) -> None:
        self._ensure_root()
        temporary = self.path.with_name(f".{self.path.name}.tmp-{os.getpid()}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(document, handle, ensure_ascii=True, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        except Exception:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise

    def put(self, reference: str, actor_id: str, kind: str, value: str) -> None:
        """Atomically create or replace one actor-bound secret."""

        if not SECRET_REFERENCE.fullmatch(reference):
            raise FinsecError("Credential reference has an invalid format.")
        if not value:
            raise FinsecError("Credential value cannot be empty.")
        document = self._load()
        secrets = document["secrets"]
        secrets[reference] = {"actor_id": actor_id, "kind": kind, "value": value}
        self._write(document)

    def put_many(self, values: list[tuple[str, str, str, str]]) -> None:
        """Atomically replace several secrets after validating the complete batch."""

        document = self._load()
        secrets = document["secrets"]
        for reference, actor_id, kind, value in values:
            if not SECRET_REFERENCE.fullmatch(reference) or not value:
                raise FinsecError("Credential batch contains an invalid item.")
            secrets[reference] = {"actor_id": actor_id, "kind": kind, "value": value}
        self._write(document)

    def resolve(self, reference: str, actor_id: str) -> str:
        """Resolve a secret only when its stored actor binding matches exactly."""

        record = self._load()["secrets"].get(reference)
        if not isinstance(record, dict) or record.get("actor_id") != actor_id:
            raise FinsecError(
                f"Credential reference {reference!r} is missing or belongs to another actor."
            )
        value = record.get("value")
        if not isinstance(value, str) or not value:
            raise FinsecError(f"Credential reference {reference!r} cannot be resolved.")
        return value

    def contains(self, reference: str, actor_id: str) -> bool:
        try:
            self.resolve(reference, actor_id)
        except FinsecError:
            return False
        return True

    def remove(self, references: list[str], actor_id: str) -> None:
        document = self._load()
        secrets = document["secrets"]
        changed = False
        for reference in references:
            record = secrets.get(reference)
            if isinstance(record, dict) and record.get("actor_id") == actor_id:
                del secrets[reference]
                changed = True
        if changed:
            self._write(document)

    def deletion_targets(self) -> tuple[Path, ...]:
        """Validate and return files owned by this workspace's secret store."""

        if self.root.is_symlink() or (self.root.exists() and not self.root.is_dir()):
            raise FinsecError("Credential-store directory is not safe.")
        if not self.root.exists():
            return ()
        if self.root.stat().st_mode & 0o077:
            raise FinsecError("Credential-store directory permissions are too broad.")

        candidates = [self.path, *sorted(self.root.glob(f".{self.path.name}.tmp-*"))]
        existing: list[Path] = []
        for candidate in candidates:
            if candidate.is_symlink() or (candidate.exists() and not candidate.is_file()):
                raise FinsecError("Credential store is not a safe regular file.")
            if candidate.exists():
                existing.append(candidate)
        return tuple(existing)

    def delete_store(self) -> tuple[Path, ...]:
        """Delete only this workspace's credential file and abandoned temporary files."""

        targets = self.deletion_targets()
        for target in targets:
            target.unlink()
        if self.root.exists() and not any(self.root.iterdir()):
            self.root.rmdir()
        return targets

    def permissions(self) -> int | None:
        return self.path.stat().st_mode & 0o777 if self.path.is_file() else None
