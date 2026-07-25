"""Application-specific exceptions shown as concise CLI errors."""


class FinsecError(Exception):
    """Base error for expected user-facing failures."""


class WorkspaceError(FinsecError):
    """Raised when a target workspace cannot be created or resolved."""


class HarFormatError(FinsecError):
    """Raised when a HAR file is unreadable or structurally invalid."""
