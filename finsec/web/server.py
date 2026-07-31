"""Loopback-only server entry point for the FinSec Hunt web interface."""

from __future__ import annotations

import argparse
import ipaddress
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from finsec.errors import FinsecError
from finsec.web.app import create_app


def run_server(
    *,
    workspace_root: Path,
    workspace: Path | None,
    capture_root: Path | None,
    host: str,
    port: int,
) -> None:
    """Serve the Web UI only on a loopback interface."""

    if not _is_loopback(host):
        raise FinsecError(
            "The Web UI has no authentication and may only bind to localhost or a loopback IP."
        )
    effective_workspace_root = workspace.parent if workspace is not None else workspace_root
    app = create_app(
        workspace_root=effective_workspace_root,
        selected_workspace=workspace,
        capture_root=capture_root,
    )
    uvicorn.run(app, host=host, port=port, access_log=False)


def main(argv: Sequence[str] | None = None) -> None:
    """Run the standalone hunt-web command."""

    parser = argparse.ArgumentParser(description="Run the local FinSec Hunt Web UI.")
    parser.add_argument("--workspace-root", type=Path, default=Path("workspaces"))
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--capture-root", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    arguments = parser.parse_args(argv)
    run_server(
        workspace_root=arguments.workspace_root,
        workspace=arguments.workspace,
        capture_root=arguments.capture_root,
        host=arguments.host,
        port=arguments.port,
    )


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":
    main()
