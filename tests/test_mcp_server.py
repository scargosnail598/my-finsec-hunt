"""FastMCP registration and stdio startup smoke tests."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from finsec.config.workspace import WorkspacePaths
from finsec.mcp.service import FinsecMcpService
from finsec.mcp_server import create_server


def test_server_registers_passive_tools_and_review_prompt(
    phase3_workspace: WorkspacePaths,
) -> None:
    service = FinsecMcpService.from_workspace_path(phase3_workspace.root)
    server = create_server(service)

    async def inspect_server() -> tuple[list[str], list[str]]:
        tools = await server.list_tools()
        prompts = await server.list_prompts()
        await server.call_tool("hunt_workspace_summary", {})
        return sorted(item.name for item in tools), sorted(item.name for item in prompts)

    tool_names, prompt_names = anyio.run(inspect_server)

    assert tool_names == [
        "hunt_generate_hypotheses",
        "hunt_get_evidence_summary",
        "hunt_get_hypothesis_context",
        "hunt_ingest_har",
        "hunt_list_hypotheses",
        "hunt_setup_workspace",
        "hunt_workspace_summary",
    ]
    assert "hunt_approve" not in tool_names
    assert "hunt_execute" not in tool_names
    assert prompt_names == ["review_hypothesis"]


def test_stdio_passive_setup_import_and_generation_round_trip(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    source, _ = sample_har
    import_root = tmp_path / "imports"
    import_root.mkdir()
    (import_root / "account-a.har").write_bytes(source.read_bytes())
    workspace = tmp_path / "workspaces" / "stdio-passive"
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "finsec.mcp_server"],
        cwd=Path(__file__).parents[1],
        env={
            **os.environ,
            "FINSEC_HUNT_WORKSPACE": str(workspace),
            "FINSEC_HUNT_IMPORT_ROOT": str(import_root),
        },
    )

    async def exercise_stdio() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        async with (
            stdio_client(parameters) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            setup = await session.call_tool(
                "hunt_setup_workspace",
                {
                    "target_name": "Stdio Passive",
                    "slug": "stdio-passive",
                    "in_scope_hosts": ["api.example.test"],
                    "account_labels": ["ACCOUNT_A", "ACCOUNT_B"],
                    "authorization_confirmed": True,
                    "production": True,
                },
            )
            ingest = await session.call_tool(
                "hunt_ingest_har",
                {
                    "source_name": "account-a.har",
                    "actor": "ACCOUNT_A",
                    "channel": "WEB",
                },
            )
            workflow = await session.call_tool("hunt_generate_hypotheses", {})
            assert setup.structuredContent is not None
            assert ingest.structuredContent is not None
            assert workflow.structuredContent is not None
            return setup.structuredContent, ingest.structuredContent, workflow.structuredContent

    setup, ingest, workflow = anyio.run(exercise_stdio)

    assert setup["status"] == "CREATED"
    assert ingest["imported"] == 5
    assert workflow["observations"] == 5
    assert workflow["hypotheses_generated"] is True


def test_missing_workspace_configuration_writes_only_to_stderr() -> None:
    environment = dict(os.environ)
    environment.pop("FINSEC_HUNT_WORKSPACE", None)

    result = subprocess.run(
        [sys.executable, "-m", "finsec.mcp_server"],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "FINSEC_HUNT_WORKSPACE" in result.stderr
    assert "Traceback" not in result.stderr


def test_stdio_client_can_initialize_list_tools_call_tool_and_get_prompt(
    phase3_workspace: WorkspacePaths,
) -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "finsec.mcp_server"],
        cwd=Path(__file__).parents[1],
        env={**os.environ, "FINSEC_HUNT_WORKSPACE": str(phase3_workspace.root)},
    )

    with tempfile.TemporaryFile(mode="w+") as errlog:

        async def exercise_stdio() -> tuple[list[str], dict[str, Any], str]:
            async with (
                stdio_client(parameters, errlog=errlog) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool("hunt_workspace_summary", {})
                prompt = await session.get_prompt("review_hypothesis", {"hypothesis_id": "HYP-002"})
                assert result.structuredContent is not None
                prompt_text = "\n".join(
                    block.content.text
                    for block in prompt.messages
                    if hasattr(block.content, "text")
                )
                return (
                    sorted(item.name for item in tools.tools),
                    result.structuredContent,
                    prompt_text,
                )

        tool_names, summary, prompt_text = anyio.run(exercise_stdio)
        errlog.seek(0)
        stderr_text = errlog.read()

    assert "hunt_workspace_summary" in tool_names
    assert summary["target_name"] == "demo"
    assert "hunt_get_hypothesis_context" in prompt_text
    assert "KEEP|DOWNGRADE|SPLIT|DISMISS" in prompt_text
    assert "Traceback" not in stderr_text
