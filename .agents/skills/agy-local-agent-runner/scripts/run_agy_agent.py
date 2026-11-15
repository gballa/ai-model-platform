#!/usr/bin/env python3
"""CLI wrapper for Google Antigravity local agent execution, skill discovery, and stdio MCP."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import Any


def _ensure_src_on_path() -> None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "src"
        if (candidate / "platform_core").is_dir():
            src_str = str(candidate)
            if src_str not in sys.path:
                sys.path.insert(0, src_str)
            return


_ensure_src_on_path()


def _positive_int(raw: str) -> int:
    try:
        val = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected positive integer, got {raw!r}.") from exc
    if val <= 0:
        raise argparse.ArgumentTypeError(f"Value must be > 0, got {val}.")
    return val


def _validate_safe_input_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if ".." in path.parts:
        raise PermissionError(f"Path traversal '..' rejected in input path: {raw_path}")
    if path.is_symlink():
        raise PermissionError(f"Symlinked input path rejected: {path}")
    return path


def _validate_safe_output_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if not raw_path.strip():
        raise ValueError("Output path must not be empty.")
    if ".." in path.parts:
        raise PermissionError(f"Path traversal '..' rejected in output path: {raw_path}")
    if path.is_symlink():
        raise PermissionError(f"Refusing to write to symlinked output path: {path}")
    if not path.is_absolute():
        cwd = Path.cwd().resolve()
        resolved = (cwd / path).resolve()
        if not resolved.is_relative_to(cwd):
            raise PermissionError(f"Relative output path escapes working directory: {raw_path}")
        cur = cwd
        for part in path.parts[:-1]:
            cur = cur / part
            if cur.is_symlink():
                raise PermissionError(f"Symlinked parent directory rejected: {cur}")
    if path.exists() and path.is_dir():
        raise IsADirectoryError(f"Output path is a directory: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_output(data: Any, output_file: str) -> None:
    """Write JSON result to `--output` after symlink and path-escape validation."""
    try:
        dest = _validate_safe_output_path(output_file)
        with dest.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"Success! Data written to: {dest}")
    except (OSError, PermissionError, ValueError, TypeError) as exc:
        print(f"Error writing output to {output_file}: {exc}", file=sys.stderr)
        sys.exit(1)


def _handle_discover(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer2_execution.agy_sdk_bridge import (
        AgyLocalOrchestrator,
        AgySkillDiscovery,
        AgyStdioMCPBridge,
    )

    skill_dirs = [_validate_safe_input_path(p) for p in args.skills_paths]
    skills = AgySkillDiscovery.discover_skills(skill_dirs)[: args.limit]
    bridge = AgyStdioMCPBridge()
    try:
        tools = bridge.list_tools(
            server_names=args.servers,
            session_tainted=args.session_tainted,
        )[: args.limit]
    finally:
        bridge.close()

    return {
        "command": "discover",
        "limit": args.limit,
        "sdk_installed": AgyLocalOrchestrator.is_sdk_installed(),
        "session_tainted": bool(args.session_tainted),
        "discovered_skill_count": len(skills),
        "skills": skills,
        "available_tool_count": len(tools),
        "tools": tools,
    }


def _handle_mcp_config(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer2_execution.agy_sdk_bridge import AgyStdioMCPBridge

    bridge = AgyStdioMCPBridge()
    try:
        tools = bridge.list_tools(
            server_names=args.servers,
            session_tainted=args.session_tainted,
        )[: args.limit]
        tool_names = [t["name"] for t in tools]
        cfg = AgyStdioMCPBridge.build_mcp_stdio_config(
            server_names=args.servers,
            python_executable=sys.executable,
            name=args.name,
            enabled_tools=tool_names,
            session_tainted=args.session_tainted,
        )
        return {
            "command": "mcp-config",
            "limit": args.limit,
            "session_tainted": bool(args.session_tainted),
            "enabled_tool_count": len(tool_names),
            "enabled_tools": tool_names,
            "mcp_stdio_config": cfg,
        }
    finally:
        bridge.close()


def _handle_run(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer1_intelligence.inference import OpenAICompatibleClient
    from platform_core.layer2_execution.agy_sdk_bridge import (
        AgyLocalAgentSpec,
        AgyLocalOrchestrator,
        AgyStdioMCPBridge,
    )

    skill_paths = tuple(str(_validate_safe_input_path(p)) for p in args.skills_paths)
    bridge = AgyStdioMCPBridge()
    try:
        tools = bridge.list_tools(
            server_names=args.servers,
            session_tainted=args.session_tainted,
        )[: args.limit]
        tool_names = [t["name"] for t in tools]
        mcp_cfg = AgyStdioMCPBridge.build_mcp_stdio_config(
            server_names=args.servers,
            python_executable=sys.executable,
            enabled_tools=tool_names,
            session_tainted=args.session_tainted,
        )
    finally:
        bridge.close()

    subagents = tuple(AgyLocalOrchestrator.build_default_subagent_specs()[: args.limit])
    spec = AgyLocalAgentSpec(
        agent_name=args.agent_name,
        runtime_kind=args.runtime_kind,
        model_or_path=args.model,
        base_url=args.base_url if args.runtime_kind == "local_openai" else None,
        litert_backend=args.litert_backend,
        enable_speculative_decoding=args.enable_speculative_decoding,
        skills_paths=skill_paths,
        mcp_servers=(mcp_cfg,),
        subagents=subagents,
        max_subagent_depth=args.max_subagent_depth,
        session_tainted=args.session_tainted,
    )

    backend = (
        OpenAICompatibleClient(base_url=args.base_url)
        if args.use_live_endpoint and args.runtime_kind == "local_openai"
        else None
    )
    orchestrator = AgyLocalOrchestrator(inference_backend=backend)
    res = orchestrator.run_local_agent(
        spec=spec,
        prompt=args.prompt,
        force_fallback=args.force_fallback,
    )
    payload = asdict(res)
    payload["command"] = "run"
    payload["limit"] = args.limit
    payload["loaded_skills"] = list(res.loaded_skills)
    payload["bound_mcp_servers"] = list(res.bound_mcp_servers)
    payload["subagent_delegations"] = list(res.subagent_delegations)
    return payload


def _handle_mcp_serve(args: argparse.Namespace) -> int:
    from platform_core.layer2_execution.agy_sdk_bridge import (
        MAX_JSONRPC_LINE_BYTES,
        AgyStdioMCPBridge,
    )

    vuln_db = args.vuln_db
    if vuln_db != ":memory:":
        _validate_safe_input_path(vuln_db)

    bridge = AgyStdioMCPBridge(vuln_db_path=vuln_db)
    try:
        if args.request_file:
            if not args.output:
                raise ValueError("--output is required when --request-file is provided.")
            if args.limit is None:
                raise ValueError("--limit is required when --request-file is provided.")
            req_path = _validate_safe_input_path(args.request_file)
            if not req_path.is_file():
                raise FileNotFoundError(f"JSON-RPC request file not found: {req_path}")
            responses: list[dict[str, Any]] = []
            with req_path.open("r", encoding="utf-8") as fh:
                while len(responses) < args.limit:
                    raw_line = fh.readline(MAX_JSONRPC_LINE_BYTES + 1)
                    if not raw_line:
                        break
                    if (
                        len(raw_line.encode("utf-8")) > MAX_JSONRPC_LINE_BYTES
                        and not raw_line.endswith("\n")
                    ) or len(raw_line.encode("utf-8")) > MAX_JSONRPC_LINE_BYTES:
                        if not raw_line.endswith("\n"):
                            while True:
                                chunk = fh.readline(MAX_JSONRPC_LINE_BYTES)
                                if not chunk or chunk.endswith("\n"):
                                    break
                        responses.append(
                            {
                                "jsonrpc": "2.0",
                                "id": None,
                                "error": {
                                    "code": -32600,
                                    "message": f"JSON-RPC request line exceeded {MAX_JSONRPC_LINE_BYTES} bytes.",
                                },
                            }
                        )
                        continue
                    line = raw_line.strip()
                    if not line:
                        continue
                    req = json.loads(line)
                    responses.append(bridge.dispatch_request(req, session_tainted=args.session_tainted))
            write_output(
                {
                    "command": "mcp-serve",
                    "mode": "batch_file",
                    "limit": args.limit,
                    "session_tainted": bool(args.session_tainted),
                    "response_count": len(responses),
                    "responses": responses,
                },
                args.output,
            )
            return 0

        return bridge.serve_stdio(session_tainted=args.session_tainted)
    finally:
        bridge.close()


def _add_taint_flags(parser: argparse.ArgumentParser, default_tainted: bool = True) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--tainted",
        "--session-tainted",
        dest="session_tainted",
        action="store_true",
        help="Enforce TAINTED_UNTRUSTED capability stripping (default)",
    )
    group.add_argument(
        "--clean",
        dest="session_tainted",
        action="store_false",
        help="Run in trusted CLEAN session mode (enables live-egress tools)",
    )
    parser.set_defaults(session_tainted=default_tainted)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Google Antigravity local multi-agent orchestration, skill discovery, and stdio MCP."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_disc = sub.add_parser("discover", help="Discover local workspace skills and MCP tools")
    p_disc.add_argument("--skills-paths", nargs="+", default=[".agents/skills"])
    p_disc.add_argument("--servers", nargs="+", default=None, help="Optional subset of MCP server names")
    _add_taint_flags(p_disc, default_tainted=True)
    p_disc.add_argument("--limit", type=_positive_int, required=True, help="Maximum skills/tools to list")
    p_disc.add_argument("--output", required=True, help="Output JSON file path")

    p_cfg = sub.add_parser("mcp-config", help="Generate McpStdioServer configuration JSON")
    p_cfg.add_argument("--servers", nargs="+", default=None, help="Optional subset of MCP server names")
    p_cfg.add_argument("--name", default="platform_core_mcp", help="MCP server name")
    _add_taint_flags(p_cfg, default_tainted=True)
    p_cfg.add_argument("--limit", type=_positive_int, required=True, help="Maximum MCP tools to enable")
    p_cfg.add_argument("--output", required=True, help="Output JSON file path")

    p_run = sub.add_parser("run", help="Run a local agent via Antigravity SDK or stdlib fallback")
    p_run.add_argument("--agent-name", default="local-sec-agent")
    p_run.add_argument("--runtime-kind", choices=["local_openai", "litert"], default="local_openai")
    p_run.add_argument("--model", default="Qwen/Qwen3.5-35B-A3B", help="Model ID or LiteRT .litertlm path")
    p_run.add_argument("--base-url", default="http://127.0.0.1:8080/v1")
    p_run.add_argument("--litert-backend", choices=["gpu", "npu"], default="gpu")
    p_run.add_argument("--enable-speculative-decoding", action="store_true")
    p_run.add_argument("--skills-paths", nargs="+", default=[".agents/skills"])
    p_run.add_argument("--servers", nargs="+", default=None)
    p_run.add_argument("--prompt", required=True, help="User objective prompt")
    _add_taint_flags(p_run, default_tainted=True)
    p_run.add_argument("--force-fallback", action="store_true", help="Force deterministic stdlib fallback runner")
    p_run.add_argument("--use-live-endpoint", action="store_true", help="Connect to --base-url via OpenAICompatibleClient")
    p_run.add_argument("--max-subagent-depth", type=_positive_int, default=2)
    p_run.add_argument("--limit", type=_positive_int, required=True, help="Maximum tools/subagents to bind")
    p_run.add_argument("--output", required=True, help="Output JSON execution report path")

    p_srv = sub.add_parser("mcp-serve", help="Run JSON-RPC 2.0 stdio MCP bridge (or batch --request-file)")
    p_srv.add_argument("--vuln-db", default=":memory:", help="Path to VulnIntel SQLite mirror")
    _add_taint_flags(p_srv, default_tainted=True)
    p_srv.add_argument("--request-file", default=None, help="Optional JSONL file of JSON-RPC requests")
    p_srv.add_argument("--limit", type=_positive_int, default=None, help="Required max requests when using --request-file")
    p_srv.add_argument("--output", default=None, help="Required JSON output path when using --request-file")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            data = _handle_discover(args)
        elif args.command == "mcp-config":
            data = _handle_mcp_config(args)
        elif args.command == "run":
            data = _handle_run(args)
        elif args.command == "mcp-serve":
            return _handle_mcp_serve(args)
        else:
            print(f"Unknown command: {args.command}", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"Error ({args.command}): {exc}", file=sys.stderr)
        return 1

    write_output(data, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
