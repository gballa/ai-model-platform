---
name: agy-local-agent-runner
description: >-
  Use this skill when running local multi-agent orchestration via Google
  Antigravity SDK (LiteRT or LocalOpenAI) with automatic stdlib fallback,
  discovering workspace skills, or serving platform_core MCP tools over stdio.
---

# Google Antigravity Local Agent Runner & Stdio MCP Bridge

## Overview

Configures and executes local multi-agent workflows powered by `google-antigravity` (`LiteRTAgentConfig`, `LocalOpenAIAgentConfig`, `skills_paths`, `SubagentConfig`, `McpStdioServer`) with seamless zero-dependency stdlib fallback when the SDK is absent. Exposes `platform_core`'s existing deterministic MCP servers (`DataAndVisualMCPServer`, `VulnIntelMCPServer`, `ForensicsMCPServer`, `CodeGraphMCPServer`, `BinRevMCPServer`, `DefensiveCyberMCPServer`) over JSON-RPC 2.0 stdio and enforces `IndependentVerifierAgent` (`SecVerifier`) gating plus `TAINTED_UNTRUSTED` capability isolation.

## Dependencies

- **Runtime**: `.venv/bin/python` works out of the box with `PYTHONPATH=src` and zero extra pip installs via `AgyLocalOrchestrator` stdlib fallback and `AgyStdioMCPBridge`.
- **Optional extras**:
  - `google-antigravity` (`google.antigravity`) for live `LiteRTAgentConfig` (NPU/GPU `.litertlm`) or `LocalOpenAIAgentConfig` execution.
  - Local OpenAI-compatible server (`mlx_lm.server`, `llama-server`, `Ollama`) at `http://127.0.0.1:8080/v1`.
- **Related skills**:
  - `corpus-harvester`, `local-model-advisor`, `scratch-slm-trainer`, `pretrained-qlora-finetuner`: All `.agents/skills/` are automatically discoverable via `AgySkillDiscovery` and `skills_paths`.

## Quick Start

1. Discover workspace skills and taint-filtered MCP tools:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/agy-local-agent-runner/scripts/run_agy_agent.py \
     discover --skills-paths .agents/skills --limit 25 --output artifacts/agy_discovery.json
   ```
2. Run a local agent task (automatically uses `google.antigravity` when installed or deterministic stdlib fallback + `IndependentVerifierAgent` gate):
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/agy-local-agent-runner/scripts/run_agy_agent.py \
     run --agent-name local-sec-agent --runtime-kind local_openai \
     --model Qwen/Qwen3.5-35B-A3B --prompt "Audit workspace skills and verify safety gates" \
     --force-fallback --limit 5 --output artifacts/agy_run.json
   ```
3. Emit a `McpStdioServer` configuration or run the JSON-RPC 2.0 stdio bridge:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/agy-local-agent-runner/scripts/run_agy_agent.py \
     mcp-config --servers data_visual vuln_intel forensics --limit 20 \
     --output artifacts/mcp_stdio_config.json
   ```

## Utility Scripts

All commands reside in [scripts/run_agy_agent.py](scripts/run_agy_agent.py). Commands returning structured reports write JSON via `--output` and require explicit `--limit` (no silent caps). Both `PYTHONPATH=src .venv/bin/python` and `.venv/bin/python` are supported.

- **`discover`**: Scans `--skills-paths` via `AgySkillDiscovery.discover_skills(...)` and lists available Python-identifier tools via `AgyStdioMCPBridge.list_tools(...)` (defaults to fail-closed `--tainted`; pass `--clean` for trusted sessions).
  - Required: `--limit <int>`, `--output <path>`.
  - Optional: `--skills-paths <dir...>`, `--servers <name...>`, `--tainted` / `--clean`.
- **`run`**: Constructs `AgyLocalAgentSpec` (with `~` home expansion on LiteRT paths, `skills_paths`, `SubagentConfig` specs, and `McpStdioServer` bindings) and executes `AgyLocalOrchestrator.run_local_agent(...)` gated by `IndependentVerifierAgent`.
  - Required: `--prompt <str>`, `--limit <int>`, `--output <path>`.
  - Optional: `--agent-name`, `--runtime-kind <local_openai|litert>`, `--model`, `--base-url`, `--litert-backend <gpu|npu>`, `--enable-speculative-decoding`, `--skills-paths <dir...>`, `--servers <name...>`, `--tainted` / `--clean`, `--force-fallback`, `--use-live-endpoint`, `--max-subagent-depth <int>`.
- **`mcp-config`**: Generates an `McpStdioServer` configuration dict and tool allowlist via `AgyStdioMCPBridge.build_mcp_stdio_config(...)`.
  - Required: `--limit <int>`, `--output <path>`.
  - Optional: `--servers <name...>`, `--name <str>`, `--tainted` / `--clean`.
- **`mcp-serve`**: Runs `AgyStdioMCPBridge.serve_stdio(...)` as a live newline-delimited JSON-RPC 2.0 MCP server, or processes a batch `--request-file` into `--output` for offline testing (enforcing `MAX_JSONRPC_LINE_BYTES`).
  - Optional: `--vuln-db <path>`, `--tainted` / `--clean`, `--request-file <jsonl>`, `--limit <int>`, `--output <path>`.

## Common Mistakes

1. **Expecting `status == "COMPLETED"` without verification**: Executor subagents never self-certify; `AgyLocalOrchestrator` always passes results through `IndependentVerifierAgent` (`can_mark_completed=True`).
2. **Calling `vuln_sync_live_feeds` without `--clean`**: Sessions default to fail-closed `--tainted` (`TAINTED_UNTRUSTED`), which strips live network-egress MCP tools and non-loopback endpoints.
3. **Passing unexpanded or symlinked `--skills-paths`**: `AgySkillDiscovery` rejects symlinked skill directories and path escapes outside the skill root.
