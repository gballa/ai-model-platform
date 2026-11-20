# Module Reference: Layer 2 — Stateful Execution, Agents, MCP Tools & Sandboxing (`platform_core.layer2_execution`)

**Source Directory:** [`src/platform_core/layer2_execution/`](../../src/platform_core/layer2_execution/)  
**Local Module README:** [`src/platform_core/layer2_execution/README.md`](../../src/platform_core/layer2_execution/README.md)

---

## Table of Contents

1. [Module Responsibilities & Boundaries](#1-module-responsibilities--boundaries)
2. [`state.py` — Typed `PlatformState` & `SQLiteStateCheckpointer`](#2-statepy--typed-platformstate--sqlitestatecheckpointer)
3. [`sandbox.py` — `FirecrackerSandboxManager` & `<15ms` CoW Snapshots](#3-sandboxpy--firecrackersandboxmanager--15ms-cow-snapshots)
4. [`mcp_tools.py`, `vuln_intel_mcp.py`, `forensics_mcp.py` — Six Deterministic Analysis, Vuln Intel & Forensics Servers](#4-mcp_toolspy-vuln_intel_mcppy-forensics_mcppy--six-deterministic-analysis-vuln-intel--forensics-servers)
5. [`agents.py` — Six Consolidated Specialist Agent Nodes](#5-agentspy--six-consolidated-specialist-agent-nodes)
6. [`orchestrator.py` — `ExecutionLifecycleOrchestrator` (Steps 1–10)](#6-orchestratorpy--executionlifecycleorchestrator-steps-110)
7. [`agy_sdk_bridge.py` — Google Antigravity SDK Bridge, Stdio MCP Server & Skill Discovery](#7-agy_sdk_bridgepy--google-antigravity-sdk-bridge-stdio-mcp-server--skill-discovery)
8. [Testing & Verification](#8-testing--verification)
9. [Related Documentation](#9-related-documentation)

---

## 1. Module Responsibilities & Boundaries

`platform_core.layer2_execution` implements the stateful runtime that executes multi-agent tasks inside isolated sandboxes with deterministic program analysis tools, step-level SQLite checkpointing, CoW snapshot rollback, and independent adversarial verification.

---

## 2. `state.py` — Typed `PlatformState` & `SQLiteStateCheckpointer`

- **Enums**:
  - `TaintLevel`: `CLEAN`, `TAINTED_UNTRUSTED`
  - `TaskStatus`: `PENDING`, `IN_PROGRESS`, `AWAITING_HUMAN_APPROVAL`, `AWAITING_VERIFICATION`, `VERIFIER_REJECTED`, `COMPLETED`, `FAILED_ESCALATED`
  - `LifecycleStep`: Integer enum `STEP_1_INGEST_AND_TAINT` (`1`) through `STEP_10_ARTIFACT_DELIVERY_AND_MEMORY` (`10`)
- **State Dataclasses**:
  - `ArtifactRef`: Out-of-context artifact pointer (`artifact_id`, `uri`, `sha256`, `byte_length`, `media_type`, `byte_range`).
  - `ApprovalRequest`: Human approval state (`request_id`, `action_description`, `risk_reason`, `approved`, `operator_id`, `approval_signature`).
  - `SubTask`: Decomposed task node (`subtask_id`, `title`, `domain`, `assigned_agent`, `status`, `scoped_tools`, `retry_count`, `max_retries`, `active_snapshot_id`, `candidate_output`, `verifier_feedback`, `verified_by_agent`).
  - `PlatformState`: Top-level session state with `to_dict()` and `from_dict()`.
- **`SQLiteStateCheckpointer`**:
  - Thread-safe (`check_same_thread=False`, `threading.RLock()`), sets `PRAGMA busy_timeout = 30000` and `PRAGMA journal_mode = WAL` (for file paths).
  - Methods: `save_checkpoint(state) -> int`, `load_latest(session_id) -> PlatformState | None`, `load_at_step(session_id, step) -> PlatformState | None`, `list_history(session_id) -> list[dict]`, `close()`.

---

## 3. `sandbox.py` — `FirecrackerSandboxManager` & `<15ms` CoW Snapshots

- **`SECCOMP_24_SYSCALL_ALLOWLIST`**: Tuple of 24 permitted VMM syscalls.
- **`SENSITIVE_ENV_PREFIXES`**: Strips `AWS_`, `GCP_`, `GOOGLE_`, `OPENAI_`, `ANTHROPIC_`, `GITHUB_`, `GITLAB_`, `HF_TOKEN`, `SSH_`, `DATABASE_URL`, `PGPASSWORD`, plus `HOME`, `TMPDIR`, `USER`, `LOGNAME`, `PYTHONPATH`.
- **Methods**:
  - `provision_microvm(vm_id, initial_files=None, tainted=True)`: Validates `vm_id` against `^[A-Za-z0-9._-]+$` and relative file paths against traversal (`..` or leading `/`).
  - `create_cow_snapshot(vm_id) -> CoWSnapshot`: Captures deep copy and SHA-256 state digest of workspace files.
  - `restore_cow_snapshot(snapshot_id) -> dict`: Restores workspace files and measures `restore_latency_ms` (`within_15ms_sla`).
  - `execute_python_in_sandbox(vm_id, python_code, timeout_sec=10.0) -> SandboxExecutionResult`: Runs `python3 -I` in an isolated `TemporaryDirectory`, syncs modified regular files back (rejecting symlinks and out-of-root paths), and prunes deleted files.
  - `check_network_egress(vm_id, destination) -> FirewallDecision`: Delegates to `CyberGymFirewall.evaluate_egress()`.

---

## 4. `mcp_tools.py`, `vuln_intel_mcp.py`, `forensics_mcp.py` — Six Deterministic Analysis, Vuln Intel & Forensics Servers

1. **`CodeGraphMCPServer`** (`mcp_tools.py`):
   - Supports `.py`, `.ts`, `.js`, `.go`, `.rs`, `.c`, `.cpp`, `.h`, `.java`.
   - `index_file(file_path, source_code)`: 16-byte BLAKE2b content cache in SQLite `indexed_files`; parses Python AST (`_parse_python_ast`) or balanced-brace polyglot CST (`_parse_polyglot_cst`) into `code_symbols`.
   - `query_symbol(symbol_name, fallback_corpus=None)`: Returns `status="Resolved"` with definitions and inverse callers, or `status="NoConfidentMatch"` with line-level `ripgrep_fallback_hits`.
   - `ingest_git_commits(commit_file_lists)` & `analyze_blast_radius(target_file, min_cochanges=1)`.
   - `apply_str_replace_edit(source_code, old_str, new_str, language="python")`: Requires exact unique match (`occurrences == 1`) and validates Python syntax via `ast.parse()` before returning `applied=True`.
2. **`BinRevMCPServer`**:
   - `inspect_binary(raw_bytes, artifact_name="sample.bin")`: Detects `ELF` (`x86_64`, `ARM64`, `x86`, `MIPS`), `PE`, `Mach-O`, `DEX`, `UEFI_FIRMWARE_VOLUME`; evaluates `checksec` (`nx_enabled`, `stack_canary`, `fortify_source`, `pie_or_aslr`); extracts ASCII strings and scans for embedded prompt-injection patterns (`PROMPT_INJECTION_PATTERNS`).
   - `run_two_phase_sk2_decompile(raw_ghidra_pseudocode, callers=None, callees=None, dataflow_aliases=None, cross_ref_strings=None)`: Builds the `ReCopilot` header, normalizes `goto LAB_...` into structured breaks (Phase 1 Skeleton), and applies variable aliases and C `stdint.h` types (`uint64_t`, `uint32_t`, `uint8_t`) (Phase 2 Skin).
3. **`DefensiveCyberMCPServer`**:
   - `scan_cpg_taint(source_code) -> list[CPGVulnerabilityFinding]`: Detects `CWE-78` (OS command injection), `CWE-89` (SQL injection), `CWE-94` (`eval`/`exec`), `CWE-502` (unsafe pickle/YAML deserialization), and `CWE-120` (unbounded C buffer copies).
   - `verify_dual_gate_patch(patched_source, poc_triggered_crash, regression_tests_passed, regression_tests_total)`: Verifies Gate 1 (zero CWEs and no PoC crash) and Gate 2 (`regression_tests_passed == regression_tests_total`), classifying failures into `POC_STILL_TRIGGERS`, `PARTIAL_FIX_SECONDARY_ENTRYPOINT`, or `OVER_CORRECTION_REGRESSION_BREAKAGE`.
4. **`DataAndVisualMCPServer`**:
   - `classify_transformation(data)`: Normalizes Shannon entropy against $\min(8.0, \log_2 N)$ (`math.log2(min(n, 256))`) and classifies into `COMPRESSION` (`gzip`, `zlib`, `zstd`, `xz_lzma`, `squashfs`), `HASH_DIGEST` (`CRC32/Adler32`, `MD5`, `SHA-1`, `SHA-256`, `SHA-512`), `ENCODING_SERIALIZATION` (`json`, `base64`, `utf8_or_binary_struct`), or `ENCRYPTION` (`block_or_stream_cipher`).
   - `safe_decode_or_decompress(data)`: Uses streaming `zlib.decompressobj().decompress(data, max_length=MAX_DECOMPRESSION_BYTES + 1)` to block decompression bombs at `10 MiB`.
   - `synthesize_kaitai_struct_ksy(format_id, magic_bytes, fields, sample_payload)`: Generates Kaitai `.ksy` YAML and checks `full_byte_coverage`.
   - `ground_visual_observations(regions, min_confidence=0.80)`: Separates grounded regions from low-confidence/obscured regions requiring `zoom_crop_region`.
   - `bundle_computer_use_actions(raw_actions, human_optimal_steps)`: Batches up to 4 deterministic actions per turn to achieve `step_efficiency_ratio <= 1.8`.
5. **`VulnIntelMCPServer`** (`vuln_intel_mcp.py`):
   - SQLite WAL mirror indexing CISA KEV, FIRST EPSS, and OSV/NVD records; blocks `sync_live_feeds()` on `session_tainted=True`, enforces `AuthorizationScope` Rules of Engagement, and correlates polyglot dependencies + AST taint (`CONFIRMED_VULNERABILITY` vs. `POTENTIAL_WEAKNESS`).
6. **`ForensicsMCPServer` & `Stix2IocEngine`** (`forensics_mcp.py`):
   - Ingests STIX 2.1 IOCs (`Pegasus`, `Predator`, `Graphite`, `Candiru`, `TriangleDB`) and triages iOS/Android/Host acquisitions, rejecting `CONFIRMED_IOC_MATCH` lacking an existing `artifact_path` and 64-hex `artifact_sha256` and recording `visibility_limitations`.

---

## 5. `agents.py` — Six Consolidated Specialist Agent Nodes

Defines `PrincipalOrchestratorAgent`, `SoftwareEngineeringAgent`, `ReverseEngineeringAgent`, `DefensiveCyberAgent`, `MultimodalDataAgent` (all `can_mark_completed=False`), and `IndependentVerifierAgent` (`can_mark_completed=True`).

---

## 6. `orchestrator.py` — `ExecutionLifecycleOrchestrator` (Steps 1–10)

Coordinates Steps 1–10 via `run_workflow()` and `approve_and_resume()`. Always call `orchestrator.close()` when finished to release SQLite connections in `checkpointer` and `code_graph_mcp`.

---

## 7. `agy_sdk_bridge.py` — Google Antigravity SDK Bridge, Stdio MCP Server & Skill Discovery

- **`AgyLocalAgentSpec` & `AgyExecutionResult`**: Configuration (`runtime_kind="local_openai"|"litert"`, `model_or_path`, `base_url`, `litert_backend`, `skills_paths`, `mcp_servers`, `max_subagent_depth=2`, `session_tainted=True`) and structured execution output (`to_dict()`).
- **`AgySkillDiscovery.discover_skills(skills_paths)`**: Discovers workspace skills containing `SKILL.md`, parses YAML frontmatter in pure stdlib, and rejects `..` traversal, symlinked directories, and symlinked `SKILL.md` files.
- **`AgyStdioMCPBridge(vuln_db_path=":memory:")`**:
  - Wraps `SUPPORTED_SERVERS = {"data_visual", "vuln_intel", "forensics", "code_graph", "binrev", "defensive_cyber"}` (`18` valid Python-identifier tools when clean; `17` when `session_tainted=True` with `vuln_sync_live_feeds` stripped and blocked with JSON-RPC `-32003`).
  - `serve_stdio(stdin=None, stdout=None, session_tainted=False)`: Serves newline-delimited JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`, `ping`) with `MAX_JSONRPC_LINE_BYTES` (`1 MiB`) line bounding and `.close()` cleanup.
  - `build_mcp_stdio_config(...)`: Generates `McpStdioServer`-compatible config dictionaries matching `session_tainted` tool filtering.
- **`AgyLocalOrchestrator(inference_backend=None)`**:
  - `is_sdk_installed()`: Lazily probes whether `google.antigravity` is installed without requiring `[agy]` at import time.
  - `build_sdk_config(spec)`: Expands `~` on LiteRT `model_path` via `os.path.expanduser`, blocks non-loopback `local_openai` `base_url` when `session_tainted=True`, enforces `max_subagent_depth`, and builds `LiteRTAgentConfig` / `LocalOpenAIAgentConfig` (or equivalent stdlib config snapshot).
  - `build_default_subagent_specs()`: Declares 4 executor subagent specs (`can_mark_completed=False`) plus `independent_verifier` (`can_mark_completed=True`).
  - `run_local_agent(spec, prompt, force_fallback=False) -> AgyExecutionResult`: Dispatches via live Google Antigravity SDK or deterministic stdlib fallback, and always validates output through `IndependentVerifierAgent` inside `FirecrackerSandboxManager` before setting `status="COMPLETED"`.

---

## 8. Testing & Verification

Covered by `TestLayer2ExecutionAndMCPServers`, `TestVulnIntelAndCyber`, `TestForensicsSpywareDetection`, `TestBenchmarksAndEpistemic`, and `TestAgySdkBridge` / `TestCliAndWorkspaceSkillSubprocesses` in [`tests/test_platform_core.py`](../../tests/test_platform_core.py), [`tests/test_vuln_intel_and_cyber.py`](../../tests/test_vuln_intel_and_cyber.py), [`tests/test_forensics_spyware.py`](../../tests/test_forensics_spyware.py), [`tests/test_benchmarks_and_epistemic.py`](../../tests/test_benchmarks_and_epistemic.py), and [`tests/test_agy_sdk_and_skills.py`](../../tests/test_agy_sdk_and_skills.py).

---

## 9. Related Documentation

- [10-Step Agent Execution Lifecycle Workflow](../workflows/agent-execution-lifecycle.md)
- [Data Flow & State Lifecycles](../architecture/data-flow.md)
- [ADR-0006: Local AI Creator & Google Antigravity SDK Bridge](../architecture/decisions/ADR-0006-local-ai-creator-and-antigravity-sdk.md)
- [Layer 2 Local README](../../src/platform_core/layer2_execution/README.md)
