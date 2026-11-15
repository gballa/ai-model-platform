# Test Report (`04-test-report.md`)

## 1. Execution Summary
- **Command Executed**: `PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v`
- **Total Tests**: 19 comprehensive test methods (covering 95+ distinct assertions across all 4 top-level subsystems, multi-threaded SQLite concurrency, security edge cases, and the CLI).
- **Result**: `OK` (19 passed, 0 failed, 0 errors, 0 warnings under `-W error`, runtime `0.323s`).

## 2. Verified Subsystem Matrix
1. **`TestDeployAndSupplyChainSecurity`**:
   - `test_safetensors_valid_and_pickle_rejection`: Verified spec-compliant `.safetensors` serialization/parsing, SHA-256 verification, rejection of `.pt`/`.pkl` extensions, and rejection of disguised `\x80\x04` Python pickle headers.
   - `test_safetensors_corrupted_offsets_and_truncated_headers`: Verified rejection of truncated buffers, overlapping tensor `data_offsets`, mismatched `shape * dtype` byte spans, unindexed buffer gaps, trailing unindexed payload bytes, and boolean dimensions in `shape`.
   - `test_license_compliance_auditor`: Verified approval of `Apache-2.0`/`MIT`, legal review flagging of `Modified-MIT`, and hard rejection of `Llama-4-Community` (EU multimodal ban), `GPL-3.0`, and empty licenses.
   - `test_signed_mcp_manifest_and_taint_enforcement`: Verified `HMAC-SHA256` MCP tool manifest signing, tamper detection, and automatic denial of `network_egress` tools when `session_tainted=True`.
   - `test_cybergym_firewall_and_k8s_sandbox_generator`: Verified `TAINTED_UNTRUSTED` total egress block, anti-SSRF cloud metadata IP (`169.254.169.254`) blocking, Squid config generation, and `kata-fc` 24-syscall seccomp K8s manifest generation.
2. **`TestLayer1IntelligenceAndTraining`**:
   - `test_model_registry_and_hardware_planner`: Verified the 4-Pool model registry, rejection of non-permissive checkpoints, Scenario B recommendation, and GPU ownership break-even calculation (`22.3` months).
   - `test_adaptive_model_router_and_best_of_n_pruner`: Verified domain/context routing across Pools 1–4, `NON_THINK` vs `THINK_HIGH` vs `THINK_MAX` token caps, `TTS@4` escalation on retry, and `BestOfNVerifierPruner` candidate ranking.
   - `test_radix_prefix_cache_simulator_meets_bl02_sla`: Verified cumulative RadixAttention prefix cache hit ratio $\ge 70\%$ and TTFT $\le 120\,\text{ms}$ on 27B multi-turn agent loops.
   - `test_swe_cyber_and_binrev_reward_oracles_and_grpo_trainer`: Verified `+1.0` full reward, `-0.5` over-correction/partial-fix penalty, `-1.0` compile/PoC failure, exact and partial-overlap (`0.5` IoU) DWARF struct layout matching, critic-free `GRPOTrainer` advantage & KL calculation (including zero-variance group safety), Stage 5 `DPOTrainer` preference alignment metrics, `MOPDDistiller` closed-API teacher blocking, and `torchtune` rejection.
3. **`TestLayer2ExecutionAndMCPServers`**:
   - `test_code_graph_mcp_three_tiers_and_fallback`: Verified Tier 1 BLAKE2b incremental AST caching, Tier 2 SCIP symbol & inverse call-graph resolution, `NoConfidentMatch` ripgrep fallback on unknown grammars (`.el`), Tier 3 Git co-change blast radius, and syntax-verified `str_replace` editing.
   - `test_code_graph_polyglot_c_cpp_go_rust_ts_java_and_concurrency`: Verified polyglot symbol and outgoing call-graph extraction across C, C++ (multi-line `template<...>`), Go receiver methods, Rust, TypeScript, and Java, plus 8-thread concurrent indexing and symbol resolution.
   - `test_binrev_mcp_and_prompt_injection_detection`: Verified ELF x86_64 header parsing, `checksec` audit, embedded prompt-injection detection, and Two-Phase SK²Decompile + ReCopilot context recovery.
   - `test_data_transformation_taxonomy_kaitai_and_visual_grounding`: Verified Shannon entropy classification of gzip/zlib/xz_lzma/squashfs/Base64/SHA-256 and 16B/32B/64B/256B encrypted blocks, streaming decompression-bomb `MemoryError` protection, preservation of plain ASCII words divisible by 4 (`b"function"`), Kaitai `.ksy` 100% byte-coverage synthesis, epistemic visual grounding with `zoom_crop_region` enforcement, and OSWorld-Human `ActionGrouping` ($\le 1.8\times$ step ratio).
   - `test_executor_cannot_self_complete_and_sandbox_isolation`: Verified `PermissionError` when executor agents attempt to set `TaskStatus.COMPLETED`, `vm_id` and file path traversal blocking (`../escape`), symlink host-file exfiltration blocking (`/etc/hosts`), deleted workspace file synchronization, and host credential env var stripping (`OPENAI_API_KEY`).
   - `test_orchestrator_human_approval_interrupt_and_rollback_retry_recovery`: Verified Step 5 human approval `interrupt()` pause & cryptographic resume, Step 10 bitemporal memory consolidation, time-travel SQLite checkpoint replay, Step 9 `<15ms` CoW snapshot rollback + automatic retry recovery, and 8-thread concurrent SQLite WAL checkpointing.
4. **`TestLayer3EvolutionMemoryAndCLI`**:
   - `test_bitemporal_memory_and_hybrid_knowledge_store`: Verified Graphiti/GAM bitemporal edge superseding, point-in-time historical queries (`query_facts_as_of`), 200K-token `DIRECT_PREFIX_CACHE` mode (even when chunk count > `top_k`) vs `>=200K` token `HYBRID_PGVECTORSCALE_SEARCH`, and prompt injection redaction.
   - `test_dataset_hygiene_decontamination_and_deduplication`: Verified rejection of GPL repos, benchmark-contaminated repos, unverified trajectories, and MinHash Jaccard near-duplicates.
   - `test_evaluation_pass_hat_k_and_8_step_improvement_cycle`: Verified $\text{pass}^4$, 95% confidence interval Canary Promotion Gate, and 8-Step Controlled Improvement Cycle root-cause attribution.
   - `test_cli_entrypoints_end_to_end`: Verified all CLI commands (`evaluate-blueprint`, `train-model`, `run-workflow --domain swe|cyber|binrev|data_protocol`, `inspect-data`).
