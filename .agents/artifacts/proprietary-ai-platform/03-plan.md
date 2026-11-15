# Implementation Plan (`03-plan.md`)

## 1. Ordered Task Graph
1. **Task 1 — Environment & Package Scaffolding**:
   - Initialize `.venv`, `pyproject.toml`, and `src/platform_core/` package structure.
2. **Task 2 — Deploy & Supply-Chain Governance (`deploy_security/governance.py`)**:
   - Implement `SafetensorsValidator` (magic header + JSON header size check + block `.pkl`/`.pt`/`.bin` pickle files).
   - Implement `LicenseComplianceAuditor` (validate base models & datasets against Apache-2.0 / MIT / BSD policy; reject Llama 4 EU-restricted multimodal and GPL/AGPL copyleft).
   - Implement `SignedManifestVerifier` (HMAC-SHA256 tool manifest verification), `CyberGymFirewall` (Squid domain allowlist + `TAINTED_UNTRUSTED` egress lockdown), and `K8sAgentSandboxGenerator` (`SandboxTemplate` & `SandboxClaim` YAML/dict generation).
3. **Task 3 — Layer 1 Intelligence, Routing & Model Creation (`layer1_intelligence/`)**:
   - Implement `models.py` (4 model pools, November 2026 competitive model registry, hardware/VRAM planner across Scenario A/B/C).
   - Implement `router.py` (`AdaptiveModelRouter`, entropy-aware `ThinkingMode` selector, Best-of-N `TTS@N` verifier-pruned selector).
   - Implement `serving.py` (`SGLangServingConfig` with RadixAttention prefix cache tree, `VLLMServingConfig`).
   - Implement `training.py` (5-stage post-training pipeline: `GRPOTrainer` with group-normalized advantage, sequence entropy weighting, and KL penalty; `SWECyberRewardOracle` dual-gate SecVerifier reward; `BinRevDecompileRewardOracle` $R_{\text{comp}} + R_{\text{exec}} + \text{Struct IoU}$; `MOPDDistiller`; `DistributedTrainingSpecBuilder` for FSDP2 & DeepSpeed ZeRO-3).
4. **Task 4 — Layer 2 Execution, MCP Servers, Sandboxing & 6-Agent StateGraph (`layer2_execution/`)**:
   - Implement `state.py` (`PlatformState`, `SubTask`, `TaintLevel`, `SQLiteStateCheckpointer`).
   - Implement `sandbox.py` (`FirecrackerSandboxManager` with CoW snapshot creation, `<15ms` rollback restoration, 24-syscall seccomp profile, and isolated execution).
   - Implement `mcp_tools.py` (`CodeGraphMCPServer`, `BinRevMCPServer`, `DefensiveCyberMCPServer`, `DataAndVisualMCPServer`).
   - Implement `agents.py` (6 consolidated specialist agents with strict `IndependentVerifierAgent` completion gate).
   - Implement `orchestrator.py` (`ExecutionLifecycleOrchestrator` executing the 10-step agent lifecycle with human `interrupt()` approval gate and automatic rollback/retry).
5. **Task 5 — Layer 3 Evolution, Bitemporal Memory, Data Factories & PropBench-9 (`layer3_evolution/`)**:
   - Implement `memory.py` (`BitemporalEpisodicMemory` with Graphiti/GAM bitemporal invalidation + `HybridKnowledgeStore` with 200K token prefix-cache threshold and prompt-injection sanitization).
   - Implement `data_factory.py` (`SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, `DatasetHygienePipeline` with MinHash LSH & decontamination blocklist).
   - Implement `evaluation.py` (`PropBench9Suite`, `BenchmarkEvaluator` with 95% CI, $\text{pass}^k$, Step Efficiency Ratio, Struct IoU, and Canary Promotion Gate).
   - Implement `observability.py` (`OTelSpanTracer` and 8-Step `ControlledImprovementCycle`).
6. **Task 6 — CLI Entrypoint & End-to-End Verification (`cli.py` + `tests/`)**:
   - Build `cli.py` with subcommands (`evaluate-blueprint`, `run-workflow`, `train-model`, `analyze-data`).
   - Write comprehensive unit, integration, and edge-case test suite in `tests/`.
   - Run full verification, security audit (`05-security-audit.md`), and test report (`04-test-report.md`).
