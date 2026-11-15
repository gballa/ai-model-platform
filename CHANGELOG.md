# Changelog

All notable architectural, feature, security, and documentation changes to `platform-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-15

### Added
- **Layer 1 — Intelligence & Model Creation (`platform_core.layer1_intelligence`)**:
  - Four-Pool `ModelRegistry` (`POOL_1_ORCHESTRATOR`, `POOL_2_SWE_CYBER`, `POOL_3_BINREV`, `POOL_4_VISUAL_OCR`) with 5 default models (`DeepSeek-V4-Flash`, `Qwen3.5-397B-A17B`, `Qwen3.8-27B-SWE-Cyber`, `Qwen3.8-27B-BinRev`, `OmniParser-V2-UI-TARS-GOT-OCR`) and dynamic pool override support.
  - `HardwareFeasibilityPlanner` evaluating Scenarios A, B, and C and computing GPU ownership break-even (`22.3` months vs cloud rental).
  - `AdaptiveModelRouter` with entropy-bounded thinking modes (`NON_THINK`, `THINK_HIGH`, `THINK_MAX`), `preferred_model_id` routing, and `BestOfNVerifierPruner` (`TTS@4` / `TTS@8`).
  - `ServingEndpointConfig` (SGLang v0.5.19 and vLLM v0.28 CLI flag generation) and `RadixPrefixCacheSimulator`.
  - 5-Stage Post-Training & Custom Model Engine (`DistributedTrainingSpecBuilder`, `MOPDDistiller`, `SWECyberRewardOracle`, `BinRevDecompileRewardOracle`, `GRPOTrainer`, `DPOTrainer`, and `CustomModelPipeline`) producing verified `<model-id>.safetensors` and `<model-id>.manifest.json` bundles.
- **Layer 2 — Stateful Execution, 6-Agent Topology & Sandboxing (`platform_core.layer2_execution`)**:
  - `PlatformState`, `SubTask`, `ArtifactRef`, `ApprovalRequest`, and thread-safe WAL-enabled `SQLiteStateCheckpointer` with crash recovery (`load_latest`) and time-travel replay (`load_at_step`).
  - `FirecrackerSandboxManager` with 24-syscall seccomp allowlist, credential environment variable sanitization, and `<15ms` Copy-on-Write (CoW) snapshot creation and rollback restoration.
  - Four deterministic MCP servers: `CodeGraphMCPServer` (3-Tier AST/CST + SCIP + Git co-change across 9 file extensions), `BinRevMCPServer` (ELF/PE/Mach-O/UEFI/DEX + `checksec` + prompt-injection detector + Two-Phase `SK²Decompile` + `ReCopilot`), `DefensiveCyberMCPServer` (CPG taint scanner + `SecVerifier` Dual-Gate verifier), and `DataAndVisualMCPServer` (information-theoretic transformation classifier, streaming decompression-bomb guard, Kaitai `.ksy` synthesizer, Epistemic Visual Grounder, and `ActionGrouping`).
  - Six consolidated specialist agents (`PrincipalOrchestratorAgent`, `SoftwareEngineeringAgent`, `ReverseEngineeringAgent`, `DefensiveCyberAgent`, `MultimodalDataAgent`, `IndependentVerifierAgent`) and the 10-step `ExecutionLifecycleOrchestrator`.
- **Layer 3 — Evolution, Bitemporal Memory & Evaluation (`platform_core.layer3_evolution`)**:
  - `BitemporalEpisodicMemory` (GAM Event Progression Graph + Graphiti bitemporal fact edges) and `HybridKnowledgeStore` (200K-token `DIRECT_PREFIX_CACHE` rule + hybrid cosine/lexical search + prompt injection redaction).
  - Proprietary data factories (`SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`) and 4-gate `DatasetHygienePipeline`.
  - `PropBench9Suite`, `BenchmarkEvaluator` (95% CI, $\text{pass}@1$, $\text{pass}^k$, Canary Promotion Gate), and 8-step `ControlledImprovementCycle`.
- **Deploy & Supply-Chain Security (`platform_core.deploy_security`)**:
  - `SafetensorsValidator`, `LicenseComplianceAuditor`, `SignedManifestVerifier` (HMAC-SHA256), `CyberGymFirewall` (Squid allowlist + `TAINTED_UNTRUSTED` lockdown + SSRF protection), and `K8sAgentSandboxGenerator` (`SandboxTemplate` / `SandboxClaim`).
- **CLI & Examples (`platform_core.cli`, `examples/`)**:
  - `platform-cli` entrypoints: `evaluate-blueprint`, `train-model`, `create-custom-model`, `run-workflow`, `run-custom-model`, and `inspect-data`.
  - Runnable end-to-end custom model script (`examples/custom_model_end_to_end.py`) with sample JSONL trajectories and cybersecurity workflow payload.
- **Documentation Ecosystem & Continuous Governance (`docs/`, `CONTRIBUTING.md`, module `README.md`s)**:
  - Comprehensive documentation hierarchy across `docs/overview/`, `docs/architecture/` (including ADRs 0001–0004), `docs/modules/`, `docs/workflows/`, `docs/development/`, `docs/api/`, `docs/testing/`, `docs/deployment/`, `docs/security/`, `docs/operations/`, and `docs/guides/`.
  - Enforceable documentation standards (`docs/DOCUMENTATION_STANDARDS.md`), AI Agent Documentation Policy (`docs/AI_DOCUMENTATION_POLICY.md`), living index (`docs/DOCUMENTATION_INDEX.md`), and coverage matrix (`docs/DOCUMENTATION_COVERAGE.md`).
