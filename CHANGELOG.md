# Changelog

All notable architectural, feature, security, and documentation changes to `platform-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Local Hardware, Inference, Vulnerability Intel, Forensics & Epistemic Architecture (`ADR-0005`)**:
  - Added `LocalHardwareDetector` (`hardware-check`), `OpenAICompatibleClient`, `MLXLocalBackend`, `DeterministicMockBackend`, `MemoryResidencyGuard`, and `ModelDownloadManager` (`download-model`) in `layer1_intelligence/inference.py`.
  - Added `VulnIntelMCPServer` (`vuln_intel_mcp.py`, `sync-vuln-db`, `audit-vulns`) with offline SQLite KEV/EPSS/OSV mirroring and fail-closed `AuthorizationScope` enforcement, plus `ForensicsMCPServer` & `Stix2IocEngine` (`forensics_mcp.py`, `scan-forensics`) with SHA-256 anti-fabrication and `visibility_limitations` gates, expanding agent workflows and `VALID_DOMAINS` to 8 domains (`vuln_intel`, `forensics` added).
  - Added `EpistemicAssessment` (`FACT`, `HYPOTHESIS`, `UNCERTAIN`) in `layer2_execution/state.py`, `BenchmarkSuiteRunner` (`run-benchmarks`, 5 default suites), and `transparency-dashboard` (`--session-id`) in `cli.py`.
- **Local AI Model Creator, Corpus Harvester, Scratch SLM & Antigravity SDK Bridge (`ADR-0006`)**:
  - Added `CorpusHarvesterPipeline`, `PDFBookExtractor`, `RateLimitedWebHarvester`, `PromptInjectionSanitizer`, `DomainChunker`, and `TeacherDistiller` (`harvest-corpus`).
  - Added `CreationStrategyAdvisor` (`recommend-strategy`), `BytePairTokenizer`, and `CompactTransformerSLMTrainer` (`train-scratch-slm`, `10M`/`50M`/`125M`/`350M` presets + `<Q` `header_pad` protection).
  - Added `AgySkillDiscovery` (5 workspace skills under `.agents/skills/`), `AgyStdioMCPBridge` (`mcp-stdio-bridge`, 18 clean / 17 tainted JSON-RPC 2.0 tools across 6 MCP servers), and `AgyLocalOrchestrator` (`run-agy-local`).
- **Heretic Abliteration, GAIN, Cold-Fusion Merge, IMatrix Calibration & Project Brain**:
  - Added `layer1_intelligence/heretic.py` (`HereticAbliterator`, `GAINAdaptiveScheduler`, `ColdFusionModelMerger`, `ImatrixQuantizationCalibrator`) and `layer3_evolution/brain_engine.py` (`ProjectBrainEngine`) alongside `.agents/brain/` ontology/corpora and CLI subcommands `brain-query`, `heretic-abliterate`, `cold-fusion-merge`, and `brain-pipeline` (`23` total subcommands).
- **Modular Extraction, Scripts & 4-Tier E2E Verification (`211` Tests)**:
  - Extracted `platform_core.data_ingestion` (`data_factory.py`, re-exported by `layer3_evolution`).
  - Added milestone corpus & trajectory utility scripts under `scripts/` and expanded verification to `211` tests (`59` across 10 `tests/test_*.py` modules + `152` across the 4-tier `tests/e2e/` runner).

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
