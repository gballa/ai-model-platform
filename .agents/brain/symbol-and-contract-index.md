# `platform-core` Codebase Symbol, Schema & Contract Atlas

**Parent Hub:** [`.agents/brain/README.md`](README.md)  
**Authoritative API Reference:** [`docs/api/README.md`](../../docs/api/README.md), [`docs/modules/cli.md`](../../docs/modules/cli.md)

---

## Table of Contents

1. [Source File & Symbol Dictionary (`src/platform_core/`)](#1-source-file--symbol-dictionary-srcplatform_core)
2. [Test Suite Atlas (`tests/`)](#2-test-suite-atlas-tests)
3. [SQLite WAL Database Schemas (5 Persistent Stores)](#3-sqlite-wal-database-schemas-5-persistent-stores)
4. [Unified CLI Subcommand Contract Table (23 Subcommands)](#4-unified-cli-subcommand-contract-table-23-subcommands)
5. [MCP Stdio JSON-RPC 2.0 Tool Registry (18 Tools Across 6 Servers)](#5-mcp-stdio-json-rpc-20-tool-registry-18-tools-across-6-servers)

---

## 1. Source File & Symbol Dictionary (`src/platform_core/`)

| File Path | Package / Layer | Exported Classes, Enums & Functions |
| :--- | :--- | :--- |
| [`src/platform_core/__init__.py`](../../src/platform_core/__init__.py) | `platform_core` | `__version__` (`"1.0.0"`) |
| [`src/platform_core/cli.py`](../../src/platform_core/cli.py) | `platform_core.cli` | `main()`, 9 `run_*` orchestration helpers, 23 CLI subcommand handlers |
| [`src/platform_core/layer1_intelligence/__init__.py`](../../src/platform_core/layer1_intelligence/__init__.py) | `layer1_intelligence` | Re-exports all Layer 1 public classes |
| [`src/platform_core/layer1_intelligence/models.py`](../../src/platform_core/layer1_intelligence/models.py) | `layer1_intelligence` | `ModelPool`, `ThinkingMode`, `ModelSpec`, `HardwareProfile`, `LocalHardwareDetector`, `HardwareFeasibilityReport`, `HardwareFeasibilityPlanner`, `CostComparisonReport`, `HardwareBreakEvenPlanner`, `ModelRegistry` |
| [`src/platform_core/layer1_intelligence/router.py`](../../src/platform_core/layer1_intelligence/router.py) | `layer1_intelligence` | `RoutingRequest`, `RoutingDecision`, `AdaptiveModelRouter`, `CandidateRollout`, `BestOfNVerifierPruner` |
| [`src/platform_core/layer1_intelligence/inference.py`](../../src/platform_core/layer1_intelligence/inference.py) | `layer1_intelligence` | `ToolDefinition`, `ToolCall`, `ChatMessage`, `InferenceRequest`, `InferenceResponse`, `InferenceBackend`, `OpenAICompatibleClient`, `MLXLocalBackend`, `DeterministicMockBackend`, `MemoryResidencyGuard`, `ModelDownloadManager` |
| [`src/platform_core/layer1_intelligence/serving.py`](../../src/platform_core/layer1_intelligence/serving.py) | `layer1_intelligence` | `ServingEndpointConfig`, `ServingHealthStatus`, `ServingHealthChecker`, `PrefixCacheMetrics`, `RadixPrefixCacheSimulator` |
| [`src/platform_core/layer1_intelligence/training.py`](../../src/platform_core/layer1_intelligence/training.py) | `layer1_intelligence` | `TrainingExecutionMode`, `TrainingStageConfig`, `TrainingRunReport`, `MLXQLoRATrainer`, `TorchTRLSpecAndRunner`, `SWECyberRewardInputs`, `SWECyberRewardOracle`, `DwarfFieldInterval`, `BinRevRewardInputs`, `BinRevDecompileRewardOracle`, `GRPORolloutSample`, `GRPOTrainer`, `MOPDDistiller`, `DistributedTrainingSpecBuilder`, `DPOPreferencePair`, `DPOTrainer`, `CustomModelArtifact`, `CustomModelPipeline` |
| [`src/platform_core/layer1_intelligence/scratch_trainer.py`](../../src/platform_core/layer1_intelligence/scratch_trainer.py) | `layer1_intelligence` | `ModelCreationPath`, `StrategyRecommendation`, `CreationStrategyAdvisor`, `BytePairTokenizer`, `ScratchSLMConfig`, `ScratchSLMArtifact`, `CompactTransformerSLMTrainer` |
| [`src/platform_core/layer1_intelligence/heretic.py`](../../src/platform_core/layer1_intelligence/heretic.py) | `layer1_intelligence` | `HereticConfig`, `AbliterationLayerResult`, `HereticAbliterationReport`, `HereticAbliterator`, `GAINSampleWeight`, `GAINAdaptiveScheduler`, `ColdFusionMergeConfig`, `ColdFusionMergeReport`, `ColdFusionModelMerger`, `ImatrixCalibrationReport`, `ImatrixQuantizationCalibrator` |
| [`src/platform_core/layer2_execution/__init__.py`](../../src/platform_core/layer2_execution/__init__.py) | `layer2_execution` | Re-exports all Layer 2 public classes |
| [`src/platform_core/layer2_execution/interfaces.py`](../../src/platform_core/layer2_execution/interfaces.py) | `layer2_execution` | `AbstractExecutionContext`, abstract execution contracts |
| [`src/platform_core/layer2_execution/state.py`](../../src/platform_core/layer2_execution/state.py) | `layer2_execution` | `TaskStatus`, `TaintLevel`, `EpistemicStatus`, `EpistemicClaim`, `EpistemicAssessment`, `SubTask`, `ArtifactRef`, `ApprovalRequest`, `PlatformState`, `StateStorageBackend`, `SQLiteStorageBackend`, `SQLiteStateCheckpointer` |
| [`src/platform_core/layer2_execution/sandbox.py`](../../src/platform_core/layer2_execution/sandbox.py) | `layer2_execution` | `ALLOWED_SECCOMP_SYSCALLS`, `CoWSnapshot`, `SandboxExecutionResult`, `FirecrackerSandboxManager` |
| [`src/platform_core/layer2_execution/mcp_tools.py`](../../src/platform_core/layer2_execution/mcp_tools.py) | `layer2_execution` | `SymbolNode`, `ImpactConeResult`, `CodeGraphMCPServer`, `DecompiledFunctionArtifact`, `BinRevMCPServer`, `SASTFinding`, `DefensiveCyberMCPServer`, `TransformationClass`, `DataClassificationResult`, `VisualInspectionResult`, `DataAndVisualMCPServer` |
| [`src/platform_core/layer2_execution/vuln_intel_mcp.py`](../../src/platform_core/layer2_execution/vuln_intel_mcp.py) | `layer2_execution` | `VulnFindingClassification`, `AuthorizationScope`, `VulnerabilityIntelligenceRecord`, `PackageDependency`, `DependencyAuditFinding`, `DependencyAuditReport`, `VulnIntelMCPServer` |
| [`src/platform_core/layer2_execution/forensics_mcp.py`](../../src/platform_core/layer2_execution/forensics_mcp.py) | `layer2_execution` | `ForensicVerdict`, `ForensicIndicator`, `ForensicFinding`, `ForensicAssessment`, `Stix2IocEngine`, `ForensicsMCPServer` |
| [`src/platform_core/layer2_execution/agents.py`](../../src/platform_core/layer2_execution/agents.py) | `layer2_execution` | `AgentNodeDescriptor`, `BaseSpecialistAgent`, `AgentToolLoop`, `PrincipalOrchestratorAgent`, `SoftwareEngineeringAgent`, `ReverseEngineeringAgent`, `DefensiveCyberAgent`, `MultimodalDataAgent`, `IndependentVerifierAgent` |
| [`src/platform_core/layer2_execution/orchestrator.py`](../../src/platform_core/layer2_execution/orchestrator.py) | `layer2_execution` | `LifecycleStep`, `ExecutionLifecycleOrchestrator` |
| [`src/platform_core/layer2_execution/agy_sdk_bridge.py`](../../src/platform_core/layer2_execution/agy_sdk_bridge.py) | `layer2_execution` | `MAX_JSONRPC_LINE_BYTES`, `AgyLocalAgentSpec`, `AgyExecutionResult`, `AgySkillDiscovery`, `AgyStdioMCPBridge`, `AgyLocalOrchestrator` |
| [`src/platform_core/layer3_evolution/__init__.py`](../../src/platform_core/layer3_evolution/__init__.py) | `layer3_evolution` | Re-exports all Layer 3 & `data_ingestion` public classes |
| [`src/platform_core/layer3_evolution/memory.py`](../../src/platform_core/layer3_evolution/memory.py) | `layer3_evolution` | `ProgressionEvent`, `BitemporalFactEdge`, `BitemporalEpisodicMemory`, `EmbeddingProvider`, `DeterministicHashEmbedder`, `InferenceBackendEmbedder`, `KnowledgeDocumentChunk`, `HybridKnowledgeStore`, `ProjectContextManager` |
| [`src/platform_core/layer3_evolution/corpus_harvester.py`](../../src/platform_core/layer3_evolution/corpus_harvester.py) | `layer3_evolution` | `RateLimitError`, `SanitizationResult`, `PromptInjectionSanitizer`, `HarvestedDocument`, `PDFBookExtractor`, `RateLimitedWebHarvester`, `DomainChunker`, `TeacherDistiller`, `HarvestReport`, `CorpusHarvesterPipeline` |
| [`src/platform_core/data_ingestion/data_factory.py`](../../src/platform_core/data_ingestion/data_factory.py) | `data_ingestion` / `layer3_evolution` | `TrainingTrajectoryRecord`, `SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, `DatasetHygienePipeline` |
| [`src/platform_core/layer3_evolution/evaluation.py`](../../src/platform_core/layer3_evolution/evaluation.py) | `layer3_evolution` | `MultiRunBenchmarkResult`, `BenchmarkEvaluator`, `PropBenchSpec`, `PropBench9Suite`, `BenchmarkCaseResult`, `BenchmarkSuiteRunner` |
| [`src/platform_core/layer3_evolution/observability.py`](../../src/platform_core/layer3_evolution/observability.py) | `layer3_evolution` | `TraceOutcome`, `FailureRootCauseBucket`, `ProductionTraceRecord`, `ControlledImprovementCycle`, `MonitoringService` |
| [`src/platform_core/layer3_evolution/brain_engine.py`](../../src/platform_core/layer3_evolution/brain_engine.py) | `layer3_evolution` | `BrainSyncReport`, `BrainQueryResult`, `BrainPipelineReport`, `ProjectBrainEngine` |
| [`src/platform_core/deploy_security/__init__.py`](../../src/platform_core/deploy_security/__init__.py) | `deploy_security` | Re-exports all Deploy & Security public classes |
| [`src/platform_core/deploy_security/governance.py`](../../src/platform_core/deploy_security/governance.py) | `deploy_security` | `SafetensorsValidationResult`, `SafetensorsValidator`, `LicenseAuditResult`, `LicenseComplianceAuditor`, `SignedToolManifest`, `SignedManifestVerifier`, `CyberGymFirewall`, `K8sAgentSandboxGenerator` |

---

## 2. Test Suite Atlas (`tests/`)

| Test File | Test Classes | Test Count | Focus Area |
| :--- | :--- | :--- | :--- |
| [`tests/test_platform_core.py`](../../tests/test_platform_core.py) | `TestDeployAndSupplyChainSecurity`, `TestLayer1IntelligenceAndTraining`, `TestLayer2ExecutionAndMCPServers`, `TestLayer3EvolutionMemoryAndCLI` | 20 | Core 3-layer architecture, 5-stage `CustomModelPipeline`, CLI subcommands, CoW sandbox, Safetensors `<Q` padding, license & HMAC gates |
| [`tests/test_e2e_harness.py`](../../tests/test_e2e_harness.py) | `TestE2EHarnessHardening` + [`tests/e2e/`](../../tests/e2e/) (Tiers 1–4: `152` tests) | 4 + 152 E2E | End-to-end CLI harness hardening, timeouts, thread safety, and 4-tier feature/boundary/pairwise/scenario suites |
| [`tests/test_inference_and_training.py`](../../tests/test_inference_and_training.py) | `TestInferenceAndTraining` | 5 | `OpenAICompatibleClient`, `MLXLocalBackend`, `MemoryResidencyGuard`, `ModelDownloadManager`, `MLXQLoRATrainer`, `TorchTRLSpecAndRunner` |
| [`tests/test_memory_rag_and_vision.py`](../../tests/test_memory_rag_and_vision.py) | `TestMemoryRagAndVision` | 2 | WAL SQLite `BitemporalEpisodicMemory`, FTS5 + vector RRF `HybridKnowledgeStore`, `ProjectContextManager`, binary PNG/JPEG/PDF inspection |
| [`tests/test_vuln_intel_and_cyber.py`](../../tests/test_vuln_intel_and_cyber.py) | `TestVulnIntelAndCyber` | 3 | `VulnIntelMCPServer` KEV/EPSS/OSV sync, tainted session block, RoE scope, AST taint SAST scanner |
| [`tests/test_forensics_spyware.py`](../../tests/test_forensics_spyware.py) | `TestForensicsSpywareDetection` | 2 | `ForensicsMCPServer`, `Stix2IocEngine`, iOS/Android acquisition triage, anti-fabrication SHA-256 verification |
| [`tests/test_benchmarks_and_epistemic.py`](../../tests/test_benchmarks_and_epistemic.py) | `TestBenchmarksAndEpistemic` | 3 | 5 executable `BenchmarkSuiteRunner` suites, `EpistemicAssessment` (`FACT`/`HYPOTHESIS`/`UNCERTAIN`), multi-turn `AgentToolLoop` |
| [`tests/test_corpus_and_scratch_trainer.py`](../../tests/test_corpus_and_scratch_trainer.py) | `TestCorpusHarvester`, `TestScratchTrainerAndStrategyAdvisor` | 9 | PDF/Web `CorpusHarvesterPipeline`, prompt-injection sanitization, `CreationStrategyAdvisor`, `BytePairTokenizer`, `CompactTransformerSLMTrainer` |
| [`tests/test_agy_sdk_and_skills.py`](../../tests/test_agy_sdk_and_skills.py) | `TestAgySdkBridge`, `TestCliAndWorkspaceSkillSubprocesses` | 5 | `AgySkillDiscovery` (5 skills + symlink rejection), `AgyStdioMCPBridge` JSON-RPC 2.0, `AgyLocalOrchestrator`, CLI & 5 skill script contracts |
| [`tests/test_heretic_and_brain.py`](../../tests/test_heretic_and_brain.py) | `TestHereticAndBrain` | 6 | Rank-$k$ refusal subspace extraction, matrix orthogonalization, KL-bounded `.safetensors` abliteration, GAIN adaptive weights, Cold-Fusion (`dare_ties` & `slerp`) merging, IMatrix GGUF/MLX calibration, and `ProjectBrainEngine` |

---

## 3. SQLite WAL Database Schemas (5 Persistent Stores)

All 5 SQLite stores enforce `PRAGMA busy_timeout = 30000`, `PRAGMA journal_mode = WAL` (when file-backed), and `threading.RLock()` synchronization:

| Store Class | Module | Tables Created | Primary Purpose |
| :--- | :--- | :--- | :--- |
| `SQLiteStateCheckpointer` | [`state.py`](../../src/platform_core/layer2_execution/state.py) | `state_checkpoints (checkpoint_id, session_id, lifecycle_step, status, created_at, state_json)` | Time-travel state persistence across all 10 lifecycle steps |
| `CodeGraphMCPServer` | [`mcp_tools.py`](../../src/platform_core/layer2_execution/mcp_tools.py) | `code_symbols (symbol_name, file_path, kind, line_number)`, `call_edges (caller, callee)` | 3-tier polyglot AST symbol index and $k$-hop reverse-call impact cone |
| `VulnIntelMCPServer` | [`vuln_intel_mcp.py`](../../src/platform_core/layer2_execution/vuln_intel_mcp.py) | `cve_records (cve_id, ecosystem, package_name, fixed_version, cvss_score, epss_score, epss_percentile, in_cisa_kev, summary, updated_at)` | Offline-capable vulnerability intelligence mirror (OSV, NVD, CISA KEV, FIRST EPSS) |
| `BitemporalEpisodicMemory` | [`memory.py`](../../src/platform_core/layer3_evolution/memory.py) | `progression_events (seq_id, event_id, session_id, timestamp, event_type, summary, commit_sha)`, `bitemporal_facts (seq_id, fact_id, subject, predicate, object_val, commit_sha, valid_from, ingested_at, valid_to, invalid_at)` | GAM event progression graph + Graphiti bitemporal fact edges (`query_as_of`) |
| `HybridKnowledgeStore` | [`memory.py`](../../src/platform_core/layer3_evolution/memory.py) | `knowledge_chunks (chunk_id, doc_id, content, source_uri, sha256_hash, token_count, embedding_json, ingested_at)`, `knowledge_chunks_fts` (FTS5 virtual table) | 200K-token prefix cache vs. BM25 + dense cosine Reciprocal Rank Fusion (RRF) |

---

## 4. Unified CLI Subcommand Contract Table (23 Subcommands)

Invoked via `PYTHONPATH=src .venv/bin/python -m platform_core.cli <subcommand>`:

| # | Subcommand | Key Arguments | Backing Subsystem |
| :--- | :--- | :--- | :--- |
| 1 | `evaluate-blueprint` | `--budget` | `HardwareFeasibilityPlanner`, `ModelRegistry`, `PropBench9Suite` |
| 2 | `train-model` | `--domain`, `--execution-mode` | `CustomModelPipeline` (5-stage post-training pipeline) |
| 3 | `create-custom-model` | `--model-id`, `--domain`, `--dataset-file`, `--output-dir`, `--execution-mode` | `CustomModelPipeline.build_custom_model()` |
| 4 | `run-workflow` | `--domain`, `--model-id`, `--manifest`, `--payload-file` | `ExecutionLifecycleOrchestrator.run_workflow()` |
| 5 | `run-custom-model` | `--manifest`, `--payload-file`, `--domain`, `--model-id` | `CustomModelPipeline.load_custom_model_manifest()` + `ExecutionLifecycleOrchestrator` |
| 6 | `inspect-data` | `--hex` | `DataAndVisualMCPServer.classify_transformation()` |
| 7 | `hardware-check` | *(none)* | `LocalHardwareDetector`, `ModelRegistry` |
| 8 | `download-model` | `--model-id`, `--license`, `--local-dir` | `ModelDownloadManager`, `LicenseComplianceAuditor` |
| 9 | `sync-vuln-db` | `--db-path`, `--feeds` | `VulnIntelMCPServer.sync_live_feeds()` |
| 10 | `scan-forensics` | `--target-dir`, `--platform`, `--stix-file`, `--use-mvt-cli` | `ForensicsMCPServer.analyze_forensic_target()` |
| 11 | `audit-vulns` | `--project-dir`, `--db-path` | `VulnIntelMCPServer.audit_project_dependencies()` |
| 12 | `analyze-image` | `--path`, `--prompt`, `--endpoint` | `DataAndVisualMCPServer` |
| 13 | `run-benchmarks` | `--suites` (`coding`, `reasoning`, `cyber_vuln`, `forensics`, `hallucination_resistance`) | `BenchmarkSuiteRunner.run_all_suites()` |
| 14 | `transparency-dashboard` | `--session-id` | `ExecutionLifecycleOrchestrator.get_session_status()` |
| 15 | `harvest-corpus` | `--pdf`, `--book-dir`, `--url`, `--domain`, `--distill-output`, `--rag-db-path` | `CorpusHarvesterPipeline` |
| 16 | `recommend-strategy` | `--corpus-tokens`, `--domain`, `--custom-vocab`, `--target-params-m` | `CreationStrategyAdvisor.recommend()` |
| 17 | `train-scratch-slm` | `--model-id`, `--corpus-file`, `--output-dir`, `--tier`, `--steps` | `CompactTransformerSLMTrainer` |
| 18 | `run-agy-local` | `--prompt`, `--runtime`, `--model`, `--tainted` / `--clean` | `AgyLocalOrchestrator.run_local_agent()` |
| 19 | `mcp-stdio-bridge` | `--server`, `--tainted` / `--clean` | `AgyStdioMCPBridge.serve_stdio()` |
| 20 | `brain-query` | `--query`, `--brain-dir`, `--top-k`, `--as-of`, `--output` | `ProjectBrainEngine.query_brain()` |
| 21 | `heretic-abliterate` | `--input-safetensors`, `--output-safetensors`, `--rank`, `--max-kl`, `--output` | `HereticAbliterator.abliterate_safetensors()` |
| 22 | `cold-fusion-merge` | `--checkpoints`, `--output-safetensors`, `--method`, `--drop-rate`, `--density`, `--quant-type`, `--output-dir`, `--output` | `ColdFusionModelMerger.merge_safetensors()` + `ImatrixQuantizationCalibrator` |
| 23 | `brain-pipeline` | `--output-dir`, `--model-id`, `--brain-dir`, `--domain`, `--steps`, `--rank`, `--drop-rate`, `--quant-type`, `--output` | `ProjectBrainEngine.run_brain_training_pipeline()` |

---

## 5. MCP Stdio JSON-RPC 2.0 Tool Registry (18 Tools Across 6 Servers)

Served via `AgyStdioMCPBridge` (`platform-cli mcp-stdio-bridge`). All tool names and parameter keys are valid Python identifiers (`str.isidentifier() == True`):

| MCP Server Key | Tool Identifier | Available in `TAINTED_UNTRUSTED`? | Description |
| :--- | :--- | :---: | :--- |
| `code_graph` | `code_index_python_source` | Yes | Parse Python AST symbols and call edges into SQLite WAL code graph |
| `code_graph` | `code_query_impact_cone` | Yes | Compute $k$-hop reverse-call impact cone for modified symbols |
| `code_graph` | `code_build_skeleton` | Yes | Build signature-only skeleton of Python source files for context compression |
| `binrev` | `binrev_decompile_and_cfg` | Yes | Disassemble/decompile raw binary hex and extract CFG metrics |
| `binrev` | `binrev_verify_equivalence` | Yes | Verify compiled C pseudocode equivalence against reference I/O vectors |
| `cyber` | `cyber_sast_taint_scan` | Yes | Run AST taint-tracking scan for command/SQL/deserialization sinks |
| `cyber` | `cyber_verify_remediation` | Yes | Verify security patch blocks exploit PoC while passing regression tests |
| `data_visual` | `data_classify_transformation` | Yes | Classify byte buffer into encoding, compression, or encryption via normalized entropy |
| `data_visual` | `data_synthesize_kaitai` | Yes | Synthesize Kaitai Struct `.ksy` YAML and verify 100% byte coverage |
| `data_visual` | `visual_inspect_document` | Yes | Extract dimensions, format headers, and text streams from PNG/JPEG/GIF/WebP/PDF |
| `data_visual` | `visual_verify_mermaid` | Yes | Verify Mermaid diagram syntax and bounding-box layout IoU |
| `vuln_intel` | `vuln_audit_dependencies` | Yes | Audit `pyproject.toml`, `requirements.txt`, or `package.json` against local CVE/KEV/EPSS DB |
| `vuln_intel` | `vuln_lookup_cve` | Yes | Query local SQLite vulnerability DB for a specific CVE ID |
| `vuln_intel` | `vuln_seed_advisories` | Yes | Seed verified offline vulnerability advisories into local SQLite mirror |
| `vuln_intel` | `vuln_sync_live_feeds` | **No (Clean Only)** | Sync live CISA KEV / FIRST EPSS / OSV network feeds (stripped when `session_tainted=True`) |
| `forensics` | `forensics_triage_acquisition` | Yes | Triage iOS, Android, or Host forensic directory with SHA-256 anti-fabrication checks |
| `forensics` | `forensics_load_stix_bundle` | Yes | Load STIX 2.1 indicator bundle into `Stix2IocEngine` |
| `forensics` | `forensics_verify_finding` | Yes | Deterministically verify a `ForensicFinding` artifact path and 64-hex SHA-256 digest |
