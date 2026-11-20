# `tests` — Unit, Integration & Adversarial Security Test Suite

---

## 1. Module Responsibilities and Boundaries

The `tests/` directory contains the **211-test** automated verification suite: **59 unit/integration tests** across 10 test modules (`tests/test_*.py`) plus **152 end-to-end tests** across the 4-tier discipline suite (`tests/e2e/`), covering all five subpackages of `platform_core` (`deploy_security`, `layer1_intelligence`, `layer2_execution`, `layer3_evolution`, `data_ingestion`), the unified CLI (`cli.py`, 23 subcommands), and all 5 workspace skills under `.agents/skills/`.

---

## 2. Test Suite Structure

### 2.1 Unit, Integration & Security Test Modules (59 Tests)

| Test File | TestCase Classes | Tests | Scope Covered |
| :--- | :--- | :---: | :--- |
| [`test_platform_core.py`](test_platform_core.py) | `TestDeployAndSupplyChainSecurity` (5), `TestLayer1IntelligenceAndTraining` (4), `TestLayer2ExecutionAndMCPServers` (6), `TestLayer3EvolutionMemoryAndCLI` (5) | 20 | `SafetensorsValidator`, `LicenseComplianceAuditor`, `SignedManifestVerifier`, `CyberGymFirewall`, `K8sAgentSandboxGenerator`, 4-Pool `ModelRegistry`, `AdaptiveModelRouter`, `BestOfNVerifierPruner`, `RadixPrefixCacheSimulator`, reward oracles, `GRPOTrainer`, `CodeGraphMCPServer` (polyglot + SCIP + threads), `BinRevMCPServer`, `DefensiveCyberMCPServer`, `DataAndVisualMCPServer`, `FirecrackerSandboxManager`, `SecVerifier` gate, `BitemporalEpisodicMemory`, `HybridKnowledgeStore`, `DatasetHygienePipeline`, `PropBench9Suite`, `ControlledImprovementCycle`, and core CLI entrypoints. |
| [`test_inference_and_training.py`](test_inference_and_training.py) | `TestInferenceAndTraining` | 5 | `LocalHardwareDetector`, `APPLE_SILICON_36GB` profile routing, `ServingEndpointConfig` (`mlx_lm`, `llama_cpp`), `MemoryResidencyGuard` LRU eviction, `AgentToolLoop`, `OpenAICompatibleClient`, `ModelDownloadManager`, and `TrainingExecutionMode` (`spec_only`, `mlx_qlora`, `torch_trl`). |
| [`test_memory_rag_and_vision.py`](test_memory_rag_and_vision.py) | `TestMemoryRagAndVision` | 2 | Persistent WAL SQLite `BitemporalEpisodicMemory`, `HybridKnowledgeStore` directory ingestion, image/PDF metadata & text extraction, and symlink rejection. |
| [`test_vuln_intel_and_cyber.py`](test_vuln_intel_and_cyber.py) | `TestVulnIntelAndCyber` | 3 | `VulnIntelMCPServer` OSV/NVD/KEV/EPSS correlation, polyglot manifest scanning, `TAINTED_UNTRUSTED` live-sync lockdown, fail-closed `AuthorizationScope` RoE guard, Python AST taint tracking, and sandbox PoC verification. |
| [`test_forensics_spyware.py`](test_forensics_spyware.py) | `TestForensicsSpywareDetection` | 2 | `Stix2IocEngine` ingestion, iOS/Android/Host spyware triage (`Pegasus`, `Predator`, etc.) vs clean controls, and `IndependentVerifierAgent` SHA-256 anti-fabrication gate. |
| [`test_benchmarks_and_epistemic.py`](test_benchmarks_and_epistemic.py) | `TestBenchmarksAndEpistemic` | 3 | `EpistemicAssessment` (`FACT` / `HYPOTHESIS` / `UNCERTAIN`) round-trip, end-to-end `vuln_intel` & `forensics` orchestration, `BenchmarkSuiteRunner`, and CLI checks. |
| [`test_corpus_and_scratch_trainer.py`](test_corpus_and_scratch_trainer.py) | `TestCorpusHarvester` (5), `TestScratchTrainerAndStrategyAdvisor` (4) | 9 | `PromptInjectionSanitizer`, `DomainChunker`, `PDFBookExtractor`, `RateLimitedWebHarvester` (SSRF, taint, rate pacing, 429/5xx retries, bounded reads), `TeacherDistiller` & `CorpusHarvesterPipeline`, `CreationStrategyAdvisor`, `BytePairTokenizer` UTF-8 & symlink safety, `ScratchSLMConfig` presets/validation, and `CompactTransformerSLMTrainer` deterministic export + `1408`-byte Safetensors `<Q` vs pickle regression guard. |
| [`test_agy_sdk_and_skills.py`](test_agy_sdk_and_skills.py) | `TestAgySdkBridge` (3), `TestCliAndWorkspaceSkillSubprocesses` (2) | 5 | `AgySkillDiscovery` (`5/5` `.agents/skills` + symlink/traversal rejection), `AgyStdioMCPBridge` (valid identifier names, `session_tainted=True` tool stripping, JSON-RPC stdio + `MAX_JSONRPC_LINE_BYTES` bounds), `AgyLocalOrchestrator` (`~` expansion, `SecVerifier` gate), CLI subcommands, and all 5 workspace skill wrapper scripts. |
| [`test_e2e_harness.py`](test_e2e_harness.py) | `TestE2EHarnessHardening` | 4 | E2E harness runner method aliasing, subprocess timeout handling, thread-safe in-process locking, and JSON report `OSError` resilience. |
| [`test_heretic_and_brain.py`](test_heretic_and_brain.py) | `TestHereticAndBrain` | 6 | `HereticAbliterator` subspace orthonormality & KL-bounded abliteration, `GAINAdaptiveScheduler`, `ColdFusionModelMerger` (`dare_ties`/`slerp`), `ImatrixQuantizationCalibrator`, `ProjectBrainEngine` sync/query/pipeline, and `brain-query`/`heretic-abliterate`/`cold-fusion-merge`/`brain-pipeline` CLI & symlink rejection. |

### 2.2 4-Tier End-to-End Test Suite (`tests/e2e/`, 152 Tests)

Orchestrated via [`e2e/test_runner.py`](e2e/test_runner.py) or [`e2e/run_all.py`](e2e/run_all.py) (supporting `--tier {1,2,3,4,all}`, `--domain`, `--mode {inprocess,subprocess}`, and `--output`):

| Test File | Tests | Scope Covered |
| :--- | :---: | :--- |
| [`e2e/test_tier1_feature_coverage.py`](e2e/test_tier1_feature_coverage.py) | 65 | Tier 1 single-feature CLI & core module coverage across all domains. |
| [`e2e/test_tier2_boundary_corner.py`](e2e/test_tier2_boundary_corner.py) | 65 | Tier 2 boundary inputs, fail-closed rejections, malformed schemas, and edge cases. |
| [`e2e/test_tier3_cross_feature.py`](e2e/test_tier3_cross_feature.py) | 14 | Tier 3 cross-feature and cross-layer pairwise interactions. |
| [`e2e/test_tier4_real_world.py`](e2e/test_tier4_real_world.py) | 8 | Tier 4 end-to-end real-world engineering, security, forensics, and model-creation scenarios. |

---

## 3. Running the Test Suite

Always run with `-W error` from the repository root:

```bash
PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v
```

---

## 4. Related Documentation

- [Testing & Quality Assurance Guide](../docs/testing/README.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
- [Workspace Engineering Invariants (`AGENTS.md`)](../AGENTS.md)
