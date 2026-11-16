# `tests` — Unit, Integration & Adversarial Security Test Suite

---

## 1. Module Responsibilities and Boundaries

The `tests/` directory contains the **205-test** automated verification suite across core unit/integration test modules and the 4-tier E2E discipline suite (`tests/e2e/`), covering all four subpackages of `platform_core` (`deploy_security`, `layer1_intelligence`, `layer2_execution`, `layer3_evolution`), the unified CLI (`cli.py`), and all 5 workspace skills under `.agents/skills/`.

---

## 2. Test Suite Structure

| Test File | TestCase Classes | Tests | Scope Covered |
| :--- | :--- | :---: | :--- |
| [`test_platform_core.py`](test_platform_core.py) | `TestDeployAndSupplyChainSecurity` (5), `TestLayer1IntelligenceAndTraining` (4), `TestLayer2ExecutionAndMCPServers` (6), `TestLayer3EvolutionMemoryAndCLI` (5) | 20 | `SafetensorsValidator`, `LicenseComplianceAuditor`, `SignedManifestVerifier`, `CyberGymFirewall`, `K8sAgentSandboxGenerator`, 4-Pool `ModelRegistry`, `AdaptiveModelRouter`, `BestOfNVerifierPruner`, `RadixPrefixCacheSimulator`, reward oracles, `GRPOTrainer`, `CodeGraphMCPServer` (polyglot + SCIP + threads), `BinRevMCPServer`, `DefensiveCyberMCPServer`, `DataAndVisualMCPServer`, `FirecrackerSandboxManager`, `SecVerifier` gate, `BitemporalEpisodicMemory`, `HybridKnowledgeStore`, `DatasetHygienePipeline`, `PropBench9Suite`, `ControlledImprovementCycle`, and core CLI entrypoints. |
| [`test_inference_and_training.py`](test_inference_and_training.py) | `TestInferenceAndTraining` | 5 | `LocalHardwareDetector`, `APPLE_SILICON_36GB` profile routing, `ServingEndpointConfig` (`mlx_lm`, `llama_cpp`), `MemoryResidencyGuard` LRU eviction, `AgentToolLoop`, `OpenAICompatibleClient`, `ModelDownloadManager`, and `TrainingExecutionMode` (`spec_only`, `mlx_qlora`, `torch_trl`). |
| [`test_memory_rag_and_vision.py`](test_memory_rag_and_vision.py) | `TestMemoryRagAndVision` | 2 | Persistent WAL SQLite `BitemporalEpisodicMemory`, `HybridKnowledgeStore` directory ingestion, image/PDF metadata & text extraction, and symlink rejection. |
| [`test_vuln_intel_and_cyber.py`](test_vuln_intel_and_cyber.py) | `TestVulnIntelAndCyber` | 3 | `VulnIntelMCPServer` OSV/NVD/KEV/EPSS correlation, polyglot manifest scanning, `TAINTED_UNTRUSTED` live-sync lockdown, fail-closed `AuthorizationScope` RoE guard, Python AST taint tracking, and sandbox PoC verification. |
| [`test_forensics_spyware.py`](test_forensics_spyware.py) | `TestForensicsSpywareDetection` | 2 | `Stix2IocEngine` ingestion, iOS/Android/Host spyware triage (`Pegasus`, `Predator`, etc.) vs clean controls, and `IndependentVerifierAgent` SHA-256 anti-fabrication gate. |
| [`test_benchmarks_and_epistemic.py`](test_benchmarks_and_epistemic.py) | `TestBenchmarksAndEpistemic` | 3 | `EpistemicAssessment` (`FACT` / `HYPOTHESIS` / `UNCERTAIN`) round-trip, end-to-end `vuln_intel` & `forensics` orchestration, `BenchmarkSuiteRunner`, and CLI checks. |
| [`test_corpus_and_scratch_trainer.py`](test_corpus_and_scratch_trainer.py) | `TestCorpusHarvester` (5), `TestScratchTrainerAndStrategyAdvisor` (4) | 9 | `PromptInjectionSanitizer`, `DomainChunker`, `PDFBookExtractor`, `RateLimitedWebHarvester` (SSRF, taint, rate pacing, 429/5xx retries, bounded reads), `TeacherDistiller` & `CorpusHarvesterPipeline`, `CreationStrategyAdvisor`, `BytePairTokenizer` UTF-8 & symlink safety, `ScratchSLMConfig` presets/validation, and `CompactTransformerSLMTrainer` deterministic export + `1408`-byte Safetensors `<Q` vs pickle regression guard. |
| [`test_agy_sdk_and_skills.py`](test_agy_sdk_and_skills.py) | `TestAgySdkBridge` (3), `TestCliAndWorkspaceSkillSubprocesses` (2) | 5 | `AgySkillDiscovery` (`5/5` `.agents/skills` + symlink/traversal rejection), `AgyStdioMCPBridge` (valid identifier names, `session_tainted=True` tool stripping, JSON-RPC stdio + `MAX_JSONRPC_LINE_BYTES` bounds), `AgyLocalOrchestrator` (`~` expansion, `SecVerifier` gate), all 5 new `platform_core.cli` subcommands, and all 5 workspace skill wrapper scripts. |

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
