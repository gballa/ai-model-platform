# Implementation Plan: Transforming `platform-core` into a Live Custom AI Engineering, Cybersecurity & Digital Forensics Platform

## 1. Goal Description

Transform `platform-core` (`v1.0.0`) from a pure-stdlib architectural blueprint and state-machine simulator into a **live, fast, reliable, locally runnable, and continuously improving custom AI model development, software engineering, cybersecurity, vulnerability intelligence, and digital forensics platform**.

This plan covers:
1. **System Audit** of the existing codebase, identifying verified strengths to preserve and simulated/missing capabilities to replace.
2. **2026 Open-Weight Model & Stack Evaluation**, tailored both to the **local Apple Silicon host (`Apple M3 Pro`, `36 GB Unified Memory`, `arm64`)** and **multi-GPU workstation/cluster scaling**.
3. **Target Architecture & Proposed Changes** across Inference, Fine-Tuning (QLoRA/GRPO/DPO), Persistent RAG & Bitemporal Memory, Multimodal Document/Image Analysis, Vulnerability Intelligence, Digital Forensics & Mercenary Spyware Detection, Epistemic Confidence/Attribution, and Executable Benchmarks.
4. **Prioritized Incremental Execution Roadmap** preserving all existing architectural invariants and tests.

---

## 2. Proposed Changes (Repository-Relative Paths)

### Component 1: Hardware Profiles, Live Inference Runtime & Residency Manager (`layer1_intelligence`)
- **Modify [models.py](../../../src/platform_core/layer1_intelligence/models.py):** Add `HardwareProfile`, `LocalHardwareDetector`, and `ModelRegistry.for_profile()`.
- **Add [inference.py](../../../src/platform_core/layer1_intelligence/inference.py):** Implement `InferenceBackend`, `OpenAICompatibleClient`, `MLXLocalBackend`, `MemoryResidencyGuard`, `DeterministicMockBackend`, and `ModelDownloadManager`.
- **Modify [serving.py](../../../src/platform_core/layer1_intelligence/serving.py):** Add `mlx_lm`, `llama_cpp`, and `ServingHealthChecker`.

### Component 2: Real Local & Cluster Fine-Tuning Engine (`layer1_intelligence`)
- **Modify [training.py](../../../src/platform_core/layer1_intelligence/training.py):** Add `TrainingExecutionMode`, `MLXQLoRATrainer`, `TorchTRLSpecAndRunner`, and `"forensics"` / `"vuln_intel"` domains.

### Component 3: Persistent RAG, Embeddings & Context Management (`layer3_evolution`)
- **Modify [memory.py](../../../src/platform_core/layer3_evolution/memory.py):** Add SQLite WAL persistence, FTS5 BM25 + vector cosine RRF, `DeterministicHashEmbedder`, `InferenceBackendEmbedder`, `ingest_directory()`, and `ProjectContextManager`.

### Component 4: Autonomous Tool-Calling Agents, SWE & Epistemic Verification (`layer2_execution`)
- **Modify [state.py](../../../src/platform_core/layer2_execution/state.py), [agents.py](../../../src/platform_core/layer2_execution/agents.py), [orchestrator.py](../../../src/platform_core/layer2_execution/orchestrator.py):** Add `EpistemicAssessment`, `AgentToolLoop`, `vuln_intel` / `forensics` handlers, and Step 10 epistemic ledger checks.

### Component 5: Digital Forensics & Mercenary Spyware Detection (`layer2_execution`)
- **Add [forensics_mcp.py](../../../src/platform_core/layer2_execution/forensics_mcp.py):** Implement `Stix2IocEngine` and `ForensicsMCPServer` (iOS, Android, and host triage with anti-fabrication guards).

### Component 6: Vulnerability Intelligence & AST Cyber Auditing (`layer2_execution`)
- **Add [vuln_intel_mcp.py](../../../src/platform_core/layer2_execution/vuln_intel_mcp.py):** Implement `VulnIntelMCPServer` (OSV, NVD, CISA KEV, FIRST EPSS, CWE, polyglot manifest parsing, and `AuthorizationScope`).
- **Modify [mcp_tools.py](../../../src/platform_core/layer2_execution/mcp_tools.py):** Add intraprocedural Python AST taint tracking and multimodal image/PDF inspection + cropping.

### Component 7: Executable Benchmarks, CLI & Documentation (`layer3_evolution`, `cli.py`, `docs/`)
- **Modify [evaluation.py](../../../src/platform_core/layer3_evolution/evaluation.py):** Add `BenchmarkSuiteRunner` across 5 live executable suites.
- **Modify [cli.py](../../../src/platform_core/cli.py) & [pyproject.toml](../../../pyproject.toml):** Add 7 new CLI subcommands (`hardware-check`, `download-model`, `sync-vuln-db`, `scan-forensics`, `audit-vulns`, `analyze-image`, `run-benchmarks`) and optional dependency extras (`[mlx]`, `[train]`, `[rag]`, `[vision]`, `[forensics]`, `[all]`).
- **Add [ADR-0005](../../../docs/architecture/decisions/ADR-0005-local-first-open-weight-forensics-and-vuln-intel.md)** & synchronize [DOCUMENTATION_INDEX.md](../../../docs/DOCUMENTATION_INDEX.md), [DOCUMENTATION_COVERAGE.md](../../../docs/DOCUMENTATION_COVERAGE.md), and module READMEs.
