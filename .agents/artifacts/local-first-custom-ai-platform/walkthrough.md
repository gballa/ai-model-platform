# Walkthrough: Custom AI Model Development, Cybersecurity & Forensics Platform (`platform-core`)

`platform-core` has been upgraded from an architectural simulation blueprint into a **local-first, verifiable AI engineering, cybersecurity intelligence, and digital forensics platform** while preserving its zero-dependency Python 3.11+ standard-library core (`dependencies = []` in [pyproject.toml](../../../pyproject.toml)) and all security invariants.

---

## 1. Key Capabilities Delivered

### Layer 1: Open-Weight Model Architecture, Inference & QLoRA/TRL Training
- **Hardware-Aware Catalog & Model Lineup ([models.py](../../../src/platform_core/layer1_intelligence/models.py)):** Added `HardwareProfile`, `LocalHardwareInfo`, and `LocalHardwareDetector.detect()`. On Apple Silicon 36 GB hosts (`LOCAL_APPLE_SILICON_36GB`, `safe_model_budget_gb: 28.08`), `ModelRegistry.for_profile()` registers permissive `Apache-2.0` open-weight models suited to unified memory (`Qwen/Qwen3.5-35B-A3B`, `Qwen/Qwen3-Coder-30B-A3B-Instruct`, `fdtn-ai/Foundation-Sec-8B-Reasoning`, `Qwen/Qwen3.8-27B`, `Qwen/Qwen3-VL-8B-Thinking`).
- **Live Inference Runtime & Residency Guard ([inference.py](../../../src/platform_core/layer1_intelligence/inference.py), [serving.py](../../../src/platform_core/layer1_intelligence/serving.py)):** Implemented `InferenceBackend`, `OpenAICompatibleClient` (tool calling + base64 image analysis), `MLXLocalBackend` guarded by `MemoryResidencyGuard` (LRU eviction within safe memory budget), `DeterministicMockBackend`, `ModelDownloadManager` (SPDX license gate via `LicenseComplianceAuditor`), and `ServingHealthChecker` alongside `mlx_lm` and `llama_cpp` support in `ServingEndpointConfig`.
- **Execution-Ready LoRA/QLoRA & TRL Post-Training ([training.py](../../../src/platform_core/layer1_intelligence/training.py)):** Added `TrainingExecutionMode` (`spec_only`, `mlx_qlora`, `torch_trl`), `MLXQLoRATrainer`, and `TorchTRLSpecAndRunner` supporting `"forensics"` and `"vuln_intel"` domains alongside `spec_only` artifact synthesis.

### Layer 2: Vulnerability Intelligence, Digital Forensics, AST Taint & Epistemic Verification
- **Vulnerability Intelligence & RoE Enforcement ([vuln_intel_mcp.py](../../../src/platform_core/layer2_execution/vuln_intel_mcp.py)):** Built thread-safe WAL SQLite mirror correlation for OSV, NVD, CISA KEV, FIRST EPSS, and CWEs, parsers for `requirements.txt`, `pyproject.toml`, `package-lock.json`, `go.mod`, and `Cargo.lock`, strict `CONFIRMED_VULNERABILITY` vs. `POTENTIAL_WEAKNESS` classification, clean-zone `sync_live_feeds()` blocking `TAINTED_UNTRUSTED` sessions, and fail-closed `AuthorizationScope` checks.
- **Python AST Taint & Real Sandbox Verification ([mcp_tools.py](../../../src/platform_core/layer2_execution/mcp_tools.py), [agents.py](../../../src/platform_core/layer2_execution/agents.py)):** Added intraprocedural Python AST taint tracking (`_scan_python_ast_taint`) and real Firecracker/subprocess sandbox verification for `poc_script` / `regression_test_script` payloads inside `IndependentVerifierAgent`.
- **Digital Forensics & Mercenary Spyware Triage ([forensics_mcp.py](../../../src/platform_core/layer2_execution/forensics_mcp.py)):** Built `Stix2IocEngine` and `ForensicsMCPServer` supporting iOS, Android, and host triage for Pegasus, Predator, Graphite, Candiru, and TriangleDB indicators, with optional `mvt-ios`/`mvt-android` probing, explicit `visibility_limitations`, and SHA-256 anti-fabrication verification in `IndependentVerifierAgent`.
- **Multimodal Document/Image Inspection & Epistemic Ledger ([mcp_tools.py](../../../src/platform_core/layer2_execution/mcp_tools.py), [state.py](../../../src/platform_core/layer2_execution/state.py), [orchestrator.py](../../../src/platform_core/layer2_execution/orchestrator.py)):** Added `inspect_image_artifact()`, `zoom_crop_region()`, `extract_document_text()`, `analyze_visual_artifact()`, `AgentToolLoop`, signed `"audit_security"` MCP manifests, and `EpistemicAssessment` (`FACT`, `HYPOTHESIS`, `UNCERTAIN`) built at Step 10.

### Layer 3: Persistent RAG, Project Context & Executable Benchmarks
- **Persistent FTS5 + Vector RRF Memory ([memory.py](../../../src/platform_core/layer3_evolution/memory.py)):** Upgraded `BitemporalEpisodicMemory` and `HybridKnowledgeStore` to thread-safe WAL SQLite with FTS5 BM25 + vector cosine RRF search (preserving the `< 200,000` token `DIRECT_PREFIX_CACHE` rule), `DeterministicHashEmbedder`, `InferenceBackendEmbedder`, `ingest_directory()`, and `ProjectContextManager`.
- **Executable Benchmarks & CLI ([evaluation.py](../../../src/platform_core/layer3_evolution/evaluation.py), [cli.py](../../../src/platform_core/cli.py)):** Added `BenchmarkSuiteRunner` across 5 live suites (`coding`, `reasoning`, `cyber_vuln`, `forensics`, `hallucination_resistance`) and CLI subcommands `hardware-check`, `download-model`, `sync-vuln-db`, `scan-forensics`, `audit-vulns`, `analyze-image`, and `run-benchmarks`.

---

## 2. Verification Results

| Check | Command | Outcome |
| :--- | :--- | :--- |
| **Full Test Suite (`-W error`)** | `PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v` | **PASS** (`35/35` tests in `0.729s`, zero warnings) |
| **Executable Benchmarks** | `PYTHONPATH=src .venv/bin/python -W error -m platform_core.cli run-benchmarks` | **PASS** (`11/11` cases, `100.0%`, `40.63 ms`) |
| **Hardware Detection** | `PYTHONPATH=src .venv/bin/python -W error -m platform_core.cli hardware-check` | **PASS** (`Apple M3 Pro`, `36.0 GB`, `LOCAL_APPLE_SILICON_36GB`) |
| **E2E Custom Model Lifecycle** | `PYTHONPATH=src .venv/bin/python -W error examples/custom_model_end_to_end.py` | **PASS** (`COMPLETED`, `verified_by: independent_verifier`) |
| **Adversarial Code Review** | `code-reviewer` subagent | **VERDICT: PASS** |
