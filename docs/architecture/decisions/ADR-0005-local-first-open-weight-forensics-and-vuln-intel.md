# ADR-0005: Local-First Open-Weight Lineup, Offline Vulnerability Intelligence Mirror, & Anti-Fabrication Spyware Forensics

---

## Status

`Accepted`

---

## Context

Running 300B+ parameter MoE checkpoints exclusively on multi-GPU clusters blocks local development, fine-tuning, and sovereign offline analysis on Apple Silicon workstations (36 GB Unified Memory M3 Pro) and single-GPU developer machines. Simultaneously, autonomous cybersecurity and digital forensics workflows require real OSV/NVD/CISA KEV/EPSS/CWE vulnerability correlation, STIX 2.x mercenary spyware IOC triage, and strict epistemic separation between verified facts and hypotheses so models never fabricate compromise claims.

---

## Decision

1. **Hardware-Aware Model Registry (`HardwareProfile`)**:
   - Preserve `CLUSTER_DEFAULT` untouched for cluster regression stability while adding `LOCAL_APPLE_SILICON_36GB` (`Qwen/Qwen3.5-35B-A3B`, `Qwen/Qwen3-Coder-30B-A3B-Instruct`, `fdtn-ai/Foundation-Sec-8B-Reasoning`, `Qwen/Qwen3.8-27B`, `Qwen/Qwen3-VL-8B-Thinking` — all `Apache-2.0`) and `WORKSTATION_GPU`, auto-detected via `LocalHardwareDetector.detect()`.
   - Gate local model residency with a thread-safe LRU `MemoryResidencyGuard` (`safe_model_budget_gb = total_memory_gb * 0.78`) and provide unified inference across `MLXLocalBackend`, `OpenAICompatibleClient` (`mlx_lm.server`, `llama-server`, `sglang`, `vllm`), and `DeterministicMockBackend`.
2. **Real Post-Training Execution (`TrainingExecutionMode`)**:
   - Extend `CustomModelPipeline.build_custom_model()` with `spec_only` (default), `mlx_qlora` (Apple Silicon 4-bit QLoRA + fuse + Safetensors verification), and `torch_trl` (self-contained PEFT/TRL pipeline script generation + chat JSONL export), plus an optional `eval_runner` callback for live canary benchmarking.
3. **Offline-First Vulnerability Intelligence & AST Taint (`VulnIntelMCPServer`, `DefensiveCyberMCPServer`)**:
   - Mirror OSV, NVD, CISA KEV, FIRST EPSS, and CWE catalogs into a thread-safe WAL SQLite store (`VulnIntelMCPServer`), blocking live feed sync (`sync_live_feeds()`) whenever `session_tainted=True` (`TAINTED_UNTRUSTED` invariant).
   - Distinguish `CONFIRMED_VULNERABILITY` (pinned version in affected range or confirmed Python AST source-to-sink taint flow) from `POTENTIAL_WEAKNESS` (unpinned versions or heuristic sinks) and enforce fail-closed Rules-of-Engagement (`AuthorizationScope`).
4. **Mercenary Spyware Forensics & Epistemic Claim Ledger (`ForensicsMCPServer`, `EpistemicAssessment`)**:
   - Analyze iOS backups/logs (`Info.plist`, `Manifest.plist`, `Shutdown.log`, `DataUsage.sqlite`, `SMS.db`, `TCC.db`, `.mobileconfig`), Android artifacts (`packages.xml`, permission triads, `/data/local/tmp`), and host artifacts against STIX 2.0/2.1 IOCs (`Stix2IocEngine`).
   - Enforce `NO_KNOWN_IOC_DETECTED` vs `SUSPICIOUS_ANOMALY` vs `CONFIRMED_IOC_MATCH` (always requiring SHA-256 + artifact path verification inside `IndependentVerifierAgent`), record explicit `visibility_limitations` (e.g., `IsEncrypted=True`), and emit an `EpistemicAssessment` ledger separating `FACT`, `HYPOTHESIS`, and `UNCERTAIN` claims on `PlatformState`.

---

## Consequences

- **Positive**: Developers can run inference, QLoRA fine-tuning, persistent SQLite FTS5+cosine RAG, SBOM/CVE auditing, spyware IOC triage, and 5-suite capability/hallucination benchmarks (`BenchmarkSuiteRunner`) locally on 36 GB Apple Silicon with zero mandatory cloud API dependencies.
- **Negative / Trade-offs**: Full live weight inference, VLM image decoding, and QLoRA weight updates require installing optional extras (`[mlx]`, `[train]`, `[vision]`, `[forensics]`); the core package remains pure stdlib for zero-dependency test determinism.

---

## Alternatives Considered

- **Cloud-only API routing**: Rejected due to sovereignty, privacy on forensic backups, and continuous local post-training requirements.
- **Hardcoding MLX imports at module import time**: Rejected because it breaks `-W error` tests and cross-platform CI on hosts without Apple Silicon Metal.

---

## Source Code Traceability

- [`src/platform_core/layer1_intelligence/models.py`](../../../src/platform_core/layer1_intelligence/models.py)
- [`src/platform_core/layer1_intelligence/inference.py`](../../../src/platform_core/layer1_intelligence/inference.py)
- [`src/platform_core/layer1_intelligence/training.py`](../../../src/platform_core/layer1_intelligence/training.py)
- [`src/platform_core/layer2_execution/vuln_intel_mcp.py`](../../../src/platform_core/layer2_execution/vuln_intel_mcp.py)
- [`src/platform_core/layer2_execution/forensics_mcp.py`](../../../src/platform_core/layer2_execution/forensics_mcp.py)
- [`src/platform_core/layer2_execution/state.py`](../../../src/platform_core/layer2_execution/state.py)
- [`src/platform_core/layer3_evolution/evaluation.py`](../../../src/platform_core/layer3_evolution/evaluation.py)
