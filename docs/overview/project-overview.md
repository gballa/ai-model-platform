# Project Overview — Proprietary Technical Intelligence Platform (`platform-core`)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Strategic Rationale](#2-problem-statement--strategic-rationale)
3. [Eight Target Technical Domains](#3-eight-target-technical-domains)
4. [Three-Layer Hybrid Intelligence Architecture](#4-three-layer-hybrid-intelligence-architecture)
5. [Scenario Economics & Hardware Feasibility](#5-scenario-economics--hardware-feasibility)
6. [Implemented vs. Cluster-Deployment Scope](#6-implemented-vs-cluster-deployment-scope)
7. [Related Documentation](#7-related-documentation)

---

## 1. Executive Summary

`platform-core` is an enterprise-grade, zero-dependency Python software stack implementing the **Three-Layer Hybrid Technical Intelligence Architecture**. It pairs open-weight foundation and specialist models (**Layer 1**) with a checkpointed 6-agent execution topology, deterministic Model Context Protocol (MCP) program analysis servers, and Copy-on-Write (CoW) microVM sandboxing (**Layer 2**), backed by bitemporal episodic memory, automated trajectory data factories, and statistical multi-run evaluation (**Layer 3**).

---

## 2. Problem Statement & Strategic Rationale

Engineering organizations building autonomous coding, cybersecurity, and reverse-engineering systems face four structural failure modes when relying on raw foundation models or closed commercial APIs:

1. **Self-Certification & Over-Correction**: Standard LLM agents mark their own tasks complete and break existing regression tests in 24%–40% of vulnerability patches (`OVER_CORRECTION_REGRESSION_BREAKAGE`) or leave secondary entry points open in 55% of multi-sink vulnerabilities (`PARTIAL_FIX_SECONDARY_ENTRYPOINT`).
2. **The Overthinking Trap**: Unconstrained chain-of-thought reasoning exhibits a negative correlation ($r = -0.56$) between token length and accuracy on tool-grounded engineering tasks while inflating Time-to-First-Token (TTFT).
3. **Un economical Scratch Pre-Training vs. Closed API Lock-In**: Pre-training a frontier model from scratch costs \$5.6M–\$50M+ (`pretrain_from_scratch_justified: False`), whereas distilling closed proprietary APIs violates commercial Terms of Service and leaks proprietary source code or binaries.
4. **Untrusted Execution & Supply-Chain Risks**: Analysing untrusted repositories or stripped binaries exposes the host to embedded prompt injection, outbound SSRF/exfiltration, decompression bombs, and malicious Python `.pkl`/`.pt` pickle checkpoints.

`platform-core` solves these failure modes structurally:
- **Deterministic Verifier Separation**: Only `IndependentVerifierAgent` (`can_mark_completed=True`) can transition a `SubTask` to `TaskStatus.COMPLETED` after running compilers, unit tests, CPG taint checks, or Kaitai byte-coverage assertions inside an isolated sandbox.
- **Entropy-Bounded Thinking & `TTS@N` Pruning**: `AdaptiveModelRouter` caps per-turn thinking tokens (`0`, `512–1024`, or `2048`) and escalates to parallel `TTS@4` / `TTS@8` rollouts pruned by `BestOfNVerifierPruner`.
- **5-Stage Open-Weight Specialization**: `CustomModelPipeline` specializes permissive open-weight models (`Apache-2.0` `Qwen3.8-27B` and `MIT` `DeepSeek-V4-Flash`) via `CPT -> SFT -> MOPD -> GRPO/RLVR -> DPO` into verified `.safetensors` checkpoints.
- **Taint-Isolated Sandboxing & `<15ms` CoW Rollback**: External code/binaries mark the session `TAINTED_UNTRUSTED`, stripping `network_egress`/`admin_deploy` scopes, enforcing `CyberGymFirewall` lockdown, and restoring pre-execution CoW workspace snapshots in `<15ms` on verification failure.

---

## 3. Eight Target Technical Domains

`CustomModelPipeline.VALID_DOMAINS` and `ExecutionLifecycleOrchestrator` support eight specialized domains:

| Domain Identifier | Routed Model Pool | Assigned Specialist Agent | Primary Deterministic MCP Tools | Verification Gate (`IndependentVerifierAgent`) |
| :--- | :--- | :--- | :--- | :--- |
| `swe` | `POOL_2_SWE_CYBER` | `SoftwareEngineeringAgent` | `CodeGraphMCPServer` (`index_file`, `query_symbol`, `apply_str_replace_edit`) | AST syntax validation + zero-exit unit/regression test execution in sandbox |
| `architecture` | `POOL_1_ORCHESTRATOR` | `SoftwareEngineeringAgent` (decomposed by `PrincipalOrchestratorAgent`) | `CodeGraphMCPServer` (`analyze_blast_radius`, `query_symbol`, `apply_str_replace_edit`) | AST syntax validation + integration test execution in sandbox |
| `cyber` | `POOL_2_SWE_CYBER` | `DefensiveCyberAgent` | `DefensiveCyberMCPServer` (`scan_cpg_taint`, `verify_dual_gate_patch`) + `CodeGraphMCPServer` | `SecVerifier` Dual-Gate: Gate 1 (`0` remaining CWEs & PoC crash eliminated) + Gate 2 (`100%` pass-to-pass regression tests) |
| `vuln_intel` | `POOL_2_SWE_CYBER` | `DefensiveCyberAgent` | `VulnIntelMCPServer` (`audit_project_dependencies`, OSV/KEV/EPSS lookup) + `CodeGraphMCPServer` | Rules-of-Engagement (`AuthorizationScope`) enforced + `CONFIRMED_VULNERABILITY` vs. `POTENTIAL_WEAKNESS` separated |
| `forensics` | `POOL_2_SWE_CYBER` | `DefensiveCyberAgent` | `ForensicsMCPServer` (`analyze_forensic_target`, `Stix2IocEngine`) | Anti-fabrication gate: every `CONFIRMED_IOC_MATCH` backed by real `artifact_path` + 64-hex `artifact_sha256` & `visibility_limitations` |
| `binrev` | `POOL_3_BINREV` | `ReverseEngineeringAgent` | `BinRevMCPServer` (`inspect_binary`, `run_two_phase_sk2_decompile`) | Phase 2 decompiled code is non-empty and contains zero unresolved `goto LAB_` branches |
| `data_protocol` | `POOL_2_SWE_CYBER` | `MultimodalDataAgent` | `DataAndVisualMCPServer` (`classify_transformation`, `safe_decode_or_decompress`, `synthesize_kaitai_struct_ksy`) | Kaitai `.ksy` schema achieves `full_byte_coverage == True` (`100%` byte coverage) |
| `visual_ocr` | `POOL_4_VISUAL_OCR` | `MultimodalDataAgent` | `DataAndVisualMCPServer` (`ground_visual_observations`, `bundle_computer_use_actions`, `synthesize_kaitai_struct_ksy`) | `full_byte_coverage == True` AND `epistemic_hallucination_guard_active == True` |

---

## 4. Three-Layer Hybrid Intelligence Architecture

| Layer | Package | Core Responsibility |
| :--- | :--- | :--- |
| **Layer 1: Intelligence & Model Creation** | [`platform_core.layer1_intelligence`](../../src/platform_core/layer1_intelligence/README.md) | 4-Pool `ModelRegistry`, `LocalHardwareDetector`, `HardwareFeasibilityPlanner`, `OpenAICompatibleClient` / `MLXLocalBackend`, `AdaptiveModelRouter`, `BestOfNVerifierPruner`, `ServingEndpointConfig`, `CustomModelPipeline`, `CreationStrategyAdvisor`, `CompactTransformerSLMTrainer`, and `HereticAbliterator` / `GAINAdaptiveScheduler` / `ColdFusionModelMerger` / `ImatrixQuantizationCalibrator`. |
| **Layer 2: Stateful Execution & Sandboxing** | [`platform_core.layer2_execution`](../../src/platform_core/layer2_execution/README.md) | `PlatformState` (`EpistemicAssessment`), `SQLiteStateCheckpointer`, `FirecrackerSandboxManager` (CoW snapshots), 6 MCP tool servers (`CodeGraph`, `BinRev`, `DefensiveCyber`, `DataAndVisual`, `VulnIntel`, `Forensics`), 6 specialist agents, 10-step `ExecutionLifecycleOrchestrator`, and `AgyLocalOrchestrator` / `AgyStdioMCPBridge` / `AgySkillDiscovery`. |
| **Layer 3: Evolution, Memory & Evaluation** | [`platform_core.layer3_evolution`](../../src/platform_core/layer3_evolution/README.md) & [`platform_core.data_ingestion`](../../src/platform_core/data_ingestion/README.md) | `BitemporalEpisodicMemory`, `HybridKnowledgeStore` (200K-token rule), `CorpusHarvesterPipeline`, `ProjectBrainEngine`, `SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, `DatasetHygienePipeline`, `PropBench9Suite`, `BenchmarkSuiteRunner`, `BenchmarkEvaluator`, and 8-step `ControlledImprovementCycle`. |
| **Cross-Cutting: Deploy & Security Governance** | [`platform_core.deploy_security`](../../src/platform_core/deploy_security/README.md) | `SafetensorsValidator`, `LicenseComplianceAuditor`, `SignedManifestVerifier`, `CyberGymFirewall`, and `K8sAgentSandboxGenerator`. |

---

## 5. Scenario Economics & Hardware Feasibility

`HardwareFeasibilityPlanner` ([src/platform_core/layer1_intelligence/models.py](../../src/platform_core/layer1_intelligence/models.py)) models three deployment scenarios and recommends **Scenario-B** for organizations requiring full-weight RLVR specialization:

| Scenario | Annual Budget (USD) | Team Size | Timeline | Hardware Footprint | Model Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scenario-A** (Lean Development) | \$120K – \$250K | 2–3 | 3 months | 1x Dual-RTX PRO 6000 Blackwell workstation (192GB GDDR7) + 1x Bare-metal KVM server + on-demand MI355X | Self-host `Qwen3.8-27B` + `DeepSeek-V4-Flash` with LoRA/QLoRA adapters |
| **Scenario-B** (Recommended Target) | \$1.2M – \$2.8M | 6–10 | 6 months | On-prem enclave (4x RTX PRO 6000 Blackwell + 2x Dual-EPYC KVM servers) + Reserved 8-GPU AMD MI355X or H200 pod + burst 32-GPU training | Full 5-stage specialization (`CPT -> SFT -> MOPD -> GRPO/RLVR -> DPO`) producing full-weight `Qwen3.8-27B` checkpoints |
| **Scenario-C** (Frontier Lab) | \$12M – \$35M | 20–35 | 15 months | 64–256x NVIDIA B200/GB300 NVL72 or AMD MI355X cluster + 16-node KVM farm | 500B–2T token CPT on `DeepSeek-V4-Pro` + 100K-environment async RLVR |

At \$470,000 hardware CapEx, \$2,500/month power/hosting, \$38/hour equivalent cloud rental, and 85% utilization, `HardwareFeasibilityPlanner.calculate_gpu_break_even_months()` computes a **22.3-month GPU ownership break-even**.

---

## 6. Implemented vs. Cluster-Deployment Scope

To guarantee deterministic local execution and zero third-party dependency overhead on developer workstations (macOS and Linux), `platform-core` cleanly separates **in-process deterministic execution** from **cluster-scale specification generation**:

| Capability | In-Process Implementation (Runs Locally on Python 3.11+) | Production Cluster Integration Output |
| :--- | :--- | :--- |
| **Model Routing & `TTS@N` Pruning** | Full execution in `AdaptiveModelRouter` and `BestOfNVerifierPruner` | Connects to live endpoints configured via `ServingEndpointConfig` |
| **Inference Serving & Radix Cache** | `RadixPrefixCacheSimulator` models block-level prefix hits and TTFT | `ServingEndpointConfig.to_launch_args()` emits exact CLI args for `sglang.launch_server` or `vllm serve` |
| **5-Stage Post-Training & Custom Models** | Exact mathematical computation of `MOPDDistiller` KL loss, `GRPOTrainer` group-normalized advantages & unbiased KL, `DPOTrainer` loss/margins, and binary `.safetensors` serialization | `DistributedTrainingSpecBuilder.build_spec()` emits `pytorch_fsdp2_dtensor` or `deepspeed_zero3` cluster configs |
| **MicroVM Sandboxing & CoW Rollback** | `FirecrackerSandboxManager` runs isolated `python3 -I` subprocesses in temporary directories with sanitized env vars and `<15ms` in-memory CoW snapshot rollback | `K8sAgentSandboxGenerator` emits `agentsandbox.x-k8s.io/v1alpha1` `SandboxTemplate` (`kata-fc`) and `SandboxClaim` CRDs |
| **MCP Program Analysis Tools** | Native AST/polyglot CST parser, SQLite SCIP symbol & inverse call-graph index, CPG regex taint rules, ELF/PE/Mach-O/UEFI/DEX parser, two-phase `SK²Decompile` normalizer, entropy classifier, and Kaitai `.ksy` synthesizer | Can be augmented with external headless Ghidra or Joern CPG servers in production |

---

## 7. Related Documentation

- [System Architecture](../architecture/system-architecture.md)
- [Component Architecture](../architecture/component-architecture.md)
- [Data Flow & State Lifecycles](../architecture/data-flow.md)
- [Getting Started Guide](../development/getting-started.md)
- [Custom Model Creation & Execution Guide](../CUSTOM_MODEL_GUIDE.md)
