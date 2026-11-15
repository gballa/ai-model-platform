# Component Architecture & Package Boundaries

---

## Table of Contents

1. [Package Dependency Rules](#1-package-dependency-rules)
2. [Layer 1 (`layer1_intelligence`) Component Diagram & Classes](#2-layer-1-layer1_intelligence-component-diagram--classes)
3. [Layer 2 (`layer2_execution`) Component Diagram & Classes](#3-layer-2-layer2_execution-component-diagram--classes)
4. [Layer 3 (`layer3_evolution`) Component Diagram & Classes](#4-layer-3-layer3_evolution-component-diagram--classes)
5. [Deploy & Security (`deploy_security`) Component Diagram & Classes](#5-deploy--security-deploy_security-component-diagram--classes)
6. [CLI Entrypoint (`cli.py`) Component Mapping](#6-cli-entrypoint-clipy-component-mapping)
7. [Related Documentation](#7-related-documentation)

---

## 1. Package Dependency Rules

`platform_core` enforces a strict directed acyclic dependency structure across subpackages:

```mermaid
flowchart TB
    CLI["platform_core.cli"]
    L1["platform_core.layer1_intelligence\n(models, router, serving, training)"]
    L2["platform_core.layer2_execution\n(state, sandbox, mcp_tools, agents, orchestrator)"]
    L3["platform_core.layer3_evolution\n(memory, data_factory, evaluation, observability)"]
    SEC["platform_core.deploy_security\n(governance)"]

    CLI --> L1
    CLI --> L2
    CLI --> L3
    L2 --> L1
    L2 --> L3
    L2 --> SEC
    L1 --> L3
    L1 --> SEC
    L3 --> SEC
```

**Dependency Invariants**:
- `platform_core.deploy_security` is the foundational zero-internal-dependency security layer; it imports only Python standard library modules (`dataclasses`, `enum`, `hashlib`, `hmac`, `ipaddress`, `json`, `math`, `pathlib`, `struct`, `typing`, `urllib.parse`).
- `platform_core.layer3_evolution` depends only on `deploy_security` (`LicenseComplianceAuditor` in `data_factory.py`) and standard library modules.
- `platform_core.layer1_intelligence` depends on `deploy_security` (`LicenseComplianceAuditor`, `SafetensorsValidator`) and `layer3_evolution` (`DatasetHygienePipeline`, data factories, and `BenchmarkEvaluator` inside `training.py`).
- `platform_core.layer2_execution` orchestrates `layer1_intelligence` (`AdaptiveModelRouter`, `ModelPool`), `layer3_evolution` (`BitemporalEpisodicMemory`), and `deploy_security` (`SignedManifestVerifier`, `CyberGymFirewall`).

---

## 2. Layer 1 (`layer1_intelligence`) Component Diagram & Classes

Source directory: [`src/platform_core/layer1_intelligence/`](../../src/platform_core/layer1_intelligence/)

```mermaid
classDiagram
    class ModelSpec {
        +str model_id
        +ModelPool pool
        +float total_params_b
        +float active_params_b
        +int context_window
        +str license_id
        +to_dict() dict
        +from_dict(data) ModelSpec
    }
    class ModelRegistry {
        +register_model(spec, set_as_pool_default) LicenseAuditResult
        +get_model(model_id) ModelSpec
        +get_pool_override(pool) ModelSpec
        +list_by_pool(pool) list~ModelSpec~
        +all_models() list~ModelSpec~
    }
    class AdaptiveModelRouter {
        +ModelRegistry registry
        +route(request) RoutingDecision
    }
    class BestOfNVerifierPruner {
        +select_best_candidate(candidates, custom_verifier) CandidateRollout
    }
    class ServingEndpointConfig {
        +str engine
        +str model_id
        +str quantization
        +int port
        +to_launch_args() list~str~
    }
    class RadixPrefixCacheSimulator {
        +record_request(token_blocks, active_params_b) dict
        +cumulative_hit_ratio() float
        +build_default_pool_configs(models) list~ServingEndpointConfig~
    }
    class CustomModelPipeline {
        +resolve_pool(domain, explicit_pool) ModelPool
        +load_trajectories_from_file(dataset_file) list~TrainingTrajectoryRecord~
        +build_custom_model(config, custom_trajectories, output_dir, registry, set_as_pool_default) CustomModelArtifact
        +load_custom_model_manifest(manifest_path, registry, set_as_pool_default) dict
    }

    ModelRegistry "1" *-- "5..*" ModelSpec
    AdaptiveModelRouter --> ModelRegistry
    CustomModelPipeline --> ModelRegistry
    CustomModelPipeline --> ServingEndpointConfig
```

| File | Public Classes & Enums | Responsibility |
| :--- | :--- | :--- |
| [`models.py`](../../src/platform_core/layer1_intelligence/models.py) | `ModelPool`, `ThinkingMode`, `ModelSpec`, `ScenarioBudgetProfile`, `ModelRegistry`, `HardwareFeasibilityPlanner` | Model catalog, license-gated registration, pool default overrides, and Scenario A/B/C financial/GPU break-even planning. |
| [`router.py`](../../src/platform_core/layer1_intelligence/router.py) | `RoutingRequest`, `RoutingDecision`, `CandidateRollout`, `AdaptiveModelRouter`, `BestOfNVerifierPruner` | Domain/token/modality routing, entropy-bounded thinking budgets (`NON_THINK`, `THINK_HIGH`, `THINK_MAX`), and `TTS@N` rollout pruning. |
| [`serving.py`](../../src/platform_core/layer1_intelligence/serving.py) | `ServingEndpointConfig`, `RadixPrefixCacheSimulator` | Deterministic SGLang v0.5.19 / vLLM v0.28 CLI flag generation and RadixAttention prefix tree hit-rate/TTFT simulation. |
| [`training.py`](../../src/platform_core/layer1_intelligence/training.py) | `SWECyberEvaluationInput`, `SWECyberRewardOracle`, `StructFieldSpan`, `BinRevDecompileInput`, `BinRevDecompileRewardOracle`, `GRPORolloutSample`, `GRPOStepMetrics`, `GRPOTrainer`, `TeacherModelDescriptor`, `MOPDDistiller`, `DistributedTrainingSpecBuilder`, `DPOPreferencePair`, `DPOStepMetrics`, `DPOTrainer`, `CustomModelConfig`, `CustomModelArtifact`, `CustomModelPipeline` | 5-Stage post-training algorithms, verifiable execution reward oracles, FSDP2/ZeRO-3 sharding spec generation, and atomic `.safetensors` + `.manifest.json` creation/loading. |

---

## 3. Layer 2 (`layer2_execution`) Component Diagram & Classes

Source directory: [`src/platform_core/layer2_execution/`](../../src/platform_core/layer2_execution/)

```mermaid
classDiagram
    class ExecutionLifecycleOrchestrator {
        +SQLiteStateCheckpointer checkpointer
        +AdaptiveModelRouter router
        +FirecrackerSandboxManager sandbox
        +BitemporalEpisodicMemory episodic_memory
        +SignedManifestVerifier manifest_verifier
        +run_workflow(...) PlatformState
        +approve_and_resume(...) PlatformState
        +close() None
    }
    class SQLiteStateCheckpointer {
        +save_checkpoint(state) int
        +load_latest(session_id) PlatformState
        +load_at_step(session_id, step) PlatformState
        +list_history(session_id) list~dict~
        +close() None
    }
    class FirecrackerSandboxManager {
        +provision_microvm(vm_id, initial_files, tainted) dict
        +create_cow_snapshot(vm_id) CoWSnapshot
        +restore_cow_snapshot(snapshot_id) dict
        +execute_python_in_sandbox(vm_id, python_code, timeout_sec) SandboxExecutionResult
    }
    class BaseSpecialistAgent {
        +AgentNodeDescriptor descriptor
        +set_subtask_status(subtask, new_status) None
    }
    class IndependentVerifierAgent {
        +verify_subtask(subtask, sandbox, vm_id, cyber_mcp) dict
    }

    ExecutionLifecycleOrchestrator --> SQLiteStateCheckpointer
    ExecutionLifecycleOrchestrator --> FirecrackerSandboxManager
    ExecutionLifecycleOrchestrator --> BaseSpecialistAgent
    BaseSpecialistAgent <|-- IndependentVerifierAgent
```

| File | Public Classes & Enums | Responsibility |
| :--- | :--- | :--- |
| [`state.py`](../../src/platform_core/layer2_execution/state.py) | `TaintLevel`, `TaskStatus`, `LifecycleStep`, `ArtifactRef`, `ApprovalRequest`, `SubTask`, `PlatformState`, `SQLiteStateCheckpointer` | Typed shared workflow state, out-of-context artifact pointers, and thread-safe SQLite WAL checkpoint persistence with time-travel replay. |
| [`sandbox.py`](../../src/platform_core/layer2_execution/sandbox.py) | `CoWSnapshot`, `SandboxExecutionResult`, `FirecrackerSandboxManager` | 24-syscall seccomp profile definition, credential env-var stripping, isolated `python3 -I` subprocess execution, symlink-safe sync-back, and `<15ms` CoW snapshot rollback. |
| [`mcp_tools.py`](../../src/platform_core/layer2_execution/mcp_tools.py) | `CodeSymbolNode`, `CodeGraphMCPServer`, `BinRevMCPServer`, `CPGVulnerabilityFinding`, `DefensiveCyberMCPServer`, `TransformationClass`, `VisualRegionObservation`, `DataAndVisualMCPServer` | Deterministic program analysis, binary decompilation (`SK²Decompile` + `ReCopilot`), CPG taint scanning, `SecVerifier` dual-gate verification, entropy/transformation classification, Kaitai `.ksy` synthesis, and epistemic visual grounding. |
| [`agents.py`](../../src/platform_core/layer2_execution/agents.py) | `AgentNodeDescriptor`, `BaseSpecialistAgent`, `PrincipalOrchestratorAgent`, `SoftwareEngineeringAgent`, `ReverseEngineeringAgent`, `DefensiveCyberAgent`, `MultimodalDataAgent`, `IndependentVerifierAgent` | The 6 specialist agent nodes and structural enforcement of the `can_mark_completed` invariant. |
| [`orchestrator.py`](../../src/platform_core/layer2_execution/orchestrator.py) | `ExecutionLifecycleOrchestrator` | Executes Steps 1–10 of the reliable agent lifecycle, human `interrupt()` approval pause/resume, and CoW rollback + `TTS@4` retry escalation. |

---

## 4. Layer 3 (`layer3_evolution`) Component Diagram & Classes

Source directory: [`src/platform_core/layer3_evolution/`](../../src/platform_core/layer3_evolution/)

| File | Public Classes & Enums | Responsibility |
| :--- | :--- | :--- |
| [`memory.py`](../../src/platform_core/layer3_evolution/memory.py) | `ProgressionEvent`, `BitemporalFactEdge`, `BitemporalEpisodicMemory`, `KnowledgeDocumentChunk`, `HybridKnowledgeStore` | Append-only GAM event graph, bitemporal Graphiti fact edges with point-in-time queries, and 200K-token `DIRECT_PREFIX_CACHE` vs `HYBRID_PGVECTORSCALE_SEARCH` retrieval. |
| [`data_factory.py`](../../src/platform_core/layer3_evolution/data_factory.py) | `TrainingTrajectoryRecord`, `SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, `DatasetHygienePipeline` | Trajectory synthesis for SWE, CVE remediation, and stripped binary decompilation, plus 4-gate decontamination and Jaccard deduplication. |
| [`evaluation.py`](../../src/platform_core/layer3_evolution/evaluation.py) | `MultiRunBenchmarkResult`, `BenchmarkEvaluator`, `PropBenchSpec`, `PropBench9Suite` | Multi-run 95% confidence intervals, $\text{pass}@1$ and $\text{pass}^k$ consistency ratios, Canary Promotion Gate, and the 9 `PropBench-9` benchmark specifications. |
| [`observability.py`](../../src/platform_core/layer3_evolution/observability.py) | `TraceOutcome`, `FailureRootCauseBucket`, `ProductionTraceRecord`, `ControlledImprovementCycle` | 8-Step continuous improvement loop with automated failure clustering, root-cause attribution, unverified-prose filtering, and canary gating. |

---

## 5. Deploy & Security (`deploy_security`) Component Diagram & Classes

Source directory: [`src/platform_core/deploy_security/`](../../src/platform_core/deploy_security/)

| File | Public Classes & Enums | Responsibility |
| :--- | :--- | :--- |
| [`governance.py`](../../src/platform_core/deploy_security/governance.py) | `PickleSupplyChainError`, `SafetensorsValidationError`, `LicenseVerdict`, `LicenseAuditResult`, `LicenseComplianceAuditor`, `SafetensorsValidator`, `MCPToolManifest`, `SignedManifestVerifier`, `FirewallDecision`, `CyberGymFirewall`, `K8sAgentSandboxGenerator` | Supply-chain checkpoint verification, commercial/EU license auditing, HMAC-SHA256 tool manifest signing, taint-aware network firewall, and Kubernetes `agent-sandbox` CRD generation. |

---

## 6. CLI Entrypoint (`cli.py`) Component Mapping

[`src/platform_core/cli.py`](../../src/platform_core/cli.py) exposes the `platform-cli` console script (`project.scripts` in `pyproject.toml`) and top-level helper functions:

| CLI Subcommand | Backing Python Function in `cli.py` | Underlying Subsystems Invoked |
| :--- | :--- | :--- |
| `evaluate-blueprint` | `run_evaluate_blueprint(budget_usd)` | `ModelRegistry`, `RadixPrefixCacheSimulator`, `HardwareFeasibilityPlanner`, `PropBench9Suite` |
| `train-model` | `run_model_creation_pipeline(...)` | `CustomModelPipeline.load_trajectories_from_file`, `CustomModelPipeline.build_custom_model` |
| `create-custom-model` | `run_model_creation_pipeline(...)` | `CustomModelPipeline.load_trajectories_from_file`, `CustomModelPipeline.build_custom_model` |
| `run-workflow` | `run_demo_workflow(...)` | `ExecutionLifecycleOrchestrator.run_workflow`, `_load_custom_workflow_payload` |
| `run-custom-model` | `run_demo_workflow(...)` | `CustomModelPipeline.load_custom_model_manifest`, `ExecutionLifecycleOrchestrator.run_workflow` |
| `inspect-data` | `main()` (`args.command == "inspect-data"`) | `DataAndVisualMCPServer.classify_transformation`, `DataAndVisualMCPServer.synthesize_kaitai_struct_ksy` |

---

## 7. Related Documentation

- [System Architecture](system-architecture.md)
- [Data Flow & State Lifecycles](data-flow.md)
- [Module Reference (`docs/modules/`)](../modules/README.md)
- [API & CLI Contracts (`docs/api/README.md`)](../api/README.md)
