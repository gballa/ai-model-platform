# `platform_core` — Core Python Package

---

## 1. Module Responsibilities and Boundaries

`platform_core` (`src/platform_core/`) is the installable root Python package (`version = "1.0.0"`) for the **Proprietary Technical Intelligence Platform**. It exposes the unified command-line interface (`cli.py`) and organizes the platform into five strictly bounded subpackages:
1. [`layer1_intelligence`](layer1_intelligence/README.md) — Model registry, hardware profiling, routing, serving configs, 5-stage post-training, strategy advising, compact scratch SLM training, and Heretic / GAIN / Cold-Fusion / IMatrix weight post-processing.
2. [`layer2_execution`](layer2_execution/README.md) — 10-step checkpointed execution, 6 specialist agents, 6 MCP tool servers, Firecracker CoW sandboxing, and the Google Antigravity SDK / MCP stdio bridge.
3. [`layer3_evolution`](layer3_evolution/README.md) — Bitemporal episodic memory, 200K-token hybrid knowledge store, corpus harvesting & distillation, Project Brain engine (`ProjectBrainEngine`), `PropBench-9` evaluation, and the 8-step controlled improvement cycle.
4. [`data_ingestion`](data_ingestion/README.md) — Synthetic trajectory factories (`SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`) and 4-gate `DatasetHygienePipeline` (re-exported by `layer3_evolution`).
5. [`deploy_security`](deploy_security/README.md) — Safetensors validation, license compliance, HMAC-signed tool manifests, `CyberGymFirewall`, and Kubernetes sandbox CRDs.

---

## 2. Internal Architecture

```mermaid
flowchart TB
    CLI["cli.py (platform-cli: 23 Subcommands)"]
    L1["layer1_intelligence"]
    L2["layer2_execution"]
    L3["layer3_evolution"]
    DI["data_ingestion"]
    SEC["deploy_security"]

    CLI --> L1
    CLI --> L2
    CLI --> L3
    CLI --> DI
    L2 --> L1
    L2 --> L3
    L2 --> SEC
    L1 --> L3
    L1 --> DI
    L1 --> SEC
    L3 --> DI
    L3 --> SEC
    DI --> SEC
```

---

## 3. Main Components

| File / Subpackage | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`__init__.py`](__init__.py) | `__version__ = "1.0.0"` | Package version and top-level metadata. |
| [`cli.py`](cli.py) | `main`, `run_evaluate_blueprint`, `run_transparency_dashboard`, `run_model_creation_pipeline`, `run_demo_workflow`, `run_harvest_corpus`, `run_recommend_strategy`, `run_train_scratch_slm`, `run_agy_local_command`, `run_mcp_stdio_bridge` | Unified CLI (`platform-cli`, 23 subcommands) and programmatic orchestration helpers. |
| [`layer1_intelligence/`](layer1_intelligence/README.md) | `ModelRegistry`, `AdaptiveModelRouter`, `ServingEndpointConfig`, `CustomModelPipeline`, `CreationStrategyAdvisor`, `BytePairTokenizer`, `CompactTransformerSLMTrainer`, `HereticAbliterator`, `GAINAdaptiveScheduler`, `ColdFusionModelMerger`, `ImatrixQuantizationCalibrator` | Layer 1 Intelligence, Post-Training, Scratch SLM Creation & Heretic/Cold-Fusion Weight Surgery. |
| [`layer2_execution/`](layer2_execution/README.md) | `ExecutionLifecycleOrchestrator`, `PlatformState`, `SQLiteStateCheckpointer`, `FirecrackerSandboxManager`, 6 Agents, 6 MCP Servers, `AgyLocalOrchestrator`, `AgyStdioMCPBridge` | Layer 2 Stateful Execution, Sandboxing & Google Antigravity SDK Bridge. |
| [`layer3_evolution/`](layer3_evolution/README.md) | `BitemporalEpisodicMemory`, `HybridKnowledgeStore`, `ProjectBrainEngine`, `CorpusHarvesterPipeline`, `BenchmarkEvaluator`, `BenchmarkSuiteRunner`, `ControlledImprovementCycle` | Layer 3 Evolution, Project Brain Sync/Pipeline, Corpus Harvesting, Memory & Evaluation. |
| [`data_ingestion/`](data_ingestion/README.md) | `TrainingTrajectoryRecord`, `SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, `DatasetHygienePipeline` | Trajectory synthesis factories & 4-gate decontamination/deduplication pipeline. |
| [`deploy_security/`](deploy_security/README.md) | `SafetensorsValidator`, `LicenseComplianceAuditor`, `SignedManifestVerifier`, `CyberGymFirewall`, `K8sAgentSandboxGenerator` | Cross-cutting supply-chain and runtime security. |

---

## 4. Dependencies and Integrations

- **External Runtime Dependencies**: Zero (`dependencies = []` in [`pyproject.toml`](../../pyproject.toml)).
- **Standard Library Dependencies**: `argparse`, `ast`, `base64`, `collections`, `copy`, `dataclasses`, `enum`, `gzip`, `hashlib`, `hmac`, `ipaddress`, `json`, `math`, `os`, `pathlib`, `re`, `sqlite3`, `statistics`, `struct`, `subprocess`, `sys`, `tempfile`, `threading`, `time`, `typing`, `urllib.parse`, `zlib`.

---

## 5. Execution and Data Flow

See [docs/architecture/data-flow.md](../../docs/architecture/data-flow.md) for sequence and state diagrams covering both `ExecutionLifecycleOrchestrator.run_workflow()` (Steps 1–10) and `CustomModelPipeline.build_custom_model()` (Stages 1–7).

---

## 6. Configuration Requirements

Requires Python `>= 3.11`. When running without an editable install, set `PYTHONPATH=src`. See [docs/development/configuration.md](../../docs/development/configuration.md).

---

## 7. Usage Examples

```bash
# Run CLI subcommands from repository root
PYTHONPATH=src .venv/bin/python -m platform_core.cli evaluate-blueprint --budget 1800000
PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain swe
```

---

## 8. Testing and Troubleshooting

```bash
PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v
```

See [docs/development/troubleshooting.md](../../docs/development/troubleshooting.md) for error resolution.

---

## 9. Related Documentation

- [Root Repository README](../../README.md)
- [Central Documentation Hub](../../docs/README.md)
- [CLI Module Reference](../../docs/modules/cli.md)
