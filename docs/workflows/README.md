# Platform Workflows Index

This directory documents the three core end-to-end execution and learning workflows implemented in `platform-core`.

---

## Workflows

| Workflow Document | Primary Orchestrator / Engine | Steps | Summary |
| :--- | :--- | :--- | :--- |
| [10-Step Agent Execution Lifecycle](agent-execution-lifecycle.md) | `ExecutionLifecycleOrchestrator` ([`orchestrator.py`](../../src/platform_core/layer2_execution/orchestrator.py)) | Steps 1–10 (`LifecycleStep`) | Ingests tasks, classifies taint, indexes code graphs, routes models/thinking budgets, verifies HMAC-signed MCP scopes, enforces optional human `interrupt()` approval, runs inside Firecracker microVMs with pre-execution CoW snapshots, verifies via `IndependentVerifierAgent`, rolls back/escalates to `TTS@4` on failure, and consolidates bitemporal memory. |
| [5-Stage Model Post-Training & Custom Model Pipeline](model-post-training-pipeline.md) | `CustomModelPipeline` ([`training.py`](../../src/platform_core/layer1_intelligence/training.py)) | Stages 1–5 + Packaging & Canary Gate | Synthesizes/loads trajectories, filters via 4-gate `DatasetHygienePipeline`, generates FSDP2/ZeRO-3 sharding specs, runs `MOPDDistiller`, `GRPOTrainer` + verifiable reward oracles, and `DPOTrainer`, validates `.safetensors` checkpoints, evaluates the 5-run Canary Promotion Gate, and atomically writes `.safetensors` + `.manifest.json`. |
| [8-Step Controlled Improvement Cycle](controlled-improvement-cycle.md) | `ControlledImprovementCycle` ([`observability.py`](../../src/platform_core/layer3_evolution/observability.py)) | Steps 1–8 | Aggregates production trace outcomes, clusters failures, attributes root causes (`KNOWLEDGE_GAP_RAG_SCIP`, `TOOLING_PARSER_BUG`, `MODEL_WEIGHT_REASONING_GAP`), generates sandbox repro tasks, curates compiler/test-verified trajectories (rejecting unverified prose), triggers offline SFT+GRPO, and enforces the Canary Promotion Gate. |

---

## Related Documentation

- [Architecture Data Flow](../architecture/data-flow.md)
- [Custom Model Creation & Execution Guide](../CUSTOM_MODEL_GUIDE.md)
- [Step-by-Step How-To Guides](../HOW_TO_GUIDES.md)
