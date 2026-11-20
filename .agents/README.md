# `.agents` — Project Brain, Swarm & Delivery Artifacts, and Workspace Skills

This directory stores the persistent Project Brain / Second Brain under [`brain/`](brain/README.md), intermediate engineering and delivery artifacts under `artifacts/<feature-slug>/`, and reusable workspace skills under `skills/<skill-name>/` (keeping all workspace `.md` links relative and portable across checkouts).

## Persistent Project Brain / Second Brain (`brain/`)

Structured architectural memory, symbol ontology, domain playbooks, and bitemporal fact seed for AI coding agents and human contributors:

| Brain Document | Purpose |
| :--- | :--- |
| [`brain/README.md`](brain/README.md) | Master cognitive hub, 4-layer matrix, 8-domain routing table, 6-agent dual-gate topology, and CLI quick-reference |
| [`brain/knowledge-graph.md`](brain/knowledge-graph.md) | Architectural knowledge graph, entity-relationship dependency chains, lifecycle state machines, and `ADR-0001`..`ADR-0009` index |
| [`brain/domain-playbooks-and-invariants.md`](brain/domain-playbooks-and-invariants.md) | Deep-dive into the 7 architectural invariants, 8 domain playbooks, model creation recipes, and troubleshooting memory |
| [`brain/symbol-and-contract-index.md`](brain/symbol-and-contract-index.md) | Complete symbol dictionary across 5 subpackages (`24` implementation modules) & `211` automated tests, 5 SQLite WAL schemas, 23 CLI subcommands, and 18 MCP stdio tools |
| [`brain/brain-knowledge-graph.json`](brain/brain-knowledge-graph.json) | Machine-readable JSON ontology and bitemporal fact seed for `BitemporalEpisodicMemory` & `HybridKnowledgeStore` |
| [`brain/corpus-swe-arch-and-product.md`](brain/corpus-swe-arch-and-product.md) | Curated SWE, Software Architecture & Product Discovery corpus (`MOD-SWE-01`, `MOD-SWE-02`, `MOD-PROD-01`, `MOD-PROD-02`) |
| [`brain/corpus-android-security-masvs.md`](brain/corpus-android-security-masvs.md) | Curated Android 12–15+ Security Engineering & OWASP MASVS v2 / MASTG corpus (`MOD-AND-01`..`MOD-AND-04`) |
| [`brain/corpus-ios-security-masvs.md`](brain/corpus-ios-security-masvs.md) | Curated iOS 14–18+ Security Engineering, Apple Platform Security & OWASP MASVS v2 / MASTG corpus (`MOD-IOS-01`..`MOD-IOS-04`) |
| [`brain/corpus-obfuscation-and-multimodal.md`](brain/corpus-obfuscation-and-multimodal.md) | Curated De-Obfuscation, Finite-Sample Entropy, Visual Diagram & RIFF/WAVE Audio Grounding corpus (`MOD-OBF-01`, `MOD-OBF-02`, `MOD-MM-01`, `MOD-MM-02`) |
| [`brain/multimodal-training-corpus.jsonl`](brain/multimodal-training-corpus.jsonl) | 12 execution-verified Apache-2.0 JSONL training trajectories covering `MOD-SWE-01`..`MOD-OBF-01` for `CustomModelPipeline` & `ProjectBrainEngine` |

## Workspace Skills (`skills/`)

Discovered and validated automatically by `AgySkillDiscovery.discover_skills([".agents/skills"])`:

| Skill Name | Entrypoint | Primary `platform_core` Module / CLI |
| :--- | :--- | :--- |
| `corpus-harvester` | [`SKILL.md`](skills/corpus-harvester/SKILL.md), [`harvest_corpus.py`](skills/corpus-harvester/scripts/harvest_corpus.py) | `corpus_harvester.py` / `harvest-corpus` |
| `local-model-advisor` | [`SKILL.md`](skills/local-model-advisor/SKILL.md), [`recommend_strategy.py`](skills/local-model-advisor/scripts/recommend_strategy.py) | `scratch_trainer.py` (`CreationStrategyAdvisor`) / `recommend-strategy` |
| `scratch-slm-trainer` | [`SKILL.md`](skills/scratch-slm-trainer/SKILL.md), [`train_scratch_slm.py`](skills/scratch-slm-trainer/scripts/train_scratch_slm.py) | `scratch_trainer.py` (`CompactTransformerSLMTrainer`) / `train-scratch-slm` |
| `pretrained-qlora-finetuner` | [`SKILL.md`](skills/pretrained-qlora-finetuner/SKILL.md), [`run_qlora_pipeline.py`](skills/pretrained-qlora-finetuner/scripts/run_qlora_pipeline.py) | `training.py` (`CustomModelPipeline`) / `create-custom-model` |
| `agy-local-agent-runner` | [`SKILL.md`](skills/agy-local-agent-runner/SKILL.md), [`run_agy_agent.py`](skills/agy-local-agent-runner/scripts/run_agy_agent.py) | `agy_sdk_bridge.py` (`AgyLocalOrchestrator`, `AgyStdioMCPBridge`) / `run-agy-local`, `mcp-stdio-bridge` |

## Feature Artifact Sets (`artifacts/`)

| Feature Slug | Status | Phase | Entry Point |
| :--- | :--- | :--- | :--- |
| `proprietary-ai-platform` | Complete | Phase 4 — Final Delivery Complete | [STATUS.md](artifacts/proprietary-ai-platform/STATUS.md) |
| `local-first-custom-ai-platform` | Complete | Phase 6 — Verified & Released | [STATUS.md](artifacts/local-first-custom-ai-platform/STATUS.md) |
| `ultimate-local-model-creator` | Complete | Phase 4 — Completed / PASS (`49/49` tests) | [STATUS.md](artifacts/ultimate-local-model-creator/STATUS.md) |

## Governance & Relative Link Rules

- Keep `.agents/artifacts/` out of production commits unless explicitly requested.
- Use repository-relative Markdown links (for example, `[models.py](../src/platform_core/layer1_intelligence/models.py)` from `.agents/`, or `../../../src/...` from `artifacts/<feature-slug>/`) rather than host-specific local URIs or absolute filesystem paths.
- Follow workspace invariants in [AGENTS.md](../AGENTS.md) and documentation checks in [DOCUMENTATION_STANDARDS.md](../docs/DOCUMENTATION_STANDARDS.md).
