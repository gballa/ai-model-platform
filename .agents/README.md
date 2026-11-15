# `.agents` — Swarm & Delivery Artifacts and Workspace Skills

This directory stores intermediate engineering and delivery artifacts under `artifacts/<feature-slug>/` and reusable workspace skills under `skills/<skill-name>/` (keeping all workspace `.md` links relative and portable across checkouts).

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
- Use repository-relative Markdown links (for example, `[models.py](../src/platform_core/layer1_intelligence/models.py)` from `.agents/`, or `../../../src/...` from `artifacts/<feature-slug>/`) rather than host-specific `file://` URIs or absolute filesystem paths.
- Follow workspace invariants in [AGENTS.md](../AGENTS.md) and documentation checks in [DOCUMENTATION_STANDARDS.md](../docs/DOCUMENTATION_STANDARDS.md).
