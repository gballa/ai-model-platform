# `platform_core.data_ingestion` — Synthetic Trajectory Factories & Dataset Hygiene

---

## 1. Module Responsibilities and Boundaries

`platform_core.data_ingestion` ([`data_factory.py`](data_factory.py)) provides deterministic training trajectory synthesis and 4-gate dataset hygiene filtering prior to Layer 1 post-training (`CustomModelPipeline`) and Layer 3 corpus distillation (`CorpusHarvesterPipeline`):

- **Trajectory Record Schema (`TrainingTrajectoryRecord`)**: Frozen dataclass capturing `record_id`, `domain`, `source_repo`, `license_id`, `cve_id`, `prompt_context`, `target_completion`, `execution_verified`, and optional `metadata`.
- **Three Domain Trajectory Factories**:
  - `SWEFuseFactory` (`build_pair()`): Generates paired guided vs. issue-free software-engineering remediation trajectories.
  - `SecBenchFactory` (`build_record()`): Generates CVE vulnerability remediation trajectories with Sanitizer/PoC grounding (tracking `INSTANCE_GENERATION_COST_USD = 0.87`).
  - `DecompileBenchFactory` (`build_record()`): Validates compiler optimization levels (`-O0`, `-O1`, `-O2`, `-O3`, `-Os`) and emits ReCopilot stripped-binary decompilation records.
- **4-Gate Dataset Decontamination & Hygiene (`DatasetHygienePipeline`)**:
  1. **Gate 1 (`license_rejected`)**: Enforces `APPROVED_COMMERCIAL` licenses via `LicenseComplianceAuditor`.
  2. **Gate 2 (`benchmark_contaminated`)**: Blocks repos and CVEs matching `DEFAULT_BENCHMARK_REPO_BLOCKLIST` and `DEFAULT_CVE_BLOCKLIST`.
  3. **Gate 3 (`execution_unverified`)**: Rejects empty completions or `execution_verified=False` records.
  4. **Gate 4 (`near_duplicate`)**: Uses 3-token shingle BLAKE2b hashing and Jaccard similarity (`< 0.85` default threshold) to prevent duplicate trajectories.

> [!NOTE]
> `platform_core.layer3_evolution` re-exports all five public symbols (`TrainingTrajectoryRecord`, `SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, `DatasetHygienePipeline`) for backward compatibility.

---

## 2. Main Components

| File | Public Symbols | Key Methods |
| :--- | :--- | :--- |
| [`__init__.py`](__init__.py) | Package exports | Re-exports `TrainingTrajectoryRecord`, `SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, `DatasetHygienePipeline` |
| [`data_factory.py`](data_factory.py) | `TrainingTrajectoryRecord`, `SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, `DatasetHygienePipeline` | `build_pair()`, `build_record()`, `filter_records()` |

---

## 3. Dependencies and Integrations

- **Internal Dependencies**: `platform_core.deploy_security.governance` (`LicenseComplianceAuditor`, `LicenseVerdict`).
- **Consumers**: `platform_core.layer1_intelligence.training` (`CustomModelPipeline`), `platform_core.layer3_evolution.corpus_harvester` (`TeacherDistiller`), `platform_core.layer3_evolution` (re-export facade), and [`scripts/synthesize_v4_trajectories.py`](../../../scripts/synthesize_v4_trajectories.py).

---

## 4. Related Documentation

- [Layer 3 & Data Ingestion Module Reference](../../../docs/modules/layer3-evolution.md)
- [5-Stage Model Post-Training Pipeline](../../../docs/workflows/model-post-training-pipeline.md)
- [Core Package Overview](../README.md)
