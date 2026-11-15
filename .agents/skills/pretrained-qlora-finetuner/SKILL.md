---
name: pretrained-qlora-finetuner
description: >-
  Use this skill when fine-tuning or specializing an approved open-weight base
  model via QLoRA (Apple Silicon MLX or PyTorch PEFT/TRL), running dataset
  hygiene and license audits, and evaluating Safetensors model manifests.
---

# Pre-Trained QLoRA Fine-Tuner & Post-Training Orchestrator

## Overview

Orchestrates pre-trained-first specialization on local hardware or multi-GPU clusters without duplicating training or verification logic. Composes `LocalHardwareDetector`, `HardwareFeasibilityPlanner`, `LicenseComplianceAuditor`, `DatasetHygienePipeline`, `MLXQLoRATrainer`, `TorchTRLSpecAndRunner`, `CustomModelPipeline`, and `BenchmarkSuiteRunner`—producing verified `.safetensors` + `.manifest.json` artifacts and runnable MLX/PEFT QLoRA configs even when optional GPU packages are absent.

## Dependencies

- **Runtime**: `.venv/bin/python` works out of the box with `PYTHONPATH=src` and zero extra pip installs for `plan`, `evaluate`, `spec_only`, and `torch_trl` script/dataset generation.
- **Optional extras**:
  - `pip install -e ".[mlx]"` (`mlx`, `mlx-lm`, `huggingface-hub`) for live Apple Silicon 4-bit QLoRA training and adapter fusion.
  - `pip install -e ".[train]"` (`torch`, `transformers`, `peft`, `trl`) for executing generated CUDA PyTorch PEFT/TRL scripts.
- **Upstream / Downstream skills**:
  - `corpus-harvester`: Supplies distilled `TrainingTrajectoryRecord` JSONL datasets.
  - `local-model-advisor`: Confirms `PRETRAINED_QLORA_FIRST` or `MULTI_GPU_FULL_POST_TRAIN` fits local memory before training.
  - `agy-local-agent-runner`: Runs the resulting specialized model with local skills and MCP tools.

## Quick Start

1. Audit license, hardware budget, and dataset hygiene, and emit a QLoRA plan:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/pretrained-qlora-finetuner/scripts/run_qlora_pipeline.py \
     plan --base-checkpoint fdtn-ai/Foundation-Sec-8B-Reasoning --license Apache-2.0 \
     --domain cyber --limit 50 --output artifacts/qlora_plan.json
   ```
2. Run the 5-stage post-training pipeline (exports verified `.safetensors`, `.manifest.json`, `training_data/`, and runnable `lora_config.json` / `train_trl_pipeline.py` without requiring GPU packages):
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/pretrained-qlora-finetuner/scripts/run_qlora_pipeline.py \
     train --model-id foundation-sec-8b-custom --base-checkpoint fdtn-ai/Foundation-Sec-8B-Reasoning \
     --domain cyber --output-dir artifacts/custom_qlora --limit 100 --output artifacts/qlora_train.json
   ```
3. Verify the exported manifest, `.safetensors` SHA-256, and platform benchmarks:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/pretrained-qlora-finetuner/scripts/run_qlora_pipeline.py \
     evaluate --manifest artifacts/custom_qlora/foundation-sec-8b-custom.manifest.json \
     --run-benchmarks --limit 5 --output artifacts/qlora_eval.json
   ```

## Utility Scripts

All commands reside in [scripts/run_qlora_pipeline.py](scripts/run_qlora_pipeline.py), write JSON via `--output`, and require explicit `--limit` (no silent caps). Both `PYTHONPATH=src .venv/bin/python` and `.venv/bin/python` are supported.

- **`plan`**: Audits license compliance (`LicenseComplianceAuditor`), detects hardware (`LocalHardwareDetector`), evaluates blueprint ROI (`HardwareFeasibilityPlanner`), filters optional `--dataset-file` trajectories (`DatasetHygienePipeline`), checks installed MLX/PyTorch/PEFT packages, and emits both `MLXQLoRATrainer` and PyTorch `PEFT`/`TRL` QLoRA specs.
  - Required: `--limit <int>`, `--output <path>`.
  - Optional: `--base-checkpoint <id>`, `--license <spdx>`, `--domain <str>`, `--dataset-file <path>`, `--lora-rank <int>`.
- **`train`**: Executes `CustomModelPipeline.build_custom_model(...)` with `DatasetHygienePipeline` filtering, `MOPDDistiller`, `GRPOTrainer`, `DPOTrainer`, `SafetensorsValidator`, and `BenchmarkEvaluator` canary promotion. In `auto` mode, adapts safely if `mlx-lm` or `torch` is not installed.
  - Required: `--model-id <id>`, `--output-dir <dir>`, `--limit <int>`, `--output <path>`.
  - Optional: `--base-checkpoint <id>`, `--domain <str>`, `--license <spdx>`, `--dataset-file <path>`, `--execution-mode <auto|spec_only|mlx_qlora|torch_trl>`, `--lora-rank <int>`, `--training-iters <int>`, `--live-mlx`.
- **`evaluate`**: Verifies `<model_id>.manifest.json` + `.safetensors` checksum via `CustomModelPipeline.load_custom_model_manifest(...)` and optionally executes `BenchmarkSuiteRunner.run_all_suites(...)`.
  - Required: `--manifest <path>`, `--limit <int>`, `--output <path>`.
  - Optional: `--run-benchmarks`.

## Common Mistakes

1. **Using prohibited base/teacher licenses (`GPL-3.0`, `Llama-4-Community`, `Proprietary-Closed-API`)**: `LicenseComplianceAuditor` rejects any license outside `APPROVED_COMMERCIAL`.
2. **Expecting live GPU weights update without `--live-mlx` / optional extras**: Without `[mlx]` or `[train]` installed, `auto` mode generates clean QLoRA configs, chat JSONL splits, and verified `.safetensors` metadata checkpoints without failing.
3. **Providing contaminated benchmark holdout repos/CVEs in `--dataset-file`**: `DatasetHygienePipeline` drops contaminated, unverified, or near-duplicate records before training.
