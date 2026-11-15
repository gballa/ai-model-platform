---
name: local-model-advisor
description: >-
  Use this skill when deciding whether to use RAG, QLoRA fine-tuning on an
  open-weight base model, multi-GPU post-training, or a from-scratch compact SLM
  for the host hardware and corpus token budget.
---

# Local Model Creation Strategy Advisor

## Overview

Inspects host CPU/GPU/Unified Memory via `LocalHardwareDetector` and pairs hardware capacity with corpus size (`corpus_tokens`) and domain requirements via `CreationStrategyAdvisor`. Follows the platform's pre-trained-first engineering hierarchy (`PRETRAINED_RAG_ONLY` for `< 50,000` tokens, `PRETRAINED_QLORA_FIRST` for `>= 50,000` tokens on 36 GB Apple Silicon / workstation budgets, `FROM_SCRATCH_COMPACT_SLM` when custom tokenization or `10M–350M` models are required, and `MULTI_GPU_FULL_POST_TRAIN` on cluster hardware).

## Dependencies

- **Runtime**: `.venv/bin/python` works out of the box with `PYTHONPATH=src` and zero extra pip installs for core/fallback paths (pure stdlib hardware detection via `sysctl`, `/proc/meminfo`, or `nvidia-smi`).
- **Optional extras**: `mlx` / `train` extras are only needed later when executing training via downstream skills.
- **Related skills**:
  - `corpus-harvester`: Supplies `total_tokens_est` from harvested PDFs/web pages.
  - `pretrained-qlora-finetuner`: Next step when `recommend` returns `PRETRAINED_QLORA_FIRST` or `MULTI_GPU_FULL_POST_TRAIN`.
  - `scratch-slm-trainer`: Next step when `recommend` returns `FROM_SCRATCH_COMPACT_SLM`.

## Quick Start

1. Check host hardware and fitting open-weight models:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/local-model-advisor/scripts/recommend_strategy.py \
     hardware-check --limit 10 --output artifacts/hardware_check.json
   ```
2. Recommend a model creation strategy for a harvested corpus token count:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/local-model-advisor/scripts/recommend_strategy.py \
     recommend --corpus-tokens 125000 --domain cyber --limit 5 --output artifacts/strategy.json
   ```

## Utility Scripts

All commands reside in [scripts/recommend_strategy.py](scripts/recommend_strategy.py), write JSON via `--output`, and require an explicit positive `--limit` (no silent caps). Both `PYTHONPATH=src .venv/bin/python` and `.venv/bin/python` work out of the box.

- **`hardware-check`**: Runs `LocalHardwareDetector.detect()` and lists approved models from `ModelRegistry.for_profile(...)` with 4-bit and FP8 memory fit flags.
  - Required: `--limit <int>` (max candidate models listed), `--output <path>`.
- **`recommend`**: Calls `CreationStrategyAdvisor.recommend(...)` and compares candidate models up to `--limit`.
  - Required: `--corpus-tokens <int>`, `--limit <int>`, `--output <path>`.
  - Optional: `--domain <swe|cyber|binrev|data_protocol|architecture|visual_ocr|forensics|vuln_intel>`, `--custom-vocab-required`, `--target-params-m <int>`, `--profile-override <LOCAL_APPLE_SILICON_36GB|WORKSTATION_GPU|CLUSTER_DEFAULT>`.

## Common Mistakes

1. **Jumping straight to from-scratch pre-training for general coding/cyber tasks**: Below tens of millions of tokens without custom tokenization needs, `PRETRAINED_QLORA_FIRST` (`Foundation-Sec-8B-Reasoning`, `Qwen3-VL-8B-Thinking`, or `Qwen3.5-35B-A3B`) outperforms tiny scratch models.
2. **Omitting `--limit` or passing negative `--corpus-tokens`**: `--limit` must be `> 0` and `--corpus-tokens` must be `>= 0`.
3. **Writing `--output` to a symlink or `..` path escape**: Symlinked paths and `..` traversal segments are rejected.
