---
name: scratch-slm-trainer
description: >-
  Use this skill when the user explicitly needs to train a custom byte-level BPE
  tokenizer and compact from-scratch causal Transformer SLM (10M-350M presets
  or micro configs) and export verified Safetensors checkpoints.
---

# From-Scratch BPE Tokenizer & Compact SLM Trainer

## Overview

Trains a deterministic byte-level BPE tokenizer (`BytePairTokenizer`) and a causal Transformer small language model (`CompactTransformerSLMTrainer`) from scratch on local domain corpora. Exports verified `.safetensors` weights (checked by `SafetensorsValidator` with zero pickle artifacts), `.tokenizer.json`, and `<model_id>.manifest.json`. Runs out of the box in pure Python stdlib and dispatches optionally to `mlx` or `torch` when installed.

## Dependencies

- **Runtime**: `.venv/bin/python` works out of the box with `PYTHONPATH=src` and zero extra pip installs for core/stdlib gradient training and `.safetensors` export.
- **Optional extras**:
  - `pip install -e ".[mlx]"` (`mlx`, `mlx-lm`) for Apple Silicon Metal acceleration (`--backend mlx`).
  - `pip install -e ".[train]"` (`torch`) for PyTorch acceleration (`--backend torch`).
- **Upstream / Downstream skills**:
  - `local-model-advisor`: Confirm `FROM_SCRATCH_COMPACT_SLM` is justified before training from scratch.
  - `corpus-harvester`: Supplies sanitized domain text corpora.

## Quick Start

1. Train a standalone byte-level BPE tokenizer:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/scratch-slm-trainer/scripts/train_scratch_slm.py \
     train-tokenizer --corpus-files README.md --vocab-size 512 --limit 200 \
     --tokenizer-out artifacts/custom_slm/custom.tokenizer.json \
     --output artifacts/tokenizer_report.json
   ```
2. Train a compact causal Transformer SLM from scratch and export verified `.safetensors`:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/scratch-slm-trainer/scripts/train_scratch_slm.py \
     train-slm --model-id micro-sec-slm --corpus-files README.md \
     --output-dir artifacts/micro_sec_slm --steps 15 --limit 200 \
     --output artifacts/slm_train_report.json
   ```
3. Generate tokens from the exported `.manifest.json`:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/scratch-slm-trainer/scripts/train_scratch_slm.py \
     generate --manifest artifacts/micro_sec_slm/micro-sec-slm.manifest.json \
     --prompt "def verify_" --limit 16 --output artifacts/slm_sample.json
   ```

## Utility Scripts

All commands reside in [scripts/train_scratch_slm.py](scripts/train_scratch_slm.py), write JSON via `--output`, and require explicit `--limit` (and `--steps` for `train-slm`) with no silent caps. Both `PYTHONPATH=src .venv/bin/python` and `.venv/bin/python` are supported.

- **`train-tokenizer`**: Trains `BytePairTokenizer` on non-symlink corpus files and saves JSON vocab/merges.
  - Required: `--corpus-files <path...>`, `--limit <int>`, `--tokenizer-out <path>`, `--output <path>`.
  - Optional: `--vocab-size <int>` (default `512`, must be `>= 260`), `--min-frequency <int>` (default `2`).
- **`train-slm`**: Configures `ScratchSLMConfig` (custom dims or `--tier` in `{10M, 50M, 125M, 350M}`), validates license via `LicenseComplianceAuditor`, trains `CompactTransformerSLMTrainer`, validates `.safetensors` via `SafetensorsValidator`, and writes artifacts.
  - Required: `--model-id <id>`, `--corpus-files <path...>`, `--output-dir <dir>`, `--steps <int>`, `--limit <int>`, `--output <path>`.
  - Optional: `--tier`, `--vocab-size`, `--d-model`, `--n-layers`, `--n-heads`, `--d-ff`, `--max-seq-len`, `--learning-rate`, `--batch-size`, `--seed`, `--domain`, `--license`, `--backend <auto|stdlib|mlx|torch>`.
- **`generate`**: Verifies `<model_id>.manifest.json` and `.safetensors` checksum, then runs `CompactTransformerSLMTrainer.generate_sample`.
  - Required: `--manifest <path>`, `--prompt <str>`, `--limit <int>` (`max_new_tokens`), `--output <path>`.

## Common Mistakes

1. **Setting `vocab_size < 260`**: Byte-level BPE reserves 256 byte tokens plus 4 special tokens (`<pad>`, `<bos>`, `<eos>`, `<unk>`), so `vocab_size` must be `>= 260`.
2. **Choosing `d_model` not divisible by `n_heads`**: `ScratchSLMConfig.validate()` enforces `d_model % n_heads == 0`.
3. **Training a `10M–350M` preset on pure-CPU stdlib with large `--steps`**: Pure-stdlib training is designed for micro configs (`d_model=64`, `n_layers=2`) and deterministic verification; use `--backend mlx` or `--backend torch` for multi-million-parameter runs.
