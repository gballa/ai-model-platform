# Module Reference: Layer 1 — Intelligence & Model Creation (`platform_core.layer1_intelligence`)

**Source Directory:** [`src/platform_core/layer1_intelligence/`](../../src/platform_core/layer1_intelligence/)  
**Local Module README:** [`src/platform_core/layer1_intelligence/README.md`](../../src/platform_core/layer1_intelligence/README.md)

---

## Table of Contents

1. [Module Responsibilities & Boundaries](#1-module-responsibilities--boundaries)
2. [`models.py` — 4-Pool Registry, Thinking Modes & Hardware Planner](#2-modelspy--4-pool-registry-thinking-modes--hardware-planner)
3. [`router.py` — Adaptive Model Router & Best-of-N Verifier Pruner](#3-routerpy--adaptive-model-router--best-of-n-verifier-pruner)
4. [`serving.py` — SGLang/vLLM Launch Configs & Radix Prefix Cache Simulator](#4-servingpy--sglangvllm-launch-configs--radix-prefix-cache-simulator)
5. [`training.py` — 5-Stage Post-Training, Reward Oracles & Custom Model Pipeline](#5-trainingpy--5-stage-post-training-reward-oracles--custom-model-pipeline)
6. [`scratch_trainer.py` — Strategy Advisor, Byte-Level BPE & Compact Scratch SLM](#6-scratch_trainerpy--strategy-advisor-byte-level-bpe--compact-scratch-slm)
7. [`heretic.py` — Heretic Abliteration, GAIN Scheduling, Cold-Fusion Merge & IMatrix Calibration](#7-hereticpy--heretic-abliteration-gain-scheduling-cold-fusion-merge--imatrix-calibration)
8. [Testing & Verification](#8-testing--verification)
9. [Related Documentation](#9-related-documentation)

---

## 1. Module Responsibilities & Boundaries

`platform_core.layer1_intelligence` manages the platform's model catalog, financial/hardware capacity planning, entropy-bounded inference routing, SGLang/vLLM serving configurations, and the 5-stage post-training pipeline (`CPT -> SFT -> MOPD -> GRPO/RLVR -> DPO`).

---

## 2. `models.py` — 4-Pool Registry, Thinking Modes & Hardware Planner

- **`ModelPool(str, Enum)`**: `POOL_1_ORCHESTRATOR`, `POOL_2_SWE_CYBER`, `POOL_3_BINREV`, `POOL_4_VISUAL_OCR`.
- **`ThinkingMode(str, Enum)`**: `NON_THINK`, `THINK_HIGH`, `THINK_MAX`.
- **`ModelSpec`**: Immutable specification of a model checkpoint. Includes `to_dict()` and `from_dict(data)` with strict boolean-safe numeric validation (`_validate_positive_int`, `_validate_positive_float`).
- **`ModelRegistry`**:
  - Registers 5 default models on initialization.
  - The default SWE/Cyber pool now uses the Apache-2.0 GGUF repository `DavidAU/Qwen3.8-27B-TURBO-Fable-Cold-Fusion-735-882-Heretic-Uncensored-NEO-CODER-MAX-MTP-GGUF`; the `heretic-llm` and `annihilation-llm` profile aliases resolve to that registry entry. GGUF serving uses llama.cpp with the `Q4_K_M` quant.
  - `register_model(spec: ModelSpec, set_as_pool_default: bool = False) -> LicenseAuditResult`: Audits `spec.license_id` via `LicenseComplianceAuditor` and raises `PermissionError` unless `verdict == LicenseVerdict.APPROVED_COMMERCIAL`.
  - `get_pool_override(pool: ModelPool) -> ModelSpec | None`: Returns the custom default model registered for `pool`.
- **`HardwareFeasibilityPlanner`**:
  - `SCENARIOS`: Defines `Scenario-A`, `Scenario-B`, and `Scenario-C` (`ScenarioBudgetProfile`).
  - `calculate_gpu_break_even_months(hardware_capex_usd, monthly_power_hosting_usd, cloud_hourly_rate_usd, utilization_ratio=0.85) -> float`: Computes months to break even when owning GPUs vs cloud rental (`22.3` months for default Scenario-B parameters).
  - `recommend_scenario(annual_budget_usd, require_full_weight_rlvr=True) -> dict[str, Any]`: Recommends `Scenario-B` when `annual_budget_usd >= 1_000_000` or `require_full_weight_rlvr=True`, and confirms `pretrain_from_scratch_justified: False`.

---

## 3. `router.py` — Adaptive Model Router & Best-of-N Verifier Pruner

- **`RoutingRequest`**: Input request containing `task_id`, `task_domain`, `prompt_tokens`, `has_visual_input`, `is_routine_tool_lookup`, `uncertainty_entropy` (`[0.0, 1.0]`), `retry_attempt`, `require_best_of_n`, and `preferred_model_id`.
- **`AdaptiveModelRouter`**:
  - **Pool Selection**: Uses `preferred_model_id` if provided; otherwise routes `prompt_tokens > 200_000` or `domain == "architecture"` to `POOL_1_ORCHESTRATOR` (`Qwen3.5-397B-A17B` if `has_visual_input` else `DeepSeek-V4-Flash`), `binrev` to `POOL_3_BINREV`, `visual_ocr` to `POOL_4_VISUAL_OCR`, and `swe`/`cyber`/`data_protocol` to `POOL_2_SWE_CYBER` (honoring `registry.get_pool_override()`).
  - **Thinking Mode Caps**:
    - `NON_THINK` (`0` tokens): Routine tool lookups, `POOL_4_VISUAL_OCR`, or `uncertainty_entropy < 0.25` with `retry_attempt == 0`.
    - `THINK_MAX` (`2048` tokens): `domain == "architecture"` and `uncertainty_entropy >= 0.75`.
    - `THINK_HIGH` (`512..1024` tokens scaled linearly by `uncertainty_entropy`): All other cases with `uncertainty_entropy >= 0.25` or `retry_attempt > 0`.
  - **`TTS@N` Rollouts**: `8` if `require_best_of_n and uncertainty_entropy >= 0.7`, `4` if `require_best_of_n` or `retry_attempt >= 2`, else `1`.
- **`BestOfNVerifierPruner.select_best_candidate(candidates, custom_verifier=None)`**:
  - Ranks `CandidateRollout` items by `(dual_gate_pass, compiled_and_primary, round(score, 6), -tool_steps_taken, -thinking_tokens_used)`.

---

## 4. `serving.py` — SGLang/vLLM Launch Configs & Radix Prefix Cache Simulator

- **`ServingEndpointConfig.to_launch_args() -> list[str]`**: Generates CLI flags for `sglang` (`python3 -m sglang.launch_server ...`) or `vllm` (`vllm serve ...`).
  - `RadixPrefixCacheSimulator.build_default_pool_configs()` selects llama.cpp and `Q4_K_M` for the registered GGUF model; other model specs keep SGLang configurations.
- **`RadixPrefixCacheSimulator`**:
  - Simulates 16-token block prefix caching (`record_request(token_blocks, active_params_b)`), computing `prefix_hit_ratio`, `cumulative_hit_ratio`, and `estimated_ttft_ms`.
  - `build_default_pool_configs(models)` generates SGLang v0.5.19 configs on ports `30000..30004`.

---

## 5. `training.py` — 5-Stage Post-Training, Reward Oracles & Custom Model Pipeline

- **`SWECyberRewardOracle.compute_reward(outcome)`**: Returns `+1.0`, `-0.5`, or `-1.0`.
- **`BinRevDecompileRewardOracle`**:
  - `compute_struct_layout_iou(predicted, ground_truth)`: Greedy bipartite byte-interval `[offset_bytes, offset_bytes + size_bytes)` IoU.
  - `compute_reward(outcome)`: Computes $0.25 R_{\text{comp}} + 0.55 R_{\text{exec}} + 0.20 \text{IoU}_{\text{struct}}$ (or `-1.0` if `compiles_cleanly=False`).
- **`GRPOTrainer.compute_group_step(group)`**: Computes group-normalized advantages, SWE-Fuse sequence entropy weights, unbiased KL penalty, and surrogate loss.
- **`MOPDDistiller.blend_teacher_probs(teacher_token_probs, student_token_probs)`**: Audits teacher licenses (`APPROVED_COMMERCIAL` + `allows_commercial_distillation`) and computes blended teacher distribution and forward KL loss.
- **`DistributedTrainingSpecBuilder.build_spec(...)`**: Selects `pytorch_fsdp2_dtensor` vs `deepspeed_zero3`, blocks `torchtune`, and enforces `0.15 <= general_replay_ratio <= 0.30` for `CPT`.
- **`DPOTrainer.compute_dpo_step(pairs)`**: Computes numerically stable sigmoid preference loss, reward margin, and accuracy.
- **`CustomModelPipeline`**:
  - `load_trajectories_from_file(dataset_file)`: Loads JSON array or streaming JSONL trajectories (rejecting symlinks and non-boolean `execution_verified`).
  - `build_custom_model(config, custom_trajectories, output_dir, registry, set_as_pool_default)`: Runs all stages and atomically exports `<model-id>.safetensors` and `<model-id>.manifest.json`.
  - `load_custom_model_manifest(manifest_path, registry, set_as_pool_default)`: Verifies `.safetensors` SHA-256 and binary layout, audits the license, and registers the custom `ModelSpec`.

---

## 6. `scratch_trainer.py` — Strategy Advisor, Byte-Level BPE & Compact Scratch SLM

- **`ModelCreationPath(str, Enum)`**: `PRETRAINED_QLORA_FIRST`, `PRETRAINED_RAG_ONLY`, `FROM_SCRATCH_COMPACT_SLM`, `MULTI_GPU_FULL_POST_TRAIN`.
- **`CreationStrategyAdvisor.recommend(corpus_tokens, domain="swe", hardware_info=None, custom_vocab_required=False, target_params_m=None) -> StrategyRecommendation`**:
  - Recommends `FROM_SCRATCH_COMPACT_SLM` only when `custom_vocab_required=True` or `10 <= target_params_m <= 350`.
  - Recommends `PRETRAINED_RAG_ONLY` for small corpora (`< 50,000` tokens), `PRETRAINED_QLORA_FIRST` when a local model fits `safe_model_budget_gb`, or `MULTI_GPU_FULL_POST_TRAIN` when local VRAM is insufficient.
- **`BytePairTokenizer`**:
  - UTF-8 byte-level BPE (`SPECIAL_TOKENS = ("<pad>", "<bos>", "<eos>", "<unk>")`) with `train(texts, vocab_size=512, min_frequency=2)`, `encode()`, `decode()`, `save()`, and `load()`.
  - Rejects `bool` passed as `int`, symlinks, and `..` path traversal (`_assert_no_symlink_or_traversal`).
- **`ScratchSLMConfig`**:
  - Micro defaults (`vocab_size=512`, `d_model=64`, `n_layers=2`, `n_heads=4`, `d_ff=128`, `max_seq_len=128`, `execution_backend="auto"`).
  - `ScratchSLMConfig.preset_tier(model_id, tier="10M", domain="swe")` provides `10M`, `50M`, `125M`, and `350M` parameter presets.
  - Enforces `not isinstance(val, bool)`, `LicenseComplianceAuditor` approval, and safe `model_id` slugs (`^[A-Za-z0-9._-]+$`).
- **`CompactTransformerSLMTrainer`**:
  - `train_and_export(config, corpus_texts, output_dir) -> ScratchSLMArtifact`: Trains BPE + causal Transformer (`stdlib`, `mlx`, or `torch`), pads `metadata["header_pad"]` if `raw_st[:2]` would collide with `\x80\x02`–`\x80\x05`, validates via `SafetensorsValidator.validate_file()`, and atomically writes `<model_id>.safetensors`, `<model_id>.tokenizer.json`, and `<model_id>.manifest.json`.
  - `load_artifact_manifest(manifest_path)`: Validates manifest asset bounds (`is_relative_to`), Safetensors SHA-256, and verifies `max(tokenizer.vocab.values()) < config.vocab_size`.
  - `generate_sample(manifest_path, prompt, max_new_tokens=16) -> str`: Generates deterministic next-token continuations from a validated checkpoint.

---

## 7. `heretic.py` — Heretic Abliteration, GAIN Scheduling, Cold-Fusion Merge & IMatrix Calibration

- **`HereticConfig` & `HereticAbliterator`**:
  - `extract_refusal_subspace(harmful_prompts, harmless_prompts, ...)`: Builds contrastive activation difference subspaces using Modified Gram-Schmidt orthonormalization across target layer bands.
  - `orthogonalize_matrix(weight_matrix, basis, alpha)`: Applies rank-$k$ projection orthogonalization ($W' = W - \alpha \sum_{i=1}^k (\hat{r}_i \hat{r}_i^T) W$).
  - `abliterate_safetensors(input_path, output_path, config=None) -> HereticAbliterationReport`: Optimizes `(alpha, layer_band)` parameters under `max_kl_divergence`, applies `<Q` `header_pad` protection against pickle magic bytes, and validates outputs with `SafetensorsValidator`.
- **`GAINAdaptiveScheduler`**:
  - `compute_sample_weights(sample_texts, ...) -> list[GAINSampleWeight]`: Computes per-sample token Shannon entropy and structural complexity to scale learning rate and GRPO advantage multipliers within `[0.5, 1.5]`.
- **`ColdFusionModelMerger`**:
  - `merge_safetensors(checkpoint_paths, output_path, config=None) -> ColdFusionMergeReport`: Merges two or more F32 `.safetensors` checkpoints using `dare_ties` (Drop And REscale + TIES sign election) or `slerp` interpolation and exports a reproducible `mergekit` YAML config.
- **`ImatrixQuantizationCalibrator`**:
  - `calibrate_and_build_gguf_plan(safetensors_path, calibration_texts, output_dir, quant_type="Q5_K_M") -> ImatrixCalibrationReport`: Computes activation-aware importance scores and emits `llama-imatrix`, `llama-quantize`, and `mlx_lm.convert` quantization artifacts (`Q4_K_M`, `Q4_K_S`, `Q5_K_M`, `Q8_0`, `IQ4_XS`).

---

## 8. Testing & Verification

Covered by `TestLayer1IntelligenceAndTraining`, `TestCustomModelPipelineAndCLI`, and `TestInferenceAndTraining` in [`tests/test_platform_core.py`](../../tests/test_platform_core.py) and [`tests/test_inference_and_training.py`](../../tests/test_inference_and_training.py), by `TestScratchTrainerAndStrategyAdvisor` in [`tests/test_corpus_and_scratch_trainer.py`](../../tests/test_corpus_and_scratch_trainer.py), and by `TestHereticAndBrain` in [`tests/test_heretic_and_brain.py`](../../tests/test_heretic_and_brain.py).

---

## 9. Related Documentation

- [5-Stage Model Post-Training Pipeline](../workflows/model-post-training-pipeline.md)
- [Custom Model Creation & Execution Guide](../CUSTOM_MODEL_GUIDE.md)
- [ADR-0006: Local AI Creator & Google Antigravity SDK Bridge](../architecture/decisions/ADR-0006-local-ai-creator-and-antigravity-sdk.md)
- [Layer 1 Local README](../../src/platform_core/layer1_intelligence/README.md)
