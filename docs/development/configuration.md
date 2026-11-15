# Configuration & Environment Reference

---

## 1. Purpose

Provide a complete, source-verified reference for all configuration dataclasses, CLI arguments, runtime constants, SQLite pragmas, and sandbox environment variable rules in `platform-core`.

---

## 2. Prerequisites

- Python `>= 3.11` and an initialized `.venv` (`PYTHONPATH=src .venv/bin/python`).

---

## 3. Required Configuration

`platform-core` uses typed Python dataclasses (`frozen=True`) and explicit constructor parameters rather than hidden global environment variables.

### 3.1 `CustomModelConfig` ([`layer1_intelligence/training.py`](../../src/platform_core/layer1_intelligence/training.py))

| Field | Type | Default | Constraints & Validation |
| :--- | :--- | :--- | :--- |
| `model_id` | `str` | *(Required)* | Must match `^[A-Za-z0-9._-]+$`; cannot be `.` or `..`. |
| `base_checkpoint` | `str` | `"Qwen/Qwen3.8-27B"` | Base open-weight checkpoint identifier. |
| `domain` | `str` | `"swe"` | One of `{"swe", "cyber", "binrev", "data_protocol", "architecture", "visual_ocr", "forensics", "vuln_intel"}`. |
| `pool` | `ModelPool \| None` | `None` | Auto-resolved from `domain` if `None`. |
| `architecture` | `str` | `"Dense Native VLM with 3:1 Gated DeltaNet Linear Attention"` | Architecture descriptor stored in `ModelSpec`. |
| `total_params_b` | `float` | `27.8` | Positive finite float (`not bool`). Triggers `deepspeed_zero3` and `mxfp4` at `>= 100.0`. |
| `active_params_b` | `float \| None` | `None` | Defaults to `total_params_b` if `None`. |
| `context_window` | `int` | `262_144` | Positive integer (`not bool`). |
| `license_id` | `str` | `"Apache-2.0"` | Must pass `LicenseComplianceAuditor` (`APPROVED_COMMERCIAL`). |
| `vram_4bit_gb` | `float \| None` | `None` | Defaults to `round(max(4.0, total_params_b * 0.58), 1)`. |
| `vram_fp8_gb` | `float \| None` | `None` | Defaults to `round(max(6.0, total_params_b * 1.01), 1)`. |
| `supports_early_fusion_vision` | `bool` | `True` | Boolean flag. |
| `attention_mechanism` | `str` | `"Gated DeltaNet 3:1 Dense"` | Attention mechanism descriptor. |
| `general_replay_ratio` | `float` | `0.20` | Must be in `[0.15, 0.30]` during CPT stage. |
| `dpo_beta` | `float` | `0.1` | Positive float (`> 0`). |
| `num_gpus` | `int` | `8` | Positive integer (`not bool`). |
| `serving_engine` | `str` | `"sglang"` | One of `"sglang"`, `"vllm"`, `"mlx_lm"`, `"llama_cpp"`. |
| `serving_port` | `int` | `30010` | Positive integer (`not bool`). |
| `execution_mode` | `str` | `"spec_only"` | `TrainingExecutionMode`: `"spec_only"`, `"mlx_qlora"`, or `"torch_trl"`. |
| `lora_rank` | `int` | `16` | Positive LoRA rank used by `MLXQLoRATrainer` and `TorchTRLSpecAndRunner`. |
| `training_iters` | `int` | `200` | Positive iteration count for LoRA/QLoRA fine-tuning. |

### 3.2 `ServingEndpointConfig` & `HardwareProfile` ([`layer1_intelligence/serving.py`](../../src/platform_core/layer1_intelligence/serving.py), [`models.py`](../../src/platform_core/layer1_intelligence/models.py))

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `engine` | `str` | *(Required)* | `"sglang"`, `"vllm"`, `"mlx_lm"`, or `"llama_cpp"`. |
| `engine_version` | `str` | *(Required)* | E.g., `"0.5.19"` (SGLang), `"0.28.0"` (vLLM), or `"mlx_lm"`. |
| `model_id` | `str` | *(Required)* | Model identifier or checkpoint path. |
| `quantization` | `str` | *(Required)* | `"fp8"`, `"mxfp4"`, `"awq_int4"`, or `"bf16"`. |
| `tensor_parallel_size` | `int` | *(Required)* | Number of tensor-parallel GPUs (`1` or `2`). |
| `max_context_len` | `int` | *(Required)* | Maximum context window tokens. |
| `enable_radix_prefix_cache` | `bool` | `True` | Enables RadixAttention / prefix caching. |
| `enable_chunked_prefill` | `bool` | `True` | Adds `--chunked-prefill-size=8192` (SGLang) or `--enable-chunked-prefill` (vLLM). |
| `gpu_memory_utilization` | `float` | `0.90` | Static memory fraction (`0.90`). |
| `port` | `int` | `30000` | HTTP serving port. |
| `HardwareProfile` | `Enum` | Auto-detected | `APPLE_SILICON_36GB`, `SINGLE_GPU_24GB`, `WORKSTATION_MULTI_GPU`, `CLUSTER_H200_8X`. |

### 3.3 `RoutingRequest` & Thinking Token Budgets ([`layer1_intelligence/router.py`](../../src/platform_core/layer1_intelligence/router.py))

| Constant / Field | Value / Default | Description |
| :--- | :--- | :--- |
| `NON_THINK_BUDGET` | `0` | Used for routine tool lookups, `POOL_4_VISUAL_OCR`, or `uncertainty_entropy < 0.25`. |
| `THINK_HIGH_MIN_BUDGET` | `512` | Minimum per-turn thinking token cap in `THINK_HIGH`. |
| `THINK_HIGH_MAX_BUDGET` | `1024` | Maximum per-turn thinking token cap in `THINK_HIGH`. |
| `THINK_MAX_BUDGET` | `2048` | Used when `task_domain == "architecture"` and `uncertainty_entropy >= 0.75`. |

### 3.4 Sandbox & Security Constants

| Component | Constant / Parameter | Value | Purpose |
| :--- | :--- | :--- | :--- |
| `FirecrackerSandboxManager` | `SECCOMP_24_SYSCALL_ALLOWLIST` | 24 syscalls (`read`, `write`, `openat`, ..., `clock_gettime`) | Jailer seccomp syscall filter. |
| `FirecrackerSandboxManager` | `SENSITIVE_ENV_PREFIXES` | `AWS_`, `GCP_`, `GOOGLE_`, `OPENAI_`, `ANTHROPIC_`, `GITHUB_`, `GITLAB_`, `HF_TOKEN`, `SSH_`, `DATABASE_URL`, `PGPASSWORD` | Stripped from child `python3 -I` sandbox processes (along with `HOME`, `TMPDIR`, `USER`, `LOGNAME`, `PYTHONPATH`). |
| `DataAndVisualMCPServer` | `MAX_DECOMPRESSION_BYTES` | `10 * 1024 * 1024` (10 MiB) | Streaming decompression-bomb ceiling (`zlib.decompressobj`). |
| `HybridKnowledgeStore` | `DIRECT_PREFIX_CACHE_TOKEN_LIMIT` | `200_000` | Threshold below which `retrieve()` returns `DIRECT_PREFIX_CACHE`. |
| `SafetensorsValidator` | `MAX_HEADER_BYTES` | `100 * 1024 * 1024` (100 MiB) | Maximum allowed JSON header size in `.safetensors` files. |
| `SQLiteStateCheckpointer` & `CodeGraphMCPServer` | SQLite Pragmas | `busy_timeout = 30000`, `journal_mode = WAL` (file DBs), `check_same_thread = False` | Multi-threaded concurrency safety. |

---

## 4. Step-by-Step Instructions

1. Construct a `CustomModelConfig` or `ServingEndpointConfig` in Python, or pass equivalent flags to `platform_core.cli`.
2. Let the built-in validators verify numeric bounds, SPDX licenses, and regex constraints.

---

## 5. Verified Commands and Examples

```python
from platform_core.layer1_intelligence import CustomModelConfig, ServingEndpointConfig

cfg = CustomModelConfig(
    model_id="Acme-SWE-27B",
    domain="swe",
    total_params_b=27.8,
    context_window=262_144,
    license_id="Apache-2.0",
    serving_engine="vllm",
    serving_port=30025,
)

endpoint = ServingEndpointConfig(
    engine=cfg.serving_engine,
    engine_version="0.28.0",
    model_id=cfg.model_id,
    quantization="fp8",
    tensor_parallel_size=1,
    max_context_len=cfg.context_window,
    port=cfg.serving_port,
)
print("vLLM Launch Args:", " ".join(endpoint.to_launch_args()))
```

---

## 6. Expected Results

Prints:
```text
vLLM Launch Args: vllm serve Acme-SWE-27B --tensor-parallel-size 1 --max-model-len 262144 --quantization fp8 --gpu-memory-utilization 0.90 --port 30025 --enable-prefix-caching --enable-chunked-prefill
```

---

## 7. Common Errors and Troubleshooting

| Exception | Cause | Resolution |
| :--- | :--- | :--- |
| `ValueError: Invalid context_window: True (must be a positive int, not bool).` | Passing a boolean (`True`/`False`) where an `int` or `float` is expected. | Pass an explicit integer (`262144`) or float (`27.8`). |
| `ValueError:MCP manifest signing key must be at least 16 bytes.` | Initializing `SignedManifestVerifier` or `ExecutionLifecycleOrchestrator` with a short `signing_key`. | Provide a `signing_key` of at least 16 UTF-8 bytes. |

---

## 8. Related Documentation

- [CLI Module Reference](../modules/cli.md)
- [API & Schema Contracts](../api/README.md)
- [Security Architecture](../security/README.md)
