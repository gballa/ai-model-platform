# How to Create, Save, Load, and Run a Custom Specialist Model

This guide walks through the complete lifecycle of building your own custom model in `platform-core` using [`src/platform_core/layer1_intelligence/training.py`](../src/platform_core/layer1_intelligence/training.py), [`src/platform_core/layer1_intelligence/scratch_trainer.py`](../src/platform_core/layer1_intelligence/scratch_trainer.py), [`src/platform_core/layer3_evolution/corpus_harvester.py`](../src/platform_core/layer3_evolution/corpus_harvester.py), and [`src/platform_core/cli.py`](../src/platform_core/cli.py).

---

## Table of Contents

1. [Purpose & The 5-Stage Custom Model Creation Pipeline](#1-purpose--the-5-stage-custom-model-creation-pipeline)
2. [Prerequisites & Required Configuration](#2-prerequisites--required-configuration)
3. [Step-by-Step: Creating and Running a Custom Model via the CLI](#3-step-by-step-creating-and-running-a-custom-model-via-the-cli)
4. [Step-by-Step: Creating and Running a Custom Model via the Python API](#4-step-by-step-creating-and-running-a-custom-model-via-the-python-api)
5. [Starting from the Latest Qwen or Other Base Models (Local Control Plane vs. GPU Training)](#5-starting-from-the-latest-qwen-or-other-base-models-local-control-plane-vs-gpu-training)
6. [Corpus Harvesting, Strategy Advising & Compact Scratch SLMs](#6-corpus-harvesting-strategy-advising--compact-scratch-slms)
7. [Expected Results & Artifact Verification](#7-expected-results--artifact-verification)
8. [Common Errors and Troubleshooting](#8-common-errors-and-troubleshooting)
9. [Related Documentation](#9-related-documentation)

---

## 1. Purpose & The 5-Stage Custom Model Creation Pipeline

Instead of pre-training from scratch (\$5.6M–\$50M+), `CustomModelPipeline.build_custom_model()` specializes permissive open-weight base models (`Apache-2.0` Qwen3.8-27B or `MIT` DeepSeek-V4-Flash) across five deterministic stages:

1. **Stage 1 — Proprietary Trajectory Synthesis & Hygiene Decontamination (`DatasetHygienePipeline`)**:
   - Ingests trajectories from `SWEFuseFactory`, `SecBenchFactory`, `DecompileBenchFactory`, or your custom `.jsonl`/`.json` file.
   - Rejects non-commercial/copyleft licenses (`GPL-3.0`, `Llama-4-Community`), strips benchmark-contaminated repos/CVEs, deduplicates via 3-token shingle BLAKE2b Jaccard similarity (`< 0.85`), and requires `execution_verified=True`.
2. **Stage 2 — Distributed Sharding Specification (`DistributedTrainingSpecBuilder`)**:
   - Automatically selects **PyTorch FSDP2 (`pytorch_fsdp2_dtensor`)** with `torch.compile` for `<100B` dense models and **DeepSpeed ZeRO-3 (`deepspeed_zero3`)** for `100B+` MoE models, enforcing a 15%–30% general replay mix during CPT to prevent catastrophic forgetting.
3. **Stage 3 — Multi-Teacher Online Policy Distillation (`MOPDDistiller`)**:
   - Blends token distributions from permissive open-weight teachers (`DeepSeek-V4-Pro` MIT + `Qwen3.5-397B-A17B` Apache-2.0) and computes forward KL distillation loss while blocking closed-API teacher distillation.
4. **Stage 4 — Critic-Free GRPO + Verifiable Execution Rewards (`GRPOTrainer`)**:
   - Evaluates candidate rollouts with `SWECyberRewardOracle` (`+1.0` full fix + 100% pass-to-pass regression; `-0.5` over-correction breaking existing tests; `-1.0` compile/PoC failure) and `BinRevDecompileRewardOracle` ($0.25 R_{\text{comp}} + 0.55 R_{\text{exec}} + 0.20 \text{IoU}_{\text{struct}}$).
5. **Stage 5 — Direct Preference Optimization (`DPOTrainer`) & Safetensors Packaging**:
   - Aligns decompiler identifier readability and cybersecurity refusal calibration.
   - Packages weights into a strictly validated `.safetensors` binary checkpoint (`SafetensorsValidator`), verifies the 5-run Canary Promotion Gate (`BenchmarkEvaluator`), and atomically writes `<model-id>.safetensors` + `<model-id>.manifest.json`.

---

## 2. Prerequisites & Required Configuration

- **Prerequisites**: Python `>= 3.11` with `.venv` initialized (`PYTHONPATH=src .venv/bin/python`). Zero third-party packages are required.
- **Required Configuration (`CustomModelConfig`)**:
  - `model_id`: Alphanumeric identifier matching `^[A-Za-z0-9._-]+$` (e.g., `"Acme-SecCoder-27B-v1"`).
  - `domain`: One of `{"swe", "cyber", "binrev", "data_protocol", "architecture", "visual_ocr"}`.
  - `license_id`: Commercial OSI license passing `LicenseComplianceAuditor` (`"Apache-2.0"`, `"MIT"`, `"BSD-3-Clause"`).
  - `dataset_file` *(optional)*: Path to a non-symlinked `.jsonl` or `.json` trajectory file.
  - `output_dir` *(optional)*: Directory where `<model-id>.safetensors` and `<model-id>.manifest.json` will be written atomically.

---

## 3. Step-by-Step: Creating and Running a Custom Model via the CLI

### Step 1: Prepare Your Custom Training Trajectories (`.jsonl` or `.json`)
Create a JSONL file (or use [`examples/sample_custom_trajectories.jsonl`](../examples/sample_custom_trajectories.jsonl)):
```json
{"record_id": "acme-sec-001", "domain": "sec_bench", "source_repo": "acme/edge-proxy", "license_id": "Apache-2.0", "cve_id": "CVE-2026-8101", "prompt_context": "[Sec-Bench] Sanitizer: CWE-78 OS Command Injection in ping diagnostics endpoint.\nCPG Query: cpg.call.name('subprocess.call').whereShellTrue", "target_completion": "@@ -3,1 +3,1 @@\n-    return subprocess.call(f'ping -c 1 {host}', shell=True)\n+    return subprocess.call(['ping', '-c', '1', host], shell=False)", "execution_verified": true}
{"record_id": "acme-swe-002", "domain": "swe_fuse", "source_repo": "acme/billing-ledger", "license_id": "MIT", "cve_id": null, "prompt_context": "[SWE-Fuse Issue-Guided] Fix ZeroDivisionError when computing SLA pass rate on empty window.", "target_completion": "@@ -2,1 +2,1 @@\n-    return passed / total\n+    return (passed / total) if total > 0 else 0.0", "execution_verified": true}
```

### Step 2: Run `create-custom-model` to Build & Export the Model Bundle
```bash
PYTHONPATH=src .venv/bin/python -m platform_core.cli create-custom-model \
  --model-id Acme-SecCoder-27B-v1 \
  --base-checkpoint Qwen/Qwen3.8-27B \
  --domain cyber \
  --params-b 27.8 \
  --context-window 262144 \
  --license Apache-2.0 \
  --dataset-file examples/sample_custom_trajectories.jsonl \
  --output-dir ./artifacts/custom_models
```

This writes two verified files into `./artifacts/custom_models/`:
1. `Acme-SecCoder-27B-v1.safetensors` — Binary Safetensors checkpoint verified against pickle injection and contiguous tensor byte spans.
2. `Acme-SecCoder-27B-v1.manifest.json` — Contains the serialized `ModelSpec`, `checkpoint_sha256`, 5-stage training metrics, canary promotion results, and `serving_launch_args` for SGLang (`python3 -m sglang.launch_server --model-path Acme-SecCoder-27B-v1 ...`).

### Step 3: Run Your Custom Model on a Real Workflow (`run-custom-model`)
Use [`examples/sample_cyber_workflow.json`](../examples/sample_cyber_workflow.json) (or your own task JSON file):
```bash
PYTHONPATH=src .venv/bin/python -m platform_core.cli run-custom-model \
  --manifest ./artifacts/custom_models/Acme-SecCoder-27B-v1.manifest.json \
  --payload-file examples/sample_cyber_workflow.json
```

What happens under the hood:
1. `CustomModelPipeline.load_custom_model_manifest()` rejects symlinks/path traversal, verifies `Acme-SecCoder-27B-v1.safetensors` against `checkpoint_sha256` using `SafetensorsValidator`, audits `Apache-2.0` via `LicenseComplianceAuditor`, and registers `Acme-SecCoder-27B-v1` into `ModelRegistry`.
2. `ExecutionLifecycleOrchestrator` ingests the untrusted code (`TAINTED_UNTRUSTED`), pre-indexes symbols with `CodeGraphMCPServer`, routes the task to `Acme-SecCoder-27B-v1` in `POOL_2_SWE_CYBER` with `THINK_HIGH` (`742` max thinking tokens/turn), executes CPG taint scanning and syntax-checked patching inside an isolated Firecracker sandbox with a pre-execution CoW snapshot, and verifies the remediation via `IndependentVerifierAgent`.

---

## 4. Step-by-Step: Creating and Running a Custom Model via the Python API

```python
from pathlib import Path
import tempfile

from platform_core.layer1_intelligence import (
    AdaptiveModelRouter,
    CustomModelConfig,
    CustomModelPipeline,
    ModelRegistry,
)
from platform_core.layer2_execution import ExecutionLifecycleOrchestrator

with tempfile.TemporaryDirectory() as tmp:
    registry = ModelRegistry()

    # 1. Build and save a custom Binary Reverse Engineering model (Pool 3)
    config = CustomModelConfig(
        model_id="Acme-BinRev-27B-v2",
        base_checkpoint="Qwen/Qwen3.8-27B",
        domain="binrev",
        total_params_b=27.8,
        context_window=262_144,
        license_id="Apache-2.0",
        serving_engine="sglang",
        serving_port=30020,
    )
    artifact = CustomModelPipeline.build_custom_model(
        config=config,
        output_dir=Path(tmp),
        registry=registry,
        set_as_pool_default=True,
    )
    print("Saved Safetensors:", artifact.safetensors_path)
    print("SHA-256:", artifact.checkpoint_sha256)
    print("Launch Cmd:", " ".join(artifact.serving_launch_args))

    # 2. Run a 10-step stripped ELF decompilation workflow using the custom model
    orchestrator = ExecutionLifecycleOrchestrator(router=AdaptiveModelRouter(registry=registry))
    try:
        state = orchestrator.run_workflow(
            session_id="binrev-custom-01",
            objective="Decompile stripped ELF packet verifier with Acme-BinRev-27B-v2",
            task_domain="binrev",
            preferred_model_id="Acme-BinRev-27B-v2",
            task_payload={
                "binary_payload": b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00",
                "raw_pseudocode": (
                    "undefined8 FUN_00401000(undefined4 param_1) {\n"
                    "  goto LAB_00401010;\n"
                    "LAB_00401010:\n"
                    "  return param_1;\n"
                    "}"
                ),
                "callers": ["main"],
                "callees": ["crc32_step"],
                "dataflow_aliases": {"FUN_00401000": "verify_header_crc", "param_1": "hdr_len"},
            },
        )
        print("Routed model:", state.routing_summary["primary_model"])
        print("Status:", state.status.value)
        print("Decompiled output:", state.final_deliverable["subtask_outputs"])
    finally:
        orchestrator.close()
```

---

## 5. Starting from the Latest Qwen or Other Base Models (Local Control Plane vs. GPU Training)

You can initialize `CustomModelPipeline` from **any permissive open-weight base checkpoint** — including newer **Qwen** dense or Mixture-of-Experts (MoE) releases (for example, `Qwen/Qwen3-32B`, `Qwen/Qwen3-Coder-30B-A3B-Instruct`, `Qwen/Qwen3.5-397B-A17B`, or future Qwen checkpoints) — rather than only the default `Qwen/Qwen3.8-27B`.

### 5.1 License & Registry Requirements

- **Accepted Checkpoint Identifiers**: `CustomModelConfig.base_checkpoint` and the `--base-checkpoint` CLI flag accept any Hugging Face repository ID or local checkpoint name as a string (`src/platform_core/layer1_intelligence/training.py`).
- **License Gate**: [LicenseComplianceAuditor](../src/platform_core/deploy_security/governance.py) validates `license_id` against `APPROVED_LICENSES` (`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `PostgreSQL`, `CC0-1.0`). Standard open-weight Qwen models licensed under `Apache-2.0` pass as `APPROVED_COMMERCIAL`. Any checkpoint or variant using a custom, research-only, copyleft, or non-commercial license is blocked (`PermissionError`).
- **Dense vs. MoE Parameterization**:
  - For **dense** Qwen checkpoints (`<100B` params), omit `--active-params-b` (defaults to `total_params_b`); `DistributedTrainingSpecBuilder` automatically selects **`pytorch_fsdp2_dtensor`** (`torch_compile=True`) and `fp8` serving quantization.
  - For **MoE** Qwen checkpoints (`total_params_b >= 100.0` or sparse active experts), explicitly pass both `--params-b` and `--active-params-b`; `DistributedTrainingSpecBuilder` selects **`deepspeed_zero3`** for `100B+` models and `ServingEndpointConfig` switches to `mxfp4` quantization and `tensor_parallel_size=2` when `vram_4bit_gb > 192.0`.

### 5.2 Specifying a Newer Qwen Base Model (CLI & Python)

```bash
# Example: Specializing an MoE Qwen base checkpoint for cybersecurity
PYTHONPATH=src .venv/bin/python -m platform_core.cli create-custom-model \
  --model-id Acme-Qwen-MoE-Cyber-v1 \
  --base-checkpoint Qwen/Qwen3-Coder-30B-A3B-Instruct \
  --domain cyber \
  --params-b 30.5 \
  --active-params-b 3.3 \
  --context-window 262144 \
  --license Apache-2.0 \
  --dataset-file examples/sample_custom_trajectories.jsonl \
  --output-dir ./artifacts/custom_models
```

```python
from platform_core.layer1_intelligence import CustomModelConfig, CustomModelPipeline

config = CustomModelConfig(
    model_id="Acme-Qwen-MoE-Cyber-v1",
    base_checkpoint="Qwen/Qwen3-Coder-30B-A3B-Instruct",
    domain="cyber",
    architecture="MoE Qwen Open-Weight Base",
    total_params_b=30.5,
    active_params_b=3.3,
    context_window=262_144,
    license_id="Apache-2.0",
    num_gpus=8,
    serving_engine="sglang",
)
trajectories = CustomModelPipeline.load_trajectories_from_file(
    "examples/sample_custom_trajectories.jsonl"
)
artifact = CustomModelPipeline.build_custom_model(config=config, custom_trajectories=trajectories)
print("Base checkpoint:", artifact.model_spec.base_checkpoint)
print("Serving command:", " ".join(artifact.serving_launch_args))
```

### 5.3 Local Control-Plane Simulation vs. Full GPU Weight Training

> [!IMPORTANT]
> Because `platform-core` has zero third-party runtime dependencies (`dependencies = []` in `pyproject.toml`), `CustomModelPipeline.build_custom_model()` operates as a **CPU control-plane, verification, and packaging engine** rather than downloading multi-gigabyte Hugging Face weights or running CUDA backpropagation itself.

| Responsibility | Handled by `platform-core` Today (Local CPU / Stdlib) | External GPU Cluster Stack (Production Weights) |
| :--- | :--- | :--- |
| **Base Checkpoint & License Audit** | Audits `license_id` (`Apache-2.0`/`MIT`) and records `base_checkpoint` in `ModelSpec` and `.safetensors` `__metadata__`. | Pulls real base weights (e.g., `Qwen/...`) from Hugging Face Hub or internal artifact mirror. |
| **Trajectory Filtering & Hygiene** | Runs `DatasetHygienePipeline` (license gate, benchmark decontamination, MinHash LSH deduplication, `execution_verified=True`). | Consumes the curated JSONL trajectories as training batches. |
| **Training Spec & Math Verification** | Computes `FSDP2`/`ZeRO-3` specs (`DistributedTrainingSpecBuilder`), MOPD forward KL, GRPO advantages, DPO loss, and deterministic reward oracles. | Executes GPU tensor updates using PyTorch FSDP2, DeepSpeed ZeRO-3, `verl`, or `TRL`. |
| **Checkpoint Serialization** | Writes and validates a spec-compliant placeholder `.safetensors` file (32-byte sample tensor + full `__metadata__`) and `.manifest.json`. | Exports trained multi-shard `.safetensors` weights verified by `SafetensorsValidator`. |
| **Serving & Agent Execution** | Emits `sglang.launch_server` / `vllm serve` CLI flags and runs the full 10-step `SecVerifier` agent loop deterministically. | Launches `SGLang v0.5.19+` / `vLLM v0.28+` with the generated flags and connects Layer 2 inference calls to the live endpoint. |

---

## 6. Corpus Harvesting, Strategy Advising & Compact Scratch SLMs

When starting from raw PDFs, technical books, or allowlisted web documentation—or when deciding between RAG, local QLoRA, multi-GPU post-training, or a from-scratch compact SLM—use the three companion workflows:

1. **Advise on Creation Path (`recommend-strategy`)**:
   ```bash
   PYTHONPATH=src .venv/bin/python -m platform_core.cli recommend-strategy \
     --corpus-tokens 150000 \
     --domain cyber
   ```
   `CreationStrategyAdvisor.recommend()` returns `PRETRAINED_RAG_ONLY` (`< 50,000` tokens), `PRETRAINED_QLORA_FIRST` (when a local base model fits `safe_model_budget_gb`), `FROM_SCRATCH_COMPACT_SLM` (when `--custom-vocab` or `--target-params-m` in `10..350` is explicitly requested), or `MULTI_GPU_FULL_POST_TRAIN`.

2. **Harvest & Sanitize Technical Books / Docs (`harvest-corpus`)**:
   ```bash
   PYTHONPATH=src .venv/bin/python -m platform_core.cli harvest-corpus \
     --pdf docs/CUSTOM_MODEL_GUIDE.md \
     --domain swe \
     --distill-output ./artifacts/harvested/trajectories.jsonl
   ```
   `CorpusHarvesterPipeline` sanitizes indirect prompt injections (`PromptInjectionSanitizer`), preserves fenced code blocks (`DomainChunker`), routes `< 200,000` token corpora into `DIRECT_PREFIX_CACHE` (`HybridKnowledgeStore`), and exports license-audited JSONL trajectories (`TeacherDistiller`, keeping `execution_verified=False` unless verified by an oracle or opted into `allow_unexecuted_text_synthesis=True`).

3. **Train a Compact Scratch SLM with Custom BPE (`train-scratch-slm`)**:
   ```bash
   PYTHONPATH=src .venv/bin/python -m platform_core.cli train-scratch-slm \
     --model-id micro-swe-slm \
     --text "def safe_div(a, b): return a / b if b else 0" \
     --output-dir ./artifacts/scratch_slm \
     --steps 10 \
     --sample-prompt "def safe_div"
   ```
   `CompactTransformerSLMTrainer` trains a UTF-8 `BytePairTokenizer` and deterministic causal Transformer (`10M`, `50M`, `125M`, `350M` `--tier` presets or fast micro defaults), pads `metadata["header_pad"]` if needed to avoid `<Q` header collisions with `\x80\x02`–`\x80\x05`, validates via `SafetensorsValidator`, and writes `<model-id>.safetensors`, `<model-id>.tokenizer.json`, and `<model-id>.manifest.json`.

---

## 7. Expected Results & Artifact Verification

- **`create-custom-model`**: Outputs JSON with `"checkpoint_verified": true`, `"canary_promoted": true`, `"sharding_backend": "pytorch_fsdp2_dtensor"`, and paths to `<model-id>.safetensors` and `<model-id>.manifest.json`.
- **`run-custom-model`**: Outputs JSON with `"routed_model_id": "Acme-SecCoder-27B-v1"`, `"status": "COMPLETED"`, `"current_step": 10`, and `"verified_by": "independent_verifier"`.
- **`train-scratch-slm`**: Outputs JSON with `"model_id"`, `"param_count"`, `"backend_used"`, `"final_loss"`, `"checkpoint_sha256"`, and paths to `.safetensors`, `.tokenizer.json`, and `.manifest.json`.

---

## 8. Common Errors and Troubleshooting

| Exception | Cause | Resolution |
| :--- | :--- | :--- |
| `PermissionError: Cannot create custom model '...' with license '...'` | Using a non-commercial or copyleft license (`GPL-3.0`, `Llama-4-Community`). | Use `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `PostgreSQL`, or `CC0-1.0`. |
| `ValueError: Invalid model_id '...'` | Passing slashes, spaces, or `..` in `--model-id`. | Use only `[A-Za-z0-9._-]+`. |
| `SafetensorsValidationError: SHA-256 mismatch` | The `.safetensors` file was modified or corrupted after manifest generation. | Re-run `create-custom-model` to regenerate the synchronized `.safetensors` and `.manifest.json` pair. |
| `RateLimitError` / `PermissionError` in `harvest-corpus` | HTTP 429 exhaustion or `--tainted` / non-allowlisted URL blocked by `CyberGymFirewall`. | Use `--clean` only for trusted read-only allowlisted hosts and reduce `--requests-per-second` or pass `--allowed-domain`. |

---

## 9. Related Documentation

- [5-Stage Model Post-Training Workflow](workflows/model-post-training-pipeline.md)
- [Integrations & External System Boundaries](architecture/integrations.md)
- [API & Schema Contract Reference](api/README.md)
- [ADR-0006: Local AI Creator & Google Antigravity SDK Bridge](architecture/decisions/ADR-0006-local-ai-creator-and-antigravity-sdk.md)
- [Step-by-Step Real-Life How-To Guides](HOW_TO_GUIDES.md)
- [Troubleshooting Playbook](development/troubleshooting.md)
