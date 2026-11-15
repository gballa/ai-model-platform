# Module Reference: Unified CLI (`platform_core.cli`)

**Source File:** [`src/platform_core/cli.py`](../../src/platform_core/cli.py)  
**Console Script Entrypoint:** `platform-cli = "platform_core.cli:main"` ([`pyproject.toml`](../../pyproject.toml))

---

## Table of Contents

1. [Module Responsibilities & Boundaries](#1-module-responsibilities--boundaries)
2. [Public Functions](#2-public-functions)
3. [Subcommands & CLI Arguments](#3-subcommands--cli-arguments)
4. [Custom Workflow Payload Loader (`_load_custom_workflow_payload`)](#4-custom-workflow-payload-loader-_load_custom_workflow_payload)
5. [Verified Usage Examples](#5-verified-usage-examples)
6. [Related Documentation](#6-related-documentation)

---

## 1. Module Responsibilities & Boundaries

`platform_core.cli` provides the command-line interface (`platform-cli` or `python -m platform_core.cli`) across 18 subcommands covering blueprint evaluation, custom model post-training, corpus harvesting, strategy advising, compact scratch SLM training, 10-step agent workflows across all 8 domains, hardware profiling, vulnerability intelligence, spyware forensics, multimodal analysis, benchmarking, and Google Antigravity SDK / MCP stdio bridging. All standard subcommands output deterministic, sorted-key JSON (`json.dumps(result, indent=2, sort_keys=True)`) to `stdout` and return exit code `0` on success (`mcp-stdio-bridge` streams newline-delimited JSON-RPC 2.0 responses).

`pyproject.toml` preserves `dependencies = []` (zero mandatory third-party packages) while exposing optional extras including `[agy]` (`google-antigravity>=0.1.0`), `[mlx]`, `[train]`, `[rag]`, `[vision]`, `[forensics]`, and `[all]`.

---

## 2. Public Functions

| Function | Signature | Return Value | Description |
| :--- | :--- | :--- | :--- |
| `run_evaluate_blueprint` | `run_evaluate_blueprint(budget_usd: int = 1_800_000) -> dict[str, Any]` | Dictionary containing `architecture`, `registered_models`, `serving_endpoints`, `recommended_scenario`, `pretrain_from_scratch_justified`, `gpu_ownership_break_even_months`, and `propbench_9_suites`. | Evaluates the default models in `ModelRegistry`, builds SGLang serving configs, runs `HardwareFeasibilityPlanner`, and lists all 9 `PropBench9Suite` IDs. |
| `run_model_creation_pipeline` | `run_model_creation_pipeline(model_id="Qwen3.8-27B-SWE-Cyber-v1.0", base_checkpoint="Qwen/Qwen3.8-27B", domain="swe", pool=None, total_params_b=27.8, active_params_b=None, context_window=262_144, license_id="Apache-2.0", output_dir=None, dataset_file=None, execution_mode="spec_only", lora_rank=16, training_iters=200) -> dict[str, Any]` | Dictionary summarizing training metrics, `checkpoint_sha256`, `canary_promoted`, `serving_launch_args`, and optional `safetensors_path` / `manifest_path`. | Executes `CustomModelPipeline.build_custom_model()` with optional custom JSON/JSONL trajectories, `spec_only`/`mlx_qlora`/`torch_trl` mode, and disk export. |
| `run_demo_workflow` | `run_demo_workflow(domain=None, model_id=None, manifest_path=None, payload_file=None) -> dict[str, Any]` | Dictionary with `session_id`, `status`, `current_step`, `taint_level`, `routed_model_id`, `selected_pool`, `thinking_mode`, `max_thinking_tokens_per_turn`, `verified_by`, `consolidated_memory_event_id`, `telemetry_span_count`, and `deliverable_outputs`. | Loads an optional custom model manifest and/or custom workflow JSON payload, executes `ExecutionLifecycleOrchestrator.run_workflow()`, and closes SQLite resources cleanly in a `finally` block. |
| `run_harvest_corpus` | `run_harvest_corpus(pdf_paths=None, book_dirs=None, urls=None, domain="swe", license_id="Apache-2.0", limit=50, allowed_domains=None, requests_per_second=1.0, distill_output=None, teacher_model_id="Qwen/Qwen3.5-35B-A3B", teacher_license_id="Apache-2.0", max_samples_per_doc=3, session_tainted=False, ingest_into_rag=True, rag_db_path=":memory:") -> dict[str, Any]` | Dictionary with `documents_harvested`, `total_chunks`, `total_tokens_est`, `rejected_sources`, `rag_ingestion_stats`, `documents`, and optional `distillation`. | Harvests PDF/Markdown/reST/text books and firewall-approved URLs via `CorpusHarvesterPipeline`, indexes chunks into `HybridKnowledgeStore`, and optionally synthesizes distilled JSONL trajectories. |
| `run_recommend_strategy` | `run_recommend_strategy(corpus_tokens: int, domain: str = "swe", custom_vocab_required: bool = False, target_params_m: float | None = None) -> dict[str, Any]` | Dictionary with `recommended_path`, `base_model_id`, `rationale`, `hardware_summary`, `estimated_vram_gb`, `fits_local_budget`, and `warnings`. | Delegates to `CreationStrategyAdvisor.recommend()` to choose among `PRETRAINED_RAG_ONLY`, `PRETRAINED_QLORA_FIRST`, `FROM_SCRATCH_COMPACT_SLM`, and `MULTI_GPU_FULL_POST_TRAIN`. |
| `run_train_scratch_slm` | `run_train_scratch_slm(model_id="custom-scratch-slm", corpus_files=None, corpus_dirs=None, inline_texts=None, output_dir="models/scratch_slm", tier=None, steps=None, d_model=None, n_layers=None, n_heads=None, d_ff=None, vocab_size=None, max_seq_len=None, batch_size=None, learning_rate=None, seed=None, execution_backend="auto", license_id="Apache-2.0", domain="swe", sample_prompt=None, max_new_tokens=16) -> dict[str, Any]` | Dictionary with `model_id`, `param_count`, `vocab_size`, `backend_used`, `initial_loss`, `final_loss`, `loss_history`, `safetensors_path`, `tokenizer_path`, `manifest_path`, `checkpoint_sha256`, and optional `sample_generation`. | Collects and sanitizes corpus texts, trains a `BytePairTokenizer` and `CompactTransformerSLMTrainer`, exports verified `.safetensors` + `.tokenizer.json` + `.manifest.json`, and optionally samples a prompt. |
| `run_agy_local_command` | `run_agy_local_command(agent_name="local-sec-swe-agent", prompt="", runtime_kind="local_openai", model_or_path="Qwen/Qwen3.5-35B-A3B", base_url="http://127.0.0.1:8080/v1", litert_backend="gpu", skills_dirs=None, mcp_servers=None, max_subagent_depth=2, session_tainted=True, force_fallback=False) -> dict[str, Any]` | Serialized `AgyExecutionResult.to_dict()`. | Executes a local Google Antigravity SDK agent (or deterministic stdlib fallback) with `IndependentVerifierAgent` gating and fail-closed `session_tainted=True` defaults. |
| `run_mcp_stdio_bridge` | `run_mcp_stdio_bridge(server_names=None, vuln_db_path=":memory:", session_tainted=True) -> int` | Integer exit code (`0`). | Starts `AgyStdioMCPBridge.serve_stdio()` over newline-delimited JSON-RPC 2.0 stdin/stdout. |
| `main` | `main(argv: list[str] | None = None) -> int` | Integer exit code (`0` on success). | Parses CLI arguments via `argparse` and dispatches the selected subcommand. |

---

## 3. Subcommands & CLI Arguments

| Subcommand | Supported Flags | Purpose |
| :--- | :--- | :--- |
| `evaluate-blueprint` | `--budget <int>` (default: `1800000`) | Audits the 4-Pool model lineup, license compliance, Scenario A/B/C recommendation, GPU break-even months, and PropBench-9 suites. |
| `train-model` | `--model-id`, `--base-checkpoint`, `--domain {swe,cyber,binrev,data_protocol,architecture,visual_ocr,forensics,vuln_intel}`, `--pool`, `--params-b`, `--active-params-b`, `--context-window`, `--license`, `--dataset-file`, `--output-dir`, `--execution-mode {spec_only,mlx_qlora,torch_trl}`, `--lora-rank`, `--training-iters` | Runs the 5-stage model creation & post-training pipeline. |
| `create-custom-model` | Same flags as `train-model` | Alias subcommand emphasizing custom model creation and `.safetensors` + `.manifest.json` export. |
| `run-workflow` | `--domain {swe,cyber,binrev,data_protocol,architecture,visual_ocr,forensics,vuln_intel}`, `--model-id`, `--manifest`, `--payload-file` | Runs the 10-step checkpointed agent workflow using built-in or custom task payloads. |
| `run-custom-model` | Same flags as `run-workflow` | Loads a custom model `.manifest.json` (and verifies its `.safetensors` checkpoint) and runs the 10-step workflow. |
| `inspect-data` | `--hex <hex_bytes>` (required) | Classifies a hex-encoded byte stream via `DataAndVisualMCPServer.classify_transformation()` and synthesizes a Kaitai `.ksy` schema. |
| `hardware-check` | *(none)* | Detects host OS, architecture, memory, and accelerator (`LocalHardwareDetector.detect()`) and lists recommended local models. |
| `download-model` | `--model-id <repo_id>` (required), `--license`, `--local-dir` | Downloads a license-approved open-weight model from Hugging Face via `ModelDownloadManager`. |
| `sync-vuln-db` | `--db-path`, `--feeds` (`kev epss osv`) | Syncs public CISA KEV / FIRST EPSS / OSV feeds into a local SQLite vulnerability mirror. |
| `scan-forensics` | `--target-dir <dir>` (required), `--platform {auto,ios,android,host}`, `--stix-file`, `--use-mvt-cli` | Triages iOS/Android/Host artifacts for mercenary spyware IOCs via `ForensicsMCPServer`. |
| `audit-vulns` | `--project-dir <dir>` (required), `--db-path` | Audits project dependencies and AST taint against the SQLite vulnerability mirror. |
| `analyze-image` | `--path <file>` (required), `--prompt`, `--endpoint` | Inspects image metadata or extracts text from `.pdf`/`.md`/`.txt`/`.json`/`.csv`, with optional OpenAI-compatible VLM analysis. |
| `run-benchmarks` | `--suites` (`coding reasoning cyber_vuln forensics hallucination_resistance`) | Runs executable `BenchmarkSuiteRunner` capability and hallucination-resistance suites. |
| `harvest-corpus` | `--pdf`, `--book-dir`, `--url`, `--domain`, `--license`, `--limit`, `--allowed-domain`, `--requests-per-second`, `--distill-output`, `--teacher-model`, `--teacher-license`, `--max-samples-per-doc`, `--no-ingest-rag`, `--rag-db-path`, `--output`, `--tainted` / `--clean` | Harvests local books/PDFs and firewall-approved URLs into `HybridKnowledgeStore` and optionally exports distilled JSONL trajectories. |
| `recommend-strategy` | `--corpus-tokens <int>` (required), `--domain`, `--custom-vocab`, `--target-params-m`, `--output` | Recommends RAG-only vs. local QLoRA vs. compact scratch SLM vs. multi-GPU post-training. |
| `train-scratch-slm` | `--model-id`, `--corpus-file`, `--corpus-dir`, `--text`, `--output-dir`, `--tier {10M,50M,125M,350M}`, `--steps`, `--d-model`, `--n-layers`, `--n-heads`, `--d-ff`, `--vocab-size`, `--max-seq-len`, `--batch-size`, `--learning-rate`, `--seed`, `--backend {auto,stdlib,mlx,torch}`, `--license`, `--domain`, `--sample-prompt`, `--max-new-tokens`, `--output` | Trains a byte-level BPE tokenizer and compact causal Transformer SLM, exporting `.safetensors`, `.tokenizer.json`, and `.manifest.json`. |
| `run-agy-local` | `--agent-name`, `--prompt` (required), `--runtime {local_openai,litert}`, `--model`, `--base-url`, `--litert-backend {gpu,npu}`, `--skills-dir`, `--mcp-server`, `--max-subagent-depth`, `--force-fallback`, `--output`, `--tainted` / `--clean` (default tainted) | Runs a local Google Antigravity SDK agent (or deterministic stdlib fallback) gated by `IndependentVerifierAgent`. |
| `mcp-stdio-bridge` | `--server` / `--servers`, `--vuln-db-path`, `--tainted` / `--clean` (default tainted) | Serves `platform_core` MCP servers over newline-delimited JSON-RPC 2.0 stdin/stdout. |

---

## 4. Custom Workflow Payload Loader (`_load_custom_workflow_payload`)

When `--payload-file <path.json>` is passed to `run-workflow` or `run-custom-model`, `_load_custom_workflow_payload()` performs security and type normalization:
1. Rejects symlinked payload files (`path.is_symlink() -> PermissionError`).
2. Validates `domain` against `CustomModelPipeline.VALID_DOMAINS`.
3. Automatically converts hex-encoded binary fields inside `task_payload`:
   - `binary_payload_hex` -> `binary_payload: bytes`
   - `sample_payload_hex` -> `sample_payload: bytes`
   - `magic_bytes_hex` -> `magic_bytes: bytes`
4. Deserializes `visual_regions` dictionaries (`bbox` or `bbox_xyxy` 4-tuples) into typed `VisualRegionObservation` instances.

---

## 5. Verified Usage Examples

```bash
# Evaluate blueprint
PYTHONPATH=src .venv/bin/python -m platform_core.cli evaluate-blueprint --budget 1800000

# Recommend local model creation strategy for 150K tokens
PYTHONPATH=src .venv/bin/python -m platform_core.cli recommend-strategy --corpus-tokens 150000 --domain cyber

# Harvest documentation into RAG and distilled JSONL
PYTHONPATH=src .venv/bin/python -m platform_core.cli harvest-corpus \
  --pdf docs/CUSTOM_MODEL_GUIDE.md \
  --domain swe \
  --distill-output ./artifacts/harvested/trajectories.jsonl

# Train a compact scratch SLM and sample from it
PYTHONPATH=src .venv/bin/python -m platform_core.cli train-scratch-slm \
  --model-id micro-swe-slm \
  --text "def safe_div(a, b): return a / b if b else 0" \
  --output-dir ./artifacts/scratch_slm \
  --steps 10 \
  --sample-prompt "def safe_div"

# Run local Antigravity SDK orchestrator (with deterministic fallback & SecVerifier)
PYTHONPATH=src .venv/bin/python -m platform_core.cli run-agy-local \
  --prompt "Audit sample Python function for command injection" \
  --force-fallback
```

---

## 6. Related Documentation

- [API & CLI Contract Reference](../api/README.md)
- [Custom Model Creation & Execution Guide](../CUSTOM_MODEL_GUIDE.md)
- [Layer 1 Intelligence Module Reference](layer1-intelligence.md)
- [Layer 2 Execution Module Reference](layer2-execution.md)
- [Layer 3 Evolution Module Reference](layer3-evolution.md)
- [ADR-0006: Local AI Creator & Google Antigravity SDK Bridge](../architecture/decisions/ADR-0006-local-ai-creator-and-antigravity-sdk.md)
