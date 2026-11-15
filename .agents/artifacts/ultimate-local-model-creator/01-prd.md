# Product Requirements Document (`01-prd.md`)

**Feature Slug:** `ultimate-local-model-creator`  
**Target Package:** `platform_core` (`v1.0.0` -> `v1.1.0` additive extension)  
**Zero-Dependency Invariant:** `pyproject.toml` `[project].dependencies` MUST remain `[]`.

---

## 1. Executive Objective
Enable engineers and security researchers to build, specialize, and orchestrate **sovereign local AI models and multi-agent systems** on zero additional hardware (36 GB Apple Silicon `Apple M3 Pro` baseline) while scaling seamlessly to multi-GPU clusters — combining:
1. Safe PDF book + rate-limited web harvesting + teacher distillation into `HybridKnowledgeStore` RAG and `DatasetHygienePipeline` training corpora.
2. Pre-trained-first strategy advising (`Qwen3.5-35B-A3B`, `Qwen3-Coder-30B-A3B`, `Foundation-Sec-8B-Reasoning`, `Qwen3-VL-8B-Thinking`, LiteRT `gemma4-26b`) alongside genuine from-scratch BPE tokenization + compact (`10M–350M`) Transformer SLM creation exporting verified `.safetensors` weights.
3. Google Antigravity SDK (`LiteRTAgentConfig`, `LocalOpenAIAgentConfig`, `skills_paths`, `SubagentConfig`, `McpStdioServer`) local multi-agent orchestration + stdio MCP bridge over existing `platform_core` deterministic servers, with full stdlib fallback.
4. Five portable workspace skills under `.agents/skills/` following `workflow-skill-creator` conventions.

---

## 2. User Stories & Measurable Acceptance Criteria

### Epic A: Corpus, Web & PDF Book Harvester + Teacher Distiller
- **US-A1 (PDF Book & Document Ingestion):** As a researcher, I want to extract and chunk technical PDFs, Markdown, and text books (coding, engineering, security) into provenance-tracked chunks without duplicating PDF parsers.
  - **AC-A1.1:** `PDFBookExtractor.extract_book()` delegates PDF/text extraction to `DataAndVisualMCPServer.extract_document_text()`, rejects symlinks (`PermissionError`), computes SHA-256 digests, and splits text into overlapping chunks preserving fenced code blocks where possible.
  - **AC-A1.2:** All extracted text passes through `PromptInjectionSanitizer.sanitize()`, replacing injection markers (`ignore previous instructions`, `<|im_start|>`, `<|endoftext|>`, `system: override`) with `[REDACTED_PROMPT_INJECTION]` and recording `injection_alerts`.
- **US-A2 (Rate-Limited, Firewall-Gated Web Harvesting):** As a security engineer, I want to harvest public documentation/advisories with strict SSRF, taint, and rate-limit protections.
  - **AC-A2.1:** `RateLimitedWebHarvester.fetch_url()` checks `CyberGymFirewall.evaluate_egress()` first; `session_tainted=True`, direct IP literals (`127.0.0.1`, `169.254.169.254`, RFC1918), `localhost`, and non-allowlisted domains fail closed with `PermissionError`.
  - **AC-A2.2:** Uses `time.monotonic()` to enforce `requests_per_second` (default `1.0 req/s`), retries transient `5xx` and `429` with exponential backoff logged to `sys.stderr`, caps response reads at `MAX_RESPONSE_BYTES` (5 MiB), and raises `RateLimitError` when HTTP 429 persists across retries.
- **US-A3 (RAG Integration & Teacher Synthetic Distillation):** As a model builder, I want harvested documents indexed into `HybridKnowledgeStore` and distilled into `TrainingTrajectoryRecord` JSONL via a permissive open-weight teacher.
  - **AC-A3.1:** `CorpusHarvesterPipeline.run_harvest()` ingests sanitized chunks into `HybridKnowledgeStore` preserving the `< 200,000` token `DIRECT_PREFIX_CACHE` invariant.
  - **AC-A3.2:** `TeacherDistiller.synthesize_trajectories()` checks `LicenseComplianceAuditor` on the teacher model and corpus (`APPROVED_COMMERCIAL` only), generates valid `TrainingTrajectoryRecord` items that pass `DatasetHygienePipeline.filter_records()`, and writes JSONL atomically without overwriting symlinks.

### Epic B: Pre-Trained-First Strategy Advisor + From-Scratch BPE Tokenizer & SLM Trainer
- **US-B1 (Hardware-Aware Strategy Advisor):** As a practitioner on a 36 GB Mac or multi-GPU box, I want deterministic guidance on whether to use RAG, QLoRA fine-tuning, multi-GPU post-training, or a compact from-scratch SLM.
  - **AC-B1.1:** `CreationStrategyAdvisor.recommend()` inspects `LocalHardwareDetector.detect()` (or caller-supplied `LocalHardwareInfo`) and `ModelRegistry.for_profile()`, returning a `StrategyRecommendation` with `ModelCreationPath`, chosen `base_model_id`, `estimated_vram_gb`, `fits_local_budget`, and explicit rationale.
  - **AC-B1.2:** Recommends `PRETRAINED_RAG_ONLY` for `< 50,000` corpus tokens, `PRETRAINED_QLORA_FIRST` for `>= 50,000` tokens on 36 GB local hardware (preferring `fdtn-ai/Foundation-Sec-8B-Reasoning` or `Qwen/Qwen3-VL-8B-Thinking`), `FROM_SCRATCH_COMPACT_SLM` only when `custom_vocab_required=True` or `target_params_m` in `[10, 350]` is explicitly requested, and `MULTI_GPU_FULL_POST_TRAIN` when `CLUSTER_DEFAULT` / `WORKSTATION_GPU` headroom supports 27B–35B+ training.
- **US-B2 (From-Scratch Byte-Level BPE Tokenizer):** As a model creator, I want a zero-dependency byte-level BPE tokenizer trained on my domain corpus that round-trips arbitrary UTF-8 text and persists safely to JSON.
  - **AC-B2.1:** `BytePairTokenizer.train()` learns deterministic BPE merges up to `vocab_size` (`>= 256 + 4` special tokens), `encode()`/`decode()` round-trips ASCII and UTF-8 strings accurately, and `save()`/`load()` reject symlinks and validate schema types (no `bool` as `int`).
- **US-B3 (Compact Transformer SLM Trainer & Safetensors Export):** As a model creator, I want to train a compact causal Transformer SLM (`10M–350M` design presets or tiny test dimensions) from scratch and export verified `.safetensors` + `.manifest.json`.
  - **AC-B3.1:** `ScratchSLMConfig.validate()` rejects `bool` values on integer fields, enforces `d_model % n_heads == 0`, validates `LicenseComplianceAuditor`, and supports parameter counts in the `10M–350M` range (plus tiny unit-test dimensions when configured directly).
  - **AC-B3.2:** `CompactTransformerSLMTrainer.train_and_export()` executes real gradient updates reducing cross-entropy loss (`final_loss < initial_loss` on repeatable corpus), writes `.safetensors` (validated by `SafetensorsValidator` for exact `shape * dtype` contiguous byte spans and SHA-256), `tokenizer.json`, and `<model_id>.manifest.json` loadable via `load_artifact_manifest()`, and supports `generate_sample()`.

### Epic C: Google Antigravity SDK Local Multi-Agent Runner & Stdio MCP Bridge
- **US-C1 (Local Agent Runner with SDK + Stdlib Fallback):** As an agent developer, I want to configure and run local agents using Google Antigravity SDK (`LiteRTAgentConfig`, `LocalOpenAIAgentConfig`, `skills_paths`, `SubagentConfig`, `McpStdioServer`) with graceful stdlib fallback when `google-antigravity` is not installed.
  - **AC-C1.1:** `AgyLocalOrchestrator.build_sdk_config()` supports `"litert"` (expanding `~` via `os.path.expanduser()` on `model_path`) and `"local_openai"` (`model`, `base_url`), binds `skills_paths`, `SubagentConfig` hierarchies, and `McpStdioServer` tool allowlists.
  - **AC-C1.2:** When `google.antigravity` is absent or `force_fallback=True`, `run_local_agent()` executes deterministically via `InferenceBackend` + `AgySkillDiscovery` + `IndependentVerifierAgent` without crashing, and enforces `TAINTED_UNTRUSTED` stripping (`network_egress`, `admin_deploy` excluded) plus `can_mark_completed=True` on verifier only.
- **US-C2 (Stdio JSON-RPC 2.0 MCP Bridge):** As a local agent, I want to call `platform_core`'s existing deterministic MCP tools (`DataAndVisualMCPServer`, `VulnIntelMCPServer`, `ForensicsMCPServer`, `CodeGraphMCPServer`, `BinRevMCPServer`, `DefensiveCyberMCPServer`) over stdio MCP without duplicating server logic.
  - **AC-C2.1:** `AgyStdioMCPBridge` exposes valid Python-identifier tool names (`initialize`, `tools/list`, `tools/call`), routes directly to existing MCP server methods, enforces `session_tainted=True` restrictions (blocking `sync_live_feeds` when tainted), and processes newline-delimited JSON-RPC 2.0 requests cleanly over `stdin`/`stdout`.

### Epic D: 5 Workspace Skills (`.agents/skills/`)
- **US-D1 (Skill Suite Compliance):** As an Antigravity / Codex agent, I want 5 discoverable skills under `.agents/skills/`:
  1. `corpus-harvester`
  2. `local-model-advisor`
  3. `scratch-slm-trainer`
  4. `pretrained-qlora-finetuner`
  5. `agy-local-agent-runner`
  - **AC-D1.1:** Each skill has `SKILL.md` with valid YAML frontmatter (`name` <= 64 chars, lowercase hyphenated; `description` <= 1024 chars, third-person trigger wording) and required sections (`Overview`, `Dependencies`, `Quick Start`, `Utility Scripts`, `Rate Limiting` where applicable, `Common Mistakes`).
  - **AC-D1.2:** Every skill `scripts/*.py` uses stdlib `argparse` subcommands, `--output` JSON file output (`indent=2`), explicit required `--limit` on bounded retrieval commands, `time.monotonic()` rate limiting + `RateLimitError` on HTTP 429 where web/API requests occur, and reuses `platform_core` modules without duplicating MCP logic.

### Epic E: CLI Subcommands, Verification & Documentation
- **US-E1 (`platform-cli` Extensions):** Add `harvest-corpus`, `recommend-strategy`, `train-scratch-slm`, `run-agy-local`, and `mcp-stdio-bridge` subcommands to [`src/platform_core/cli.py`](../../../src/platform_core/cli.py) without breaking any of the 13 existing subcommands.
- **US-E2 (Zero-Warning Test Gate & Security Hygiene):** All existing 35 tests plus new unit/integration tests pass under `PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v`; `pyproject.toml` retains `dependencies = []`; `security-reviewer` issues `VERDICT: PASS`; all affected docs and traceability matrices are updated in the same task.
