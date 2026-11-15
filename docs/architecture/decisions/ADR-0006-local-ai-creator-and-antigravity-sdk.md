# ADR-0006: Zero-Dependency Local AI Model Creator, Corpus Harvester, Compact Scratch SLM, & Google Antigravity SDK Bridge

---

## Status

`Accepted`

---

## Context

`platform-core` previously provided 5-stage post-training (`CustomModelPipeline` in `training.py`) and local hardware detection (`LocalHardwareDetector` in `models.py`), but lacked:
1. A safe, zero-dependency **corpus acquisition and distillation pipeline** capable of extracting technical PDFs/books/docs and firewall-gated web pages, sanitizing indirect prompt injections, preserving fenced code blocks, routing into the `< 200,000`-token `DIRECT_PREFIX_CACHE` RAG tier, and synthesizing license-audited trajectories.
2. A **hardware- and token-budget-aware strategy advisor** (`CreationStrategyAdvisor`) to steer users toward pre-trained RAG (`< 50,000` tokens), local QLoRA fine-tuning (`50,000+` tokens), multi-GPU post-training, or a **from-scratch compact causal Transformer SLM** (`10M`–`350M` tiers or fast micro defaults) with an owned byte-level BPE tokenizer (`BytePairTokenizer`) exported to verified `.safetensors` checkpoints.
3. A bridge to the **Google Antigravity SDK (`google-antigravity`)** (`AgyLocalOrchestrator`, `AgyStdioMCPBridge`, `AgySkillDiscovery`) supporting `LiteRT` (`os.path.expanduser` path resolution) and `LocalOpenAI` runtimes, newline-delimited JSON-RPC 2.0 stdio MCP tool serving across all 6 `platform_core` MCP servers, and reusable workspace skills under `.agents/skills/`—all without adding mandatory third-party dependencies (`dependencies = []` in `pyproject.toml`).

Additionally, deterministic small-tensor `.safetensors` exports uncovered an edge case where a valid little-endian `<Q` JSON header length ending in `0x80 0x02..0x05` (e.g., `640`, `896`, `1152`, `1408` bytes) matched Python pickle protocol 2–5 magic bytes (`\x80\x02`–`\x80\x05`), requiring header-aware validation in `SafetensorsValidator` and defensive `header_pad` padding in `_PureStdlibTransformer`.

---

## Decision

1. **Zero-Dependency Core with Optional `[agy]` Extra (`pyproject.toml`)**:
   - Keep `dependencies = []` empty in [`pyproject.toml`](../../../pyproject.toml) and add `[project.optional-dependencies] agy = ["google-antigravity>=0.1.0"]` (also included in `[all]`).
   - All new modules (`corpus_harvester.py`, `scratch_trainer.py`, `agy_sdk_bridge.py`) and all 5 workspace skill scripts import only Python standard library modules at import time, probing/importing `mlx`, `torch`, and `google.antigravity` lazily inside runtime methods with deterministic stdlib fallbacks.
2. **Corpus Harvesting, Sanitization & Teacher Distillation (`corpus_harvester.py`)**:
   - `PDFBookExtractor` extracts `.pdf` (via `DataAndVisualMCPServer.extract_document_text`), `.md`, `.txt`, and `.rst` while rejecting `..` traversal, symlinked targets, and symlinked ancestor directories (`_validate_safe_path`).
   - `RateLimitedWebHarvester` enforces `CyberGymFirewall.evaluate_egress(url, session_tainted)` fail-closed before every HTTP request, paces requests via `time.monotonic()`, caps responses at `MAX_RESPONSE_BYTES` (`5 MiB`) and 4xx error bodies at `1024` bytes, retries `5xx`/`429` with exponential backoff without double-sleeping, and raises `RateLimitError` upon 429 exhaustion.
   - `PromptInjectionSanitizer` strips zero-width/control characters and redacts indirect prompt-injection payloads (`<|im_start|>`, `ignore previous instructions`, `### System:`, shell exfil patterns); `DomainChunker` preserves fenced code blocks across overlapping chunks.
   - `TeacherDistiller` audits teacher/source licenses via `LicenseComplianceAuditor`, defaults `execution_verified=False` unless verified by a deterministic `verifier` callable or explicitly opted into `allow_unexecuted_text_synthesis=True`, and filters via `DatasetHygienePipeline`.
   - `CorpusHarvesterPipeline` routes extracted chunks into `HybridKnowledgeStore` (`DIRECT_PREFIX_CACHE` for `< 200,000` tokens, `HYBRID_PGVECTORSCALE_SEARCH` for `>= 200,000` tokens).
3. **Strategy Advising, Byte-Level BPE & Compact Scratch SLM (`scratch_trainer.py`)**:
   - `CreationStrategyAdvisor.recommend()` selects among `PRETRAINED_RAG_ONLY`, `PRETRAINED_QLORA_FIRST`, `FROM_SCRATCH_COMPACT_SLM` (only when `custom_vocab_required=True` or `10 <= target_params_m <= 350`), and `MULTI_GPU_FULL_POST_TRAIN`.
   - `BytePairTokenizer` implements UTF-8 byte-level BPE with special tokens `("<pad>", "<bos>", "<eos>", "<unk>")`, `bool`-as-`int` validation, and symlink-safe JSON persistence.
   - `CompactTransformerSLMTrainer` trains a deterministic causal Transformer (with `10M`, `50M`, `125M`, `350M` `ScratchSLMConfig.preset_tier` presets or fast micro defaults) across `auto` / `stdlib` / `mlx` / `torch` backends and exports verified `.safetensors`, `.tokenizer.json`, and `.manifest.json` artifacts.
   - `SafetensorsValidator.validate_bytes()` (`deploy_security/governance.py`) verifies whether a `\x80\x02`–`\x80\x05` prefix is a valid `<Q` JSON header (`0 < candidate_len <= MAX_HEADER_BYTES`, `8 + candidate_len <= len(raw_bytes)`, `raw_bytes[8:9] == b"{"`) before raising `PickleSupplyChainError`, and `_PureStdlibTransformer.export_safetensors_bytes()` pads `metadata["header_pad"]` to avoid header-length collisions.
4. **Google Antigravity SDK Bridge, Stdio MCP Server & Workspace Skills (`agy_sdk_bridge.py`, `cli.py`, `.agents/skills/`)**:
   - `AgySkillDiscovery.discover_skills()` parses `SKILL.md` YAML frontmatter in pure stdlib while rejecting `..` traversal and symlinked directories/files.
   - `AgyStdioMCPBridge` wraps `data_visual`, `vuln_intel`, `forensics`, `code_graph`, `binrev`, and `defensive_cyber` (`18` clean tools, valid Python identifiers), strips `vuln_sync_live_feeds` (`17` tools) and rejects tainted calls (`-32003`) when `session_tainted=True`, and bounds JSON-RPC 2.0 stdin lines to `MAX_JSONRPC_LINE_BYTES` (`1 MiB`).
   - `AgyLocalOrchestrator` builds `LiteRTAgentConfig` / `LocalOpenAIAgentConfig` (expanding `~` via `os.path.expanduser`, blocking non-loopback `base_url` when tainted, capping `max_subagent_depth`), runs either the live SDK or deterministic stdlib fallback, and gates final `COMPLETED` status through `IndependentVerifierAgent` (`can_mark_completed=True`) inside `FirecrackerSandboxManager`.
   - Exposed 5 new CLI subcommands (`harvest-corpus`, `recommend-strategy`, `train-scratch-slm`, `run-agy-local`, `mcp-stdio-bridge`) and 5 workspace skills (`corpus-harvester`, `local-model-advisor`, `scratch-slm-trainer`, `pretrained-qlora-finetuner`, `agy-local-agent-runner`).

---

## Consequences

- **Positive**: Engineers and AI agents can acquire and sanitize corpora, choose the optimal RAG/QLoRA/scratch-SLM path for local hardware (such as 36 GB Apple Silicon), train and sample compact `.safetensors` SLMs end-to-end on stdlib CPU, and orchestrate local Antigravity SDK agents with all 6 deterministic MCP servers over JSON-RPC stdio—all verified by 49 passing tests under `-W error`.
- **Negative / Trade-offs**: Pure-stdlib Transformer training (`_PureStdlibTransformer`) is intended for micro/smoke CPU runs and deterministic verification; training `10M`–`350M` parameter tiers at scale requires optional `mlx` or `torch` backends, and live `google-antigravity` execution requires installing the `[agy]` extra.

---

## Alternatives Considered

- **Adding `pypdf`, `pyyaml`, `mcp`, and `google-antigravity` as required dependencies**: Rejected because it violates the `dependencies = []` air-gapped stdlib invariant in `pyproject.toml`.
- **Implementing separate MCP tool logic inside `agy_sdk_bridge.py`**: Rejected to prevent policy drift; wrapping existing `platform_core` MCP servers guarantees identical taint, RoE, AST, and anti-fabrication controls.

---

## Source Code Traceability

- [`pyproject.toml`](../../../pyproject.toml)
- [`src/platform_core/cli.py`](../../../src/platform_core/cli.py)
- [`src/platform_core/deploy_security/governance.py`](../../../src/platform_core/deploy_security/governance.py)
- [`src/platform_core/layer1_intelligence/scratch_trainer.py`](../../../src/platform_core/layer1_intelligence/scratch_trainer.py)
- [`src/platform_core/layer2_execution/agy_sdk_bridge.py`](../../../src/platform_core/layer2_execution/agy_sdk_bridge.py)
- [`src/platform_core/layer3_evolution/corpus_harvester.py`](../../../src/platform_core/layer3_evolution/corpus_harvester.py)
- [`tests/test_corpus_and_scratch_trainer.py`](../../../tests/test_corpus_and_scratch_trainer.py)
- [`tests/test_agy_sdk_and_skills.py`](../../../tests/test_agy_sdk_and_skills.py)
- [`.agents/skills/`](../../../.agents/skills/)
