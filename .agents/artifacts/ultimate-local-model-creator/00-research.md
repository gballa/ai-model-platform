# Research & Architecture Feasibility Study (`00-research.md`)

**Feature Slug:** `ultimate-local-model-creator`  
**Target Host Baseline:** Apple Silicon `Apple M3 Pro`, 36 GB Unified Memory (`safe_model_budget_gb = 28.08 GB`, `LOCAL_APPLE_SILICON_36GB`), plus optional `WORKSTATION_GPU` and `CLUSTER_DEFAULT` multi-GPU scaling.  
**Core Constraint:** Zero mandatory third-party runtime dependencies in [`pyproject.toml`](../../../pyproject.toml) (`dependencies = []` preserved); optional extras (`[mlx]`, `[train]`, `[vision]`, `google-antigravity`, `litert-lm`) integrate opportunistically with deterministic stdlib fallbacks.

---

## 1. Zero-Additional-Hardware Local AI Creation on 36 GB Apple Silicon vs. Multi-GPU Scaling

### 1.1 Empirical Hardware Baseline
Running `platform_core.cli hardware-check` on this host (`Darwin`, `arm64`, `Apple M3 Pro`) reports:
- **Total Unified Memory:** `36.0 GB`
- **Safe Model Memory Budget (`safe_model_budget_gb`):** `28.08 GB` (~78% after reserving macOS + KV-cache headroom via `LocalHardwareDetector.detect()` in [`models.py`](../../../src/platform_core/layer1_intelligence/models.py))
- **Existing `LOCAL_APPLE_SILICON_36GB` Lineup in `ModelRegistry`:**

| Model ID | Pool | Params (Total / Active) | 4-bit Footprint | FP8 Footprint | Fits 28.08 GB 4-bit? | Role & Local Training Feasibility |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `Qwen/Qwen3.5-35B-A3B` | `POOL_1_ORCHESTRATOR` | 35B / 3B MoE | 19.5 GB | 36.0 GB | Yes (inference) | Primary orchestrator & native VLM; too large for local full fine-tuning, ideal for inference + teacher distillation. |
| `Qwen/Qwen3-Coder-30B-A3B-Instruct` | `POOL_2_SWE_CYBER` | 30.5B / 3.3B MoE | 17.5 GB | 31.0 GB | Yes (inference) | Fast coding specialist (~48 tok/s M3 Pro); QLoRA possible only at short context/grad checkpointing. |
| `fdtn-ai/Foundation-Sec-8B-Reasoning` | `POOL_2_SWE_CYBER` | 8.0B / 8.0B Dense | 4.8 GB | 8.5 GB | Yes (inference + QLoRA) | Primary local QLoRA fine-tuning target for cyber/vuln/forensics on 36 GB Mac (`MLXQLoRATrainer`). |
| `Qwen/Qwen3-VL-8B-Thinking` | `POOL_4_VISUAL_OCR` | 8.2B / 8.2B Dense | 5.5 GB | 9.0 GB | Yes (inference + QLoRA) | Primary local multimodal OCR/diagram QLoRA target. |
| `Qwen/Qwen3.8-27B` | `POOL_3_BINREV` | 27.8B / 27.8B Dense | 17.5 GB | 28.0 GB | Yes (tight; inference) | Dense Gated DeltaNet 3:1; QLoRA best run on `WORKSTATION_GPU` (48–96 GB) or `CLUSTER_DEFAULT` (FSDP2). |
| LiteRT `gemma4-26b` (`gemma-4-26B-A4B-it`) | On-device LiteRT | 26B / 4B MoE | ~16.8 GB `.litertlm` | N/A | Yes (Metal GPU) | Managed on-device runtime via Google Antigravity SDK `LiteRTAgentConfig` (64K KV-cache, `token_threshold=40960` compaction). |

### 1.2 Pre-Trained Post-Training First vs. From-Scratch Compact SLM (`10M–350M`)
`HardwareFeasibilityPlanner.recommend_scenario()` in [`models.py`](../../../src/platform_core/layer1_intelligence/models.py) already rejects multi-billion-parameter from-scratch pre-training (`$5.6M–$50M+`). However, users building **proprietary domain AI** on zero additional hardware face four distinct regimes where both approaches have concrete technical merit:

1. **Corpus `< 50,000` tokens (e.g., a few PDFs, internal runbooks, small repo):**
   - **Winner: `PRETRAINED_RAG_ONLY` (`HybridKnowledgeStore` + `DIRECT_PREFIX_CACHE`)**.
   - At `< 200,000` tokens, [`HybridKnowledgeStore.retrieve`](../../../src/platform_core/layer3_evolution/memory.py) returns the full corpus in `DIRECT_PREFIX_CACHE` mode with zero retrieval loss and zero training cost. Fine-tuning on `< 50K` tokens risks catastrophic overfitting.
2. **Corpus `50,000 – 50,000,000` tokens of coding, engineering, hacking methodology, or security playbooks:**
   - **Winner: `PRETRAINED_QLORA_FIRST` (`MLXQLoRATrainer` on Apple Silicon / `TorchTRLSpecAndRunner` on CUDA)**.
   - Post-training `fdtn-ai/Foundation-Sec-8B-Reasoning` (4.8 GB 4-bit) or `Qwen/Qwen3-VL-8B-Thinking` (5.5 GB 4-bit) via 4-bit MLX QLoRA (`rank=16`, `grad_checkpoint=True`, `max_seq_length=4096`) fits comfortably inside `28.08 GB` unified memory while preserving general reasoning and tool-calling priors.
3. **Specialized Fixed-Grammar, Edge-Footprint, Custom-Tokenizer, or Educational Own-Weights Creation (`10M–350M` params):**
   - **Winner: `FROM_SCRATCH_COMPACT_SLM` (`BytePairTokenizer` + `CompactTransformerSLMTrainer`)**.
   - A `10M–350M` causal Transformer with a custom domain BPE vocabulary (e.g., protocol frames, assembly mnemonics, binary/AST tokens, or compact domain corpora) trains from random initialization on consumer Apple Silicon (`MLX` or `PyTorch MPS` or pure-stdlib fallback for deterministic tiny smoke-runs) without downloading multi-GB checkpoints, producing owned `.safetensors` weights + tokenizer + manifest.
   - **Important Trade-off:** A `10M–350M` from-scratch SLM will **not** match an 8B–35B pre-trained model on open-ended reasoning or tool orchestration; `CreationStrategyAdvisor` must explicitly surface this trade-off and default to pre-trained QLoRA unless `custom_vocab_required=True` or `target_params_m` in `[10, 350]` is explicitly requested.
4. **Multi-GPU Scaling (`WORKSTATION_GPU` / `CLUSTER_DEFAULT`):**
   - **Winner: `MULTI_GPU_FULL_POST_TRAIN`** via existing `DistributedTrainingSpecBuilder` (`PyTorch FSDP2` for 7B–70B; `DeepSpeed ZeRO-3` for 100B+ MoE) and `TorchTRLSpecAndRunner` in [`training.py`](../../../src/platform_core/layer1_intelligence/training.py).

---

## 2. Corpus Acquisition: PDF Books, Rate-Limited Web Harvesting, Distillation & RAG

### 2.1 Reusing Existing Platform Primitives (Zero Duplication)
Inspection of the repository shows key primitives already exist and must be composed rather than reimplemented:
- **PDF & Text Extraction:** [`DataAndVisualMCPServer.extract_document_text`](../../../src/platform_core/layer2_execution/mcp_tools.py) already handles `.pdf` (using `pypdf` when installed, with bounded streaming `zlib.decompressobj(max_length=2*1024*1024)` fallback), `.md`, `.txt`, `.json`, `.csv`, and rejects symlinks. A new `PDFBookExtractor` should wrap and chunk its output rather than duplicating `_extract_pdf_text`.
- **SSRF & Taint Network Firewall:** [`CyberGymFirewall`](../../../src/platform_core/deploy_security/governance.py) already blocks `session_tainted=True`, direct IP literals (including `169.254.169.254` and RFC1918), `localhost`, and unapproved domains. `RateLimitedWebHarvester` must route every URL through `CyberGymFirewall.evaluate_egress()` before opening any `urllib.request` connection.
- **RAG & Prompt-Injection Sanitization:** [`HybridKnowledgeStore`](../../../src/platform_core/layer3_evolution/memory.py) already provides thread-safe WAL SQLite (`check_same_thread=False`, `RLock`, `busy_timeout=30000`), FTS5 + dense vector RRF, SHA-256 provenance, and the `< 200,000` token `DIRECT_PREFIX_CACHE` invariant.
- **Data Hygiene & Decontamination:** [`DatasetHygienePipeline`](../../../src/platform_core/layer3_evolution/data_factory.py) already enforces permissive licenses, benchmark holdout repo/CVE blocklists, MinHash Jaccard deduplication, and `execution_verified` gating on `TrainingTrajectoryRecord`.

### 2.2 Threat Surface in PDF Books & Web Pages
Technical books and security blogs (e.g., exploit writeups, pentesting methodologies, reverse-engineering guides) frequently contain:
1. **Indirect Prompt Injection:** Strings like `Ignore all previous instructions`, `<|im_start|>system`, `<|endoftext|>`, or `system: override` embedded in web comments or PDF text layers. Note that `HybridKnowledgeStore.INJECTION_REGEX` catches three basic patterns, while `BinRevMCPServer.PROMPT_INJECTION_PATTERNS` checks four; our `PromptInjectionSanitizer` must combine and expand these (covering special chat-template delimiter tokens `<|im_start|>`, `<|im_end|>`, `<|endoftext|>`, `### System:`, zero-width Unicode obfuscation) **before** chunks enter either `HybridKnowledgeStore` or teacher distillation JSONL.
2. **Oversized or Malicious Payloads:** Unbounded HTTP downloads or zip-bombed PDF streams. Enforced via `MAX_RESPONSE_BYTES` streaming reads and `DataAndVisualMCPServer` bounded decompression.
3. **Rate-Limit Abuse (HTTP 429):** Enforced via `time.monotonic()` pacing (`1.0 req/sec` default when no higher limit is documented), exponential backoff on `429`/`5xx`, stderr retry logging, and raising `RateLimitError` on exhaustion per `workflow-skill-creator` Rule 2.

---

## 3. Google Antigravity SDK (`google-antigravity`) Local Multi-Agent & MCP Integration

From the verified SDK documentation in [`local_models.md`](../../../../../.gemini/config/plugins/google-antigravity-sdk/skills/google-antigravity-sdk/references/local_models.md), [`mcp_integration.md`](../../../../../.gemini/config/plugins/google-antigravity-sdk/skills/google-antigravity-sdk/references/mcp_integration.md), [`agent_skills.md`](../../../../../.gemini/config/plugins/google-antigravity-sdk/skills/google-antigravity-sdk/examples/getting_started/agent_skills.md), and [`subagents.md`](../../../../../.gemini/config/plugins/google-antigravity-sdk/skills/google-antigravity-sdk/examples/getting_started/subagents.md):

1. **Two Local Config Classes (Zero Cloud API Key Required):**
   - `LiteRTAgentConfig(model_path=os.path.expanduser(...), backend="gpu"|"npu", enable_speculative_decoding=..., skills_paths=..., mcp_servers=..., subagents=..., policies=[...])` — manages an on-device loopback server for `.litertlm` checkpoints (e.g., `~/.litert-lm/models/gemma4-26b/model.litertlm`), using Metal on macOS Apple Silicon or CUDA on Linux/Windows.
   - `LocalOpenAIAgentConfig(model=..., base_url=..., ...).lightweight()` — connects to external local servers (`mlx_lm.server`, Ollama `http://localhost:11434/v1`, LM Studio `http://localhost:1234/v1`, `llama-server`).
2. **Skills & Hierarchical Subagents:**
   - `skills_paths=[".agents/skills"]` discovers every `<skill_name>/SKILL.md` automatically.
   - `SubagentConfig(name=..., description=..., capabilities=SubagentCapabilities(enabled_tools=..., allowed_subagents=...))` paired with `CapabilitiesConfig(enable_subagents=True, max_subagent_depth=..., allowed_subagents=...)`.
3. **MCP Stdio Bridge (`McpStdioServer`):**
   - `types.McpStdioServer(name="platform_core_mcp", command=sys.executable, args=["-m", "platform_core.cli", "mcp-stdio-bridge"], enabled_tools=[...])`.
   - Exposing `DataAndVisualMCPServer`, `VulnIntelMCPServer`, `ForensicsMCPServer`, `CodeGraphMCPServer`, `BinRevMCPServer`, and `DefensiveCyberMCPServer` over JSON-RPC 2.0 stdio using Python stdlib (`sys.stdin`/`sys.stdout` + `json`) avoids adding `fastmcp` to `pyproject.toml` core dependencies while maintaining valid Python-identifier tool and parameter names (per `mcp_integration.md` Gotchas).
4. **Graceful Stdlib Fallback & `SecVerifier` Gate:**
   - Because `google-antigravity` is an optional external package and `pyproject.toml` mandates `dependencies = []`, `AgyLocalOrchestrator` must detect `google.antigravity` dynamically at runtime. When absent (or when `force_fallback=True` for deterministic CI/offline tests), it constructs identical validated config snapshots, discovers `.agents/skills/` frontmatter, executes via `InferenceBackend` (`DeterministicMockBackend` / `OpenAICompatibleClient` / `MLXLocalBackend`), and gates final completion through `IndependentVerifierAgent` (`can_mark_completed=True`).

---

## 4. Workspace Skill Suite Design (`workflow-skill-creator` Pattern)

Following [`workflow_skill_creator/SKILL.md`](../../../../../.gemini/config/plugins/science/skills/workflow_skill_creator/SKILL.md), [`cli_script_template.py`](../../../../../.gemini/config/plugins/science/skills/workflow_skill_creator/references/cli_script_template.py), and [`agy-customizations/docs/skills.md`](../../../../../.gemini/antigravity/builtin/skills/agy-customizations/docs/skills.md):
- Every skill lives under `.agents/skills/<skill-name>/` with `SKILL.md` (strict YAML frontmatter `name` + `description`, `Dependencies`, `Quick Start`, `Utility Scripts`, `Rate Limiting`, `Common Mistakes`) and `scripts/*.py`.
- All 5 skills involve programmatic I/O, data processing, or API calls -> **CLI Script Pattern (Rule 3)** is mandatory:
  - `argparse` subcommands for each workflow step.
  - `--output` writes formatted JSON (`json.dump(..., indent=2)`); stdout prints only short status lines (Rule 4).
  - Bounded query arguments like `--limit` are `required=True` (no silent defaults).
  - HTTP interactions enforce `time.monotonic()` rate limiting, exponential backoff on `429`/`5xx`, stderr retry logging, and `RateLimitError` on HTTP 429.
  - Zero reimplementation of existing MCP servers: skills invoke `platform_core` classes (`DataAndVisualMCPServer`, `VulnIntelMCPServer`, `ForensicsMCPServer`, `CorpusHarvesterPipeline`, `CreationStrategyAdvisor`, `CompactTransformerSLMTrainer`, `CustomModelPipeline`, `AgyLocalOrchestrator`).
