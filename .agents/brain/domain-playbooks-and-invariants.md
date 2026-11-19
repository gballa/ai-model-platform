# `platform-core` Agent Operational Memory — Guardrails, Invariants & Domain Playbooks

**Parent Hub:** [`.agents/brain/README.md`](README.md)  
**Authoritative Policy:** [`AGENTS.md`](../../AGENTS.md), [`docs/HOW_TO_GUIDES.md`](../../docs/HOW_TO_GUIDES.md), [`docs/CUSTOM_MODEL_GUIDE.md`](../../docs/CUSTOM_MODEL_GUIDE.md)

---

## Table of Contents

1. [The 7 Non-Negotiable Architectural & Domain Invariants](#1-the-7-non-negotiable-architectural--domain-invariants)
2. [Concurrency, Sandbox & Binary Parser Hardening Rules](#2-concurrency-sandbox--binary-parser-hardening-rules)
3. [Domain Playbook 1: Software Engineering (`swe`)](#3-domain-playbook-1-software-engineering-swe)
4. [Domain Playbook 2: Defensive Cybersecurity (`cyber`)](#4-domain-playbook-2-defensive-cybersecurity-cyber)
5. [Domain Playbook 3: Vulnerability Intelligence (`vuln_intel`)](#5-domain-playbook-3-vulnerability-intelligence-vuln_intel)
6. [Domain Playbook 4: Digital Forensics & Spyware Triage (`forensics`)](#6-domain-playbook-4-digital-forensics--spyware-triage-forensics)
7. [Domain Playbook 5: Binary Reverse Engineering (`binrev`)](#7-domain-playbook-5-binary-reverse-engineering-binrev)
8. [Domain Playbook 6: Protocol & Data Forensics (`data_protocol`)](#8-domain-playbook-6-protocol--data-forensics-data_protocol)
9. [Domain Playbook 7: Visual Document & Layout Analysis (`visual_ocr`)](#9-domain-playbook-7-visual-document--layout-analysis-visual_ocr)
10. [Domain Playbook 8: System Architecture & Diagram Verification (`architecture`)](#10-domain-playbook-8-system-architecture--diagram-verification-architecture)
11. [Model Creation Playbook: Strategy Advisor, QLoRA & Scratch SLM](#11-model-creation-playbook-strategy-advisor-qlora--scratch-slm)
12. [Common Failure Modes & Agent Troubleshooting Memory](#12-common-failure-modes--agent-troubleshooting-memory)

---

## 1. The 7 Non-Negotiable Architectural & Domain Invariants

Every agent modifying or executing code in `platform-core` MUST preserve these 7 invariants:

### Invariant 1: Executor vs. Verifier Separation (`SecVerifier` Gate)
- **Rule**: Executor agents (`SoftwareEngineeringAgent`, `ReverseEngineeringAgent`, `DefensiveCyberAgent`, `MultimodalDataAgent`) have `can_mark_completed = False` and must **never** transition a task or workflow to `TaskStatus.COMPLETED`.
- **Gatekeeper**: Only `IndependentVerifierAgent` (`can_mark_completed = True`) may mark a workflow `COMPLETED` after deterministic test, PoC, compilation, forensic, or schema verification.
- **Applies To**: [`agents.py`](../../src/platform_core/layer2_execution/agents.py), [`orchestrator.py`](../../src/platform_core/layer2_execution/orchestrator.py), [`agy_sdk_bridge.py`](../../src/platform_core/layer2_execution/agy_sdk_bridge.py).

### Invariant 2: Taint Propagation (`TAINTED_UNTRUSTED`)
- **Rule**: Any session ingesting external repositories (`external_repo=True`) or untrusted binaries (`untrusted_binary=True`) at Step 1 is marked `TaintLevel.TAINTED_UNTRUSTED`.
- **Consequence**: Strips `network_egress` and `admin_deploy` tool capabilities, disables `vuln_sync_live_feeds`, blocks non-loopback `OpenAICompatibleClient` URLs, and enforces `internal=True` sandbox network isolation.
- **Applies To**: [`state.py`](../../src/platform_core/layer2_execution/state.py), [`orchestrator.py`](../../src/platform_core/layer2_execution/orchestrator.py), [`vuln_intel_mcp.py`](../../src/platform_core/layer2_execution/vuln_intel_mcp.py), [`agy_sdk_bridge.py`](../../src/platform_core/layer2_execution/agy_sdk_bridge.py).

### Invariant 3: 200K-Token Hybrid Knowledge Rule
- **Rule**: `HybridKnowledgeStore.retrieve()` MUST return `mode="DIRECT_PREFIX_CACHE"` whenever total ingested corpus tokens are `< 200,000` (regardless of `top_k`), switching to `mode="HYBRID_PGVECTORSCALE_SEARCH"` (FTS5 BM25 + dense vector Reciprocal Rank Fusion) only at `>= 200,000` tokens.
- **Applies To**: [`memory.py`](../../src/platform_core/layer3_evolution/memory.py).

### Invariant 4: Finite-Sample Entropy & DWARF Struct Layout IoU
- **Rule A (Entropy)**: `DataAndVisualMCPServer.classify_transformation()` normalizes raw Shannon entropy $H(X)$ against the finite-sample theoretical maximum $H_{\max} = \min(8.0, \log_2 N)$ so short (16B–64B) ciphertext buffers are accurately classified as `ENCRYPTION`.
- **Rule B (Struct IoU)**: `BinRevDecompileRewardOracle.compute_struct_layout_iou()` computes byte-interval overlap over $[ \text{offset}, \text{offset} + \text{size} )$ rather than exact offset-key equality.
- **Applies To**: [`mcp_tools.py`](../../src/platform_core/layer2_execution/mcp_tools.py), [`training.py`](../../src/platform_core/layer1_intelligence/training.py).

### Invariant 5: Forensic Anti-Fabrication & Epistemic Separation
- **Rule**: `ForensicsMCPServer` and `IndependentVerifierAgent` reject any `ForensicVerdict.CONFIRMED_IOC_MATCH` lacking a real on-disk `artifact_path` and a valid 64-character lowercase hex `artifact_sha256`. Partial or encrypted acquisitions MUST populate `visibility_limitations`, and Step 10 records `EpistemicStatus` (`FACT`, `HYPOTHESIS`, `UNCERTAIN`) on `PlatformState.epistemic_assessment`.
- **Applies To**: [`forensics_mcp.py`](../../src/platform_core/layer2_execution/forensics_mcp.py), [`state.py`](../../src/platform_core/layer2_execution/state.py), [`agents.py`](../../src/platform_core/layer2_execution/agents.py).

### Invariant 6: Workspace Markdown & `.agents/` Link Portability
- **Rule**: Every checked-in `.md` file across `README.md`, `docs/**`, `.agents/skills/**/SKILL.md`, `.agents/brain/**`, and `.agents/artifacts/**` MUST use repository-relative links only — never machine-local home-directory paths or `file:` URIs.
- **Rule (Skills)**: `.agents/skills/` contains the 5 canonical workspace skills (`corpus-harvester`, `local-model-advisor`, `scratch-slm-trainer`, `pretrained-qlora-finetuner`, `agy-local-agent-runner`), each matching its directory name in YAML frontmatter and exposing `--output` and positive `--limit` CLI flags.

### Invariant 7: Fail-Closed Script Defaults & Checkpoint Serialization Safety
- **Rule A (Fail-Closed Taint)**: `run-agy-local`, `mcp-stdio-bridge`, and `run_agy_agent.py` default to `session_tainted=True` (`--tainted`), requiring an explicit `--clean` flag to enable live network feed tools.
- **Rule B (Distillation Hygiene)**: `TeacherDistiller` defaults distilled trajectories to `execution_verified=False` unless verified by a deterministic execution oracle.
- **Rule C (Safetensors `<Q` Header Guard)**: Exported `.safetensors` checkpoints pad JSON header metadata (`header_pad`) so the 8-byte little-endian `<Q` header length prefix never collides with Python pickle magic bytes (`\x80\x02`..`\x80\x05`, i.e., lengths `640`, `896`, `1152`, `1408`).

---

## 2. Concurrency, Sandbox & Binary Parser Hardening Rules

1. **Thread-Safe SQLite Stores**:
   - Every SQLite connection (`SQLiteStateCheckpointer`, `CodeGraphMCPServer`, `VulnIntelMCPServer`, `BitemporalEpisodicMemory`, `HybridKnowledgeStore`) uses `check_same_thread=False`, `threading.RLock()`, `PRAGMA journal_mode=WAL` (for file-backed DBs), and `PRAGMA busy_timeout=30000`.
2. **Sandbox Sync-Back Safety (`FirecrackerSandboxManager`)**:
   - Rejects symlinks (`path.is_symlink()`), validates `path.resolve().is_relative_to(resolved_root)`, sanitizes sandbox IDs against `..` traversal, strips secret environment variables (`AWS_*`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `HF_TOKEN`), and prunes deleted files on rollback.
3. **Bounded Streaming & Binary Parsers**:
   - Use streaming `zlib.decompressobj().decompress(data, max_length)` instead of unbounded `zlib.decompress()`.
   - Validate `isinstance(val, int) and not isinstance(val, bool)` on integer JSON-RPC and schema fields in Python (since `bool` subclasses `int`).
   - Verify exact contiguous tensor byte spans (`data_offsets` matching `prod(shape) * dtype_size`) in `SafetensorsValidator`.

---

## 3. Domain Playbook 1: Software Engineering (`swe`)

- **CLI Entrypoint**: `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain swe`
- **Specialist Agent**: `SoftwareEngineeringAgent` -> verified by `IndependentVerifierAgent`
- **Model Pool**: `ModelPool.PRIMARY_SWE_CYBER` (`Qwen/Qwen3.5-35B-A3B` / Apache-2.0 Qwen3.8 coder)
- **MCP Tool**: `CodeGraphMCPServer.query_impact_cone(changed_symbols, max_hops=2)`
- **Reward Oracle (`SWECyberRewardOracle.compute_reward`)**:
  $$R_{\text{swe}} = 0.65 \cdot r_{\text{pass\_to\_pass}} + 0.35 \cdot r_{\text{fail\_to\_pass}} - \text{penalty}_{\text{lint/complexity}}$$
  Returns `0.0` immediately if any existing `pass_to_pass` regression test fails.

---

## 4. Domain Playbook 2: Defensive Cybersecurity (`cyber`)

- **CLI Entrypoint**: `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain cyber`
- **Specialist Agent**: `DefensiveCyberAgent` -> verified by `IndependentVerifierAgent`
- **Model Pool**: `ModelPool.PRIMARY_SWE_CYBER`
- **MCP Tool**: `DefensiveCyberMCPServer.run_sast_taint_scan(source_code, filename)`
- **AST Capabilities**: Detects tainted data flow into `eval`, `exec`, `os.system`, `subprocess.*(shell=True)`, `pickle.loads`, `yaml.load`, and raw SQL formatting (`CWE-78`, `CWE-89`, `CWE-94`, `CWE-502`).
- **Reward Oracle**: Requires both exploit PoC neutralization (`r_sec = 1.0`) and 100% functional test retention.

---

## 5. Domain Playbook 3: Vulnerability Intelligence (`vuln_intel`)

- **CLI Entrypoints**:
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli sync-vuln-db --db-path /tmp/vuln.db --feeds kev epss`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli audit-vulns --project-dir .`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain vuln_intel`
- **MCP Server**: `VulnIntelMCPServer` ([`vuln_intel_mcp.py`](../../src/platform_core/layer2_execution/vuln_intel_mcp.py))
- **Key Guardrails**:
  - Always verify `AuthorizationScope` (`authorized_targets`) before scanning.
  - Classifies dependencies into `CONFIRMED_VULNERABLE_AFFECTED`, `UPSTREAM_CVE_NOT_EXPLOITABLE`, or `CLEAN_NO_KNOWN_CVE` enriched with CISA KEV and FIRST EPSS percentile scores.

---

## 6. Domain Playbook 4: Digital Forensics & Spyware Triage (`forensics`)

- **CLI Entrypoints**:
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli scan-forensics --target-dir <dir> --platform auto`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain forensics`
- **MCP Server**: `ForensicsMCPServer` + `Stix2IocEngine` ([`forensics_mcp.py`](../../src/platform_core/layer2_execution/forensics_mcp.py))
- **Supported Acquisition Types**: iOS backup (`Manifest.db`, `Info.plist`, `Shutdown.log`, `DataUsage.sqlite`), Android bugreport/APK acquisition (`packages.xml`, `bugreport.txt`), and Host forensic directory triage.
- **Key Guardrails**: Never fabricate an IOC match without a real file and 64-hex SHA-256 digest; record encrypted/missing database constraints in `visibility_limitations`.

---

## 7. Domain Playbook 5: Binary Reverse Engineering (`binrev`)

- **CLI Entrypoint**: `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain binrev`
- **Specialist Agent**: `ReverseEngineeringAgent` -> verified by `IndependentVerifierAgent`
- **Model Pool**: `ModelPool.SYSTEMS_BINREV` (`DeepSeek-Coder-V3.5-32B-BinRev`)
- **MCP Tool**: `BinRevMCPServer.decompile_and_extract_cfg(binary_hex, arch="x86_64")`
- **Reward Oracle (`BinRevDecompileRewardOracle.compute_reward`)**:
  $$R_{\text{binrev}} = 0.20 \cdot r_{\text{compile}} + 0.50 \cdot r_{\text{io\_equiv}} + 0.20 \cdot \text{IoU}_{\text{dwarf\_bytes}} + 0.10 \cdot \text{sim}_{\text{cfg}}$$

---

## 8. Domain Playbook 6: Protocol & Data Forensics (`data_protocol`)

- **CLI Entrypoints**:
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli inspect-data --hex <hex_bytes>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain data_protocol`
- **MCP Tool**: `DataAndVisualMCPServer.classify_transformation(raw_bytes)`
- **Classification Buckets**: `ENCODING_SERIALIZATION` ($H_{\text{norm}} < 0.62$ or UTF-8/base64/JSON/TLV), `COMPRESSION` (magic headers `\x78\x9c`, `\x1f\x8b`, `\x28\xb5\x2f\xfd` or $0.62 \le H_{\text{norm}} < 0.92$), `ENCRYPTION` ($H_{\text{norm}} \ge 0.92$ with uniform byte chi-square distribution).

---

## 9. Domain Playbook 7: Visual Document & Layout Analysis (`visual_ocr`)

- **CLI Entrypoints**:
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli analyze-image --path <file>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain visual_ocr`
- **MCP Tool**: `DataAndVisualMCPServer.inspect_visual_document(file_path)`
- **Capabilities**: Pure-stdlib binary header inspection for PNG (`IHDR`), JPEG (`SOF0`/`SOF2`), GIF, WebP (`VP8`/`VP8L`/`VP8X`), and PDF (`%PDF-`, page count, `/FlateDecode` text stream extraction with bounded `zlib.decompressobj`), plus spatial `[x1, y1, x2, y2]` bounding-box IoU scoring.

---

## 10. Domain Playbook 8: System Architecture & Diagram Verification (`architecture`)

- **CLI Entrypoint**: `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain architecture`
- **MCP Tool**: `DataAndVisualMCPServer.verify_mermaid_and_layout(mermaid_source, predicted_boxes, ground_truth_boxes)`
- **Verification Gate**: Validates Mermaid graph syntax (`flowchart`, `sequenceDiagram`, `stateDiagram-v2`, `erDiagram`, `classDiagram`), balanced subgraph/bracket blocks, and spatial layout IoU.

---

## 11. Model Creation Playbook: Strategy Advisor, QLoRA, Scratch SLM, Heretic & Brain Pipeline

Use `CreationStrategyAdvisor` (`recommend-strategy`) to choose the right local model creation trajectory:

| Corpus Size & Goal | Recommended Strategy (`ModelCreationPath`) | Execution Tool / CLI |
| :--- | :--- | :--- |
| `< 50,000` tokens or rapid factual grounding | `PRETRAINED_RAG_ONLY` | `harvest-corpus` / `brain-query` -> `HybridKnowledgeStore` (`DIRECT_PREFIX_CACHE`) |
| `50,000` – `5,000,000` tokens on single Apple Silicon / 1–2 GPUs | `PRETRAINED_QLORA_FIRST` | `create-custom-model --execution-mode mlx_qlora` (or `torch_trl` / `spec_only`) |
| Strict custom vocabulary, micro footprint (`10M`–`350M`), or zero external weights | `FROM_SCRATCH_COMPACT_SLM` | `train-scratch-slm --size-tier {micro,10M,25M,50M,125M,350M}` |
| `> 5,000,000` tokens with multi-GPU cluster (`>= 4` GPUs / `>= 192 GB` VRAM) | `MULTI_GPU_FULL_POST_TRAIN` | `train-model` / `create-custom-model` with FSDP2 (`DTensor`) + GRPO/RLVR |
| Rank-$k$ refusal subspace removal with KL-divergence bound (`<= 0.05`) | `HereticAbliterator` ([`heretic.py`](../../src/platform_core/layer1_intelligence/heretic.py)) | `heretic-abliterate --input-safetensors <in> --output-safetensors <out> --rank 2 --max-kl 0.05` |
| Multi-specialist checkpoint fusion (`dare_ties` or `slerp`) + IMatrix GGUF/MLX calibration | `ColdFusionModelMerger` + `ImatrixQuantizationCalibrator` ([`heretic.py`](../../src/platform_core/layer1_intelligence/heretic.py)) | `cold-fusion-merge --checkpoints <a> <b> --output-safetensors <out> --method dare_ties --quant-type Q5_K_M` |
| End-to-end Project Brain sync, GAIN scheduling, dual specialist SLM training, Heretic abliteration, Cold-Fusion merge & IMatrix calibration | `ProjectBrainEngine` ([`brain_engine.py`](../../src/platform_core/layer3_evolution/brain_engine.py)) | `brain-pipeline --output-dir <dir> --model-id heretic-brain-slm --domain swe --quant-type Q5_K_M` |

---

## 12. Common Failure Modes & Agent Troubleshooting Memory

| Symptom / Error | Root Cause | Fix / Action |
| :--- | :--- | :--- |
| `PermissionError: Executor agent cannot set TaskStatus.COMPLETED` | An executor agent attempted to bypass `IndependentVerifierAgent`. | Route candidate output through `IndependentVerifierAgent.verify_and_complete()`. |
| `PermissionError: Live vulnerability feed sync is blocked in TAINTED_UNTRUSTED sessions` | Calling `vuln_sync_live_feeds` when `session_tainted=True` (the fail-closed default). | Use offline SQLite mirror queries (`vuln_audit_dependencies`), or pass `--clean` only for trusted operator sessions. |
| `ValueError: Pickle magic header detected in Safetensors file` | Raw 8-byte `<Q` JSON header length collided with `\x80\x02`..`\x80\x05` (e.g., 1408 bytes) or file is a disguised pickle. | Ensure `header_pad` metadata padding is applied when serializing `.safetensors` headers (handled automatically by `CustomModelPipeline` and `CompactTransformerSLMTrainer`). |
| `ValueError: Gate 1 Hygiene failure (0 records passed)` | Distilled trajectories had `execution_verified=False` and `require_execution_verified=True`. | Verify trajectories through the sandbox/reward oracle first, or pass `--allow-unverified-distillation` when generating synthetic draft datasets. |
| `TestAgySdkBridge.test_skill_discovery...` fails | A new folder or symlink was added directly under `.agents/skills/`. | Keep `.agents/skills/` strictly to the 5 verified workspace skills; store knowledge base files under `.agents/brain/` and feature artifacts under `.agents/artifacts/`. |
