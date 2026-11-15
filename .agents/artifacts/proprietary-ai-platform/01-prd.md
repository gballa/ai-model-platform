# Product Requirements Document (`01-prd.md`)

## 1. Product Vision
Deliver the **Proprietary Technical Intelligence Platform (`platform_core`)**—a modular, model-independent Python software system implementing the Three-Layer Hybrid Intelligence Architecture capable of:
1. **Handling & Orchestrating** the 4-Pool specialized open-weight model lineup, 6-Agent execution lifecycle, 3-Tier structural code intelligence, binary reverse-engineering workflows, defensive cybersecurity CPG/sanitizer verification, data transformation taxonomy/Kaitai schema synthesis, and bitemporal memory.
2. **Creating & Post-Training** the sophisticated domain-specialized AI models (`Qwen3.8-27B-SWE-Cyber` and `Qwen3.8-27B-BinRev`) via automated proprietary data factories, decontamination/hygiene pipelines, multi-stage training configs (CPT, Trajectory SFT, MOPD, DPO), and critic-free **GRPO + RLVR** with deterministic execution reward oracles.

## 2. User Stories & Measurable Acceptance Criteria

### US-01: Layer 1 Adaptive Model Gateway & Test-Time Scaling
- **As an** AI Platform Engineer, **I want** an Adaptive Model Router that maps tasks across the 4 specialized model pools, configures SGLang/vLLM RadixAttention serving, enforces switchable thinking budgets (`NON_THINK`, `THINK_HIGH`, `THINK_MAX`), and executes Best-of-N (`TTS@N`) candidate pruning via deterministic verifiers.
- **Acceptance Criteria**:
  - Routes architecture/1M-context tasks to Pool 1 (`DeepSeek-V4-Flash` / `Qwen3.5-397B-A17B`), SWE/Cyber tasks to Pool 2 (`Qwen3.8-27B-SWE-Cyber`), binary/decompilation tasks to Pool 3 (`Qwen3.8-27B-BinRev`), and UI/OCR tasks to Pool 4 (`OmniParser-V2` + `UI-TARS-1.5-7B` + `GOT-OCR-2.0`).
  - Caps thinking tokens per turn according to entropy/complexity to prevent the Overthinking Trap.
  - Selects highest-scoring verified candidate in `TTS@N` parallel rollouts.

### US-02: Layer 1 Model Creation & Post-Training Engine (CPT -> SFT -> MOPD -> GRPO/RLVR -> DPO)
- **As an** ML Scientist, **I want** a complete post-training & RLVR framework that computes critic-free GRPO advantages, scores SWE/Cyber patches and decompiled binaries via deterministic reward oracles, distills multi-teacher trajectories (MOPD), and generates distributed FSDP2 / DeepSpeed ZeRO-3 training specifications.
- **Acceptance Criteria**:
  - `GRPOTrainer` computes group-normalized advantages $A_i = (r_i - \mu_r) / (\sigma_r + \epsilon)$ with entropy weighting and KL divergence penalty against the reference policy, handling zero-variance groups safely without division by zero.
  - `SWECyberRewardOracle` implements the SecVerifier dual-gate reward: `+1.0` (compiles + PoC mitigated + 100% pass-to-pass regression tests pass), `-0.5` (PoC mitigated but pass-to-pass regression broken — penalizing over-correction), `-1.0` (compilation failure, tool JSON error, or PoC still triggers crash).
  - `BinRevDecompileRewardOracle` scores two-phase SK²Decompile + ReCopilot outputs using compilation ($R_{\text{comp}}$), functional test re-executability ($R_{\text{exec}}$), and DWARF struct layout IoU.

### US-03: Layer 2 10-Step Stateful Agent Orchestrator, 6 Specialist Agents & MicroVM Sandboxing
- **As a** Security & Software Architect, **I want** a 10-step checkpointed execution state machine with 6 consolidated specialist agents, scoped MCP tool binding, human `interrupt()` approval gates, taint propagation (`TAINTED_UNTRUSTED`), Firecracker CoW snapshot rollback, and mandatory `IndependentVerifierAgent` gating.
- **Acceptance Criteria**:
  - Implements all 10 lifecycle steps deterministically with SQLite/persistent state checkpointing and crash recovery.
  - Enforces that executor agents cannot set task status to `COMPLETED`; only `IndependentVerifierAgent` can mark `COMPLETED` or trigger a Firecracker snapshot rollback and retry (up to 3 attempts, escalating to `TTS@4` on attempt 3).
  - Marks sessions ingesting untrusted binaries/repos as `TAINTED_UNTRUSTED`, blocking outbound network egress and host mounts.

### US-04: Deterministic MCP Tool Servers (Code Graph, Binary/RevEng, Defensive Cyber, Data & Visual)
- **As an** Autonomous Agent, **I want** deterministic MCP servers for 3-Tier Code Intelligence (AST + SCIP + Git co-change + `str_replace` syntax validation), Binary Intelligence (ELF/PE/Mach-O header parsing, `checksec`, string extraction, ReCopilot context formatting, Kaitai `.ksy` synthesis), Transformation Taxonomy (Encoding vs Compression vs Encryption vs Hashing), and Epistemic Visual Grounding.
- **Acceptance Criteria**:
  - Three-Tier Code Graph indexes Python/multi-language files incrementally using content hashes, resolves callers/callees and git co-change blast radius, and returns `NoConfidentMatch` fallback when grammar is unsupported.
  - Transformation classifier accurately separates Base64/Hex/JSON encoding, gzip/zlib/zstd compression, high-entropy encryption, and fixed-length digests using Shannon entropy, chi-square byte uniformity, and magic headers, and synthesizes valid Kaitai Struct `.ksy` YAML specs.
  - Visual intelligence separates grounded `[x1, y1, x2, y2]` OCR observations from low-confidence regions requiring a programmatic crop/zoom call.

### US-05: Layer 3 Bitemporal Memory, Proprietary Data Factories, PropBench-9 & Supply-Chain Governance
- **As a** Platform Operator, **I want** Graphiti/GAM bitemporal memory, decontaminated data factories, PropBench-9 multi-run statistical evaluation, the 8-Step Controlled Improvement Cycle, and supply-chain security validators (Safetensors enforcement, license compliance audit, signed MCP manifests).
- **Acceptance Criteria**:
  - Bitemporal memory supersedes outdated facts (`valid_to`, `invalid_at`) when new commits invalidate prior assumptions.
  - Dataset hygiene pipeline performs MinHash Jaccard deduplication, execution filtering, and blocks any repo/CVE on the benchmark decontamination blocklist.
  - Supply-chain auditor rejects `.pkl`/`.pt` pickle checkpoints, rejects `Llama-4-Community` (EU ban) or copyleft `GPL`/`AGPL` licenses, and verifies HMAC-SHA256 MCP tool manifests.
