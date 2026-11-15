# Live Research & Deep Research Evaluation (`00-research.md`)

## 1. Source Document Audited
- **Document**: [Proprietary Technical AI Platform Architecture](https://docs.google.com/document/d/1U8DB99ib9grUNQqur86Fi-iU3BOlfVTVZLqvE5DqTnU/edit?usp=drivesdk)
- **Scope**: End-to-end scientific, architectural, and engineering blueprint for building, post-training, evaluating, and operating a sovereign Three-Layer Hybrid Technical Intelligence Platform across Software Engineering (Domain A), Defensive Cybersecurity (Domain B), Reverse Engineering & Binary Intelligence (Domain C), Encoding/Decoding & Data Intelligence (Domain D), Visual/UI Grounding (Domain E), Verifiable Reasoning (Domain F), and Autonomous Sandboxed Execution (Domain G).

## 2. Critical Technical Evaluation of the Deep Research Findings

### 2.1 Why Pre-Training From Scratch Is Rejected
- Pre-training a 1T–2.8T foundation model from random initialization requires $5.6M–$50M+ (2.1M–2.788M+ H100/H800 GPU-hours on 8.4T–36T tokens) and merely duplicates general linguistic/world knowledge already available under permissive licenses (`Apache-2.0` Qwen3.8-27B / Qwen3.5-397B-A17B and `MIT` DeepSeek-V4-Flash).
- Domain specialization via a **5-Stage Post-Training Pipeline (Domain CPT -> State-Aware Trajectory SFT -> Multi-Teacher Online Policy Distillation [MOPD] -> Critic-Free GRPO + RLVR -> DPO)** on `Qwen3.8-27B` elevates CyberGym Level 1 performance from 54.51% to **91.31%** (surpassing GPT-5.5-Cyber at 85.6% and Gemini 3.8 Flash Cyber at 86.3%) and improves binary decompilation functional re-executability ($R_{\text{exec}}$) by +16.2% to +40.1%.

### 2.2 Core Architectural Invariants Validated
1. **Layer 1 — Four-Pool Specialized Model Lineup**:
   - **Pool 1 (`PRIMARY_ORCHESTRATOR`)**: `DeepSeek-V4-Flash` (284B total / 13B active, MIT, 1M context via CSA+HCA sparse attention) and `Qwen3.5-397B-A17B` (Apache-2.0, native VLM MoE) for architectural synthesis and long-horizon orchestration.
   - **Pool 2 (`SWE_CYBER_WORKHORSE`)**: `Qwen3.8-27B-SWE-Cyber` (dense 27.8B Apache-2.0, 3:1 Gated DeltaNet linear attention) specialized via SWE-Fuse (issue-guided + issue-free trajectories) and SEC-bench/CyberGym RLVR.
   - **Pool 3 (`BINREV_SPECIALIST`)**: `Qwen3.8-27B-BinRev` (dense 27.8B Apache-2.0) specialized via Decompile-Bench (2M binary-source pairs across `-O0` to `-O3`), SK²Decompile two-phase Skeleton-to-Skin recovery, and ReCopilot call-graph/data-flow context injection.
   - **Pool 4 (`VISUAL_OCR_PREPARSER`)**: `OmniParser-V2` (YOLOv9-E region detector) + `UI-TARS-1.5-7B` + `GOT-OCR-2.0` for <100ms bounding-box UI grounding and layout-preserving OCR.
   - **Entropy-Aware Adaptive Test-Time Scaling**: Switchable thinking modes (`NON_THINK`, `THINK_HIGH`, `THINK_MAX`) bounded per turn to prevent the "Overthinking Trap" ($r = -0.56$ accuracy correlation on unconstrained long CoT), plus parallel Best-of-N (`TTS@4` / `TTS@8`) with deterministic verifier pruning.
2. **Layer 2 — 6-Agent Stateful Execution Graph & Hardware Sandboxing**:
   - Consolidates 12 candidate roles into **6 deterministic execution nodes**:
     1. `PrincipalOrchestratorAgent` (Orchestrator + Architect + Research)
     2. `SoftwareEngineeringAgent` (Senior Programming + Code Analysis + Debugging)
     3. `ReverseEngineeringAgent` (Binary Analysis + Decompilation + Firmware)
     4. `DefensiveCyberAgent` (CPG Taint Auditing + Sanitizer PoC + Remediation)
     5. `MultimodalDataAgent` (Visual Grounding + Data Transformation Taxonomy + Kaitai Struct `.ksy` synthesis)
     6. `IndependentVerifierAgent` (Testing & Validation + QA — **SecVerifier adversarial gate**)
   - **Hard Invariant**: Executor agents (`SoftwareEngineeringAgent`, `DefensiveCyberAgent`, `ReverseEngineeringAgent`) **cannot** mark their own tasks `COMPLETED`; only `IndependentVerifierAgent` can transition a task to `COMPLETED` after deterministic verification in a clean Firecracker microVM snapshot.
   - **Taint Tracking**: Sessions ingesting untrusted binaries or third-party repositories are tagged `TAINTED_UNTRUSTED`, automatically disabling outbound network egress (`internal=True`) and host filesystem/credential mounts.
3. **Layer 3 — Evolution, Bitemporal Memory, Data Factories & RLVR**:
   - **Three-Tier Code Graph**: Incremental CST/AST (Tree-sitter + XXH3/BLAKE2b content hashing), SCIP compiler symbol/call-graph resolution with `NoConfidentMatch` fallback, and Git co-change blast-radius graph.
   - **Bitemporal Episodic Memory (Graphiti + GAM)**: Decouples the append-only *Event Progression Graph* from the consolidated *Topic Associative Network* with bitemporal edges (`valid_from`, `valid_to`, `invalid_at`) that automatically supersede stale architectural facts on new git commits.
   - **Critic-Free GRPO + RLVR Engine**: Computes group-normalized advantages $A_i = \frac{r_i - \mu_r}{\sigma_r + \epsilon}$ with sequence-level trajectory entropy weighting and explicit dual-gate reward shaping (`+1.0` full fix + 100% pass-to-pass regression pass; `-0.5` partial fix or over-correction breaking pass-to-pass tests; `-1.0` compile/syntax/PoC failure).
   - **8-Step Controlled Improvement Cycle & PropBench-9 Canary Gate**: Never updates weights online on unverified prose; enforces 5-run 95% confidence interval ($\pm 1.96 \cdot s / \sqrt{n}$) and $\text{pass}^k$ consistency checks before promoting checkpoints.
