# ADR-0001: Three-Layer Hybrid Intelligence Architecture & 5-Stage Open-Weight Post-Training (`Scenario-B`)

- **Identifier:** ADR-0001
- **Status:** Accepted
- **Date:** 2026-11-15
- **Source Modules:** [`models.py`](../../../src/platform_core/layer1_intelligence/models.py), [`router.py`](../../../src/platform_core/layer1_intelligence/router.py), [`training.py`](../../../src/platform_core/layer1_intelligence/training.py)

---

## 1. Context

Building a technical intelligence platform capable of autonomous software engineering (`swe`), defensive cybersecurity (`cyber`), stripped binary decompilation (`binrev`), protocol forensics (`data_protocol`), architectural analysis (`architecture`), and visual UI/diagram grounding (`visual_ocr`) requires choosing:
1. Whether to pre-train foundation models from scratch, wrap closed commercial APIs, or post-train permissive open-weight models.
2. Whether to use a single monolithic model or route across specialized model pools with bounded thinking tokens.
3. How to structure the boundary between neural inference, stateful execution, and continuous learning.

Empirical evidence encoded in `HardwareFeasibilityPlanner` and `AdaptiveModelRouter` shows:
- Pre-training from scratch costs \$5.6M–\$50M+ (`pretrain_from_scratch_justified: False`).
- Unconstrained chain-of-thought reasoning suffers from the "Overthinking Trap" ($r = -0.56$ accuracy drop on tool-grounded tasks).

---

## 2. Decision

1. **Three-Layer Hybrid Architecture**: Partition the system into **Layer 1 (`layer1_intelligence`)** for model routing, serving, and post-training; **Layer 2 (`layer2_execution`)** for checkpointed 10-step execution, deterministic MCP program analysis, and microVM sandboxing; and **Layer 3 (`layer3_evolution`)** for bitemporal memory, trajectory data factories, and statistical benchmark evaluation.
2. **Four-Pool Model Lineup**: Route workloads across four specialized pools (`POOL_1_ORCHESTRATOR` with `DeepSeek-V4-Flash` `MIT` and `Qwen3.5-397B-A17B` `Apache-2.0`; `POOL_2_SWE_CYBER` with `Qwen3.8-27B-SWE-Cyber`; `POOL_3_BINREV` with `Qwen3.8-27B-BinRev`; `POOL_4_VISUAL_OCR` with `OmniParser-V2-UI-TARS-GOT-OCR`).
3. **Entropy-Bounded Switchable Thinking Modes**: Enforce per-turn token caps in `AdaptiveModelRouter` (`NON_THINK = 0`, `THINK_HIGH = 512..1024`, `THINK_MAX = 2048`).
4. **5-Stage Post-Training under `Scenario-B`**: Specialize permissive open-weight checkpoints via:
   - Stage 1: Proprietary trajectory synthesis & 4-gate `DatasetHygienePipeline`.
   - Stage 2: Distributed sharding (`pytorch_fsdp2_dtensor` for `<100B` dense; `deepspeed_zero3` for `>=100B` MoE) with a 15%–30% general replay ratio during CPT.
   - Stage 3: Multi-Teacher Online Policy Distillation (`MOPDDistiller`) from `DeepSeek-V4-Pro` (`MIT`) and `Qwen3.5-397B-A17B` (`Apache-2.0`).
   - Stage 4: Critic-free `GRPOTrainer` driven by programmatic execution reward oracles (`SWECyberRewardOracle` and `BinRevDecompileRewardOracle`).
   - Stage 5: `DPOTrainer` preference alignment, `.safetensors` packaging, and 5-run Canary Promotion Gating.

---

## 3. Consequences

- **Positive**: Full weight ownership under OSI-approved commercial licenses (`Apache-2.0` / `MIT`), `22.3`-month GPU hardware break-even vs. cloud rental, predictable TTFT (`<=120ms` on 27B models with SGLang RadixAttention), and elimination of critic-model VRAM overhead during RLVR via group-normalized GRPO advantages.
- **Trade-offs**: Requires maintaining deterministic reward oracles and decontamination pipelines (`DatasetHygienePipeline`) to prevent reward hacking and benchmark leakage.

---

## 4. Alternatives Considered

1. **Pre-Training from Scratch**: Rejected in `HardwareFeasibilityPlanner.recommend_scenario()` due to \$5.6M–\$50M+ compute cost without commensurate gains over post-trained `Qwen3.8-27B` and `DeepSeek-V4-Flash`.
2. **Closed-API Wrapping or Distillation**: Rejected in `LicenseComplianceAuditor` (`Proprietary-Closed-API`) due to zero weight ownership, external data egress of sensitive code/binaries, and Terms of Service prohibitions against commercial distillation.
3. **`torchtune` Post-Training Framework**: Explicitly blocked in `DistributedTrainingSpecBuilder.FORBIDDEN_FRAMEWORKS` in favor of native PyTorch FSDP2 (`DTensor`) and DeepSpeed ZeRO-3.
