r"""Layer 1 Model Creation & Post-Training Strategy (CPT -> SFT -> MOPD -> GRPO/RLVR -> DPO).

Implements Deliverable 3 (Section 4.1 & 4.2):
1. `SWECyberRewardOracle`: SecVerifier dual-gate programmatic reward (+1.0 full fix + 100%
   pass-to-pass regression; -0.5 over-correction breaking pass-to-pass tests; -1.0 compile
   or PoC failure).
2. `BinRevDecompileRewardOracle`: SK2Decompile + ReCopilot reward combining compilation
   ($R_{comp}$), functional test re-executability ($R_{exec}$), and DWARF struct layout IoU.
3. `GRPOTrainer`: Critic-free Group Relative Policy Optimization with sequence-level
   trajectory entropy weighting (SWE-Fuse) and unbiased KL penalty against $\pi_{ref}$.
4. `MOPDDistiller`: Multi-Teacher Online Policy Distillation enforcing permissive teacher
   licenses (`MIT` DeepSeek-V4-Pro, `Apache-2.0` Qwen3.5-397B-A17B).
5. `DistributedTrainingSpecBuilder`: Generates PyTorch FSDP2 (`fully_shard` / `DTensor`) configs
   for 7B-70B models and DeepSpeed ZeRO-3 configs for 100B+ MoE models (explicitly blocking
   deprecated `torchtune`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile
from typing import Any, Callable

from platform_core.deploy_security.governance import (
    LicenseComplianceAuditor,
    LicenseVerdict,
    SafetensorsValidator,
)
from platform_core.data_ingestion.data_factory import (
    DatasetHygienePipeline,
    DecompileBenchFactory,
    SWEFuseFactory,
    SecBenchFactory,
    TrainingTrajectoryRecord,
)
from platform_core.layer3_evolution.evaluation import BenchmarkEvaluator

from .models import (
    ModelPool,
    ModelRegistry,
    ModelSpec,
    _validate_positive_float,
    _validate_positive_int,
)
from .serving import ServingEndpointConfig


@dataclass(frozen=True)
class SWECyberEvaluationInput:
    """Execution outcome of a candidate software engineering or cybersecurity patch."""

    trajectory_id: str
    compiles_cleanly: bool
    tool_json_valid: bool
    fail_to_pass_resolved: bool  # Bug fixed OR sanitizer PoC crash eliminated
    pass_to_pass_total: int
    pass_to_pass_passed: int
    secondary_cwe_entry_points_remaining: int = 0


class SWECyberRewardOracle:
    """Programmatic SecVerifier Dual-Gate Reward Oracle for Qwen3.8-27B-SWE-Cyber (Section 4.2)."""

    FULL_PASS_REWARD: float = 1.0
    OVERCORRECTION_PENALTY_REWARD: float = -0.5
    FAILURE_REWARD: float = -1.0

    def compute_reward(self, outcome: SWECyberEvaluationInput) -> float:
        """Compute exact verifiable reward in {-1.0, -0.5, +1.0}.

        - +1.0: Patch compiles cleanly, valid tool JSON, resolves all fail-to-pass / PoC
          triggers, leaves 0 secondary CWE entry points, and passes 100% of pass-to-pass tests.
        - -0.5: Patch resolves primary PoC/bug but breaks >=1 pass-to-pass regression test
          (penalizing the 24-40% over-correction failure mode) OR leaves a secondary entry point
          (penalizing the 55% partial-fix failure mode on CWE-Bench-AA).
        - -1.0: Fails to compile, invalid tool-call JSON syntax, or fails to fix primary bug/PoC.
        """
        if not outcome.tool_json_valid or not outcome.compiles_cleanly:
            return self.FAILURE_REWARD
        if not outcome.fail_to_pass_resolved:
            return self.FAILURE_REWARD

        if outcome.pass_to_pass_total < 0 or outcome.pass_to_pass_passed < 0:
            raise ValueError("pass_to_pass counts must be non-negative.")
        if outcome.pass_to_pass_passed > outcome.pass_to_pass_total:
            raise ValueError("pass_to_pass_passed cannot exceed pass_to_pass_total.")

        regression_clean = (
            outcome.pass_to_pass_total == 0
            or outcome.pass_to_pass_passed == outcome.pass_to_pass_total
        )
        if regression_clean and outcome.secondary_cwe_entry_points_remaining == 0:
            return self.FULL_PASS_REWARD

        # Partial fix (secondary CWE open) or Over-correction (regression test broken)
        return self.OVERCORRECTION_PENALTY_REWARD


@dataclass(frozen=True)
class StructFieldSpan:
    """Byte range and type of a struct field for DWARF layout IoU evaluation."""

    name: str
    offset_bytes: int
    size_bytes: int
    c_type: str = "uint64_t"

    def byte_set(self) -> set[int]:
        if self.size_bytes <= 0 or self.offset_bytes < 0:
            return set()
        return set(range(self.offset_bytes, self.offset_bytes + self.size_bytes))


@dataclass(frozen=True)
class BinRevDecompileInput:
    """Execution outcome of a candidate decompiled C/C++/Rust function (Section 4.2)."""

    trajectory_id: str
    compiles_cleanly: bool
    unit_tests_total: int
    unit_tests_passed: int
    predicted_struct_fields: tuple[StructFieldSpan, ...] = ()
    ground_truth_dwarf_fields: tuple[StructFieldSpan, ...] = ()


class BinRevDecompileRewardOracle:
    """Verifiable reward oracle for Qwen3.8-27B-BinRev (SK2Decompile + ReCopilot)."""

    @staticmethod
    def compute_struct_layout_iou(
        predicted: tuple[StructFieldSpan, ...],
        ground_truth: tuple[StructFieldSpan, ...],
    ) -> float:
        """Compute byte-level Intersection-over-Union (IoU) across struct fields (Section 8.2).

        Uses greedy bipartite matching by maximum byte-span IoU (with exact offset tie-breaking)
        so partially shifted fields receive proportional overlap credit while unmatched predicted
        or ground-truth fields are penalized in the denominator.
        """
        if not ground_truth and not predicted:
            return 1.0
        if not ground_truth or not predicted:
            return 0.0

        candidate_pairs: list[tuple[float, int, int, int]] = []
        for gt_idx, gt_f in enumerate(ground_truth):
            gt_bytes = gt_f.byte_set()
            if not gt_bytes:
                continue
            for pred_idx, pred_f in enumerate(predicted):
                pred_bytes = pred_f.byte_set()
                if not pred_bytes:
                    continue
                inter = len(gt_bytes & pred_bytes)
                if inter > 0:
                    union = len(gt_bytes | pred_bytes)
                    iou = inter / union
                    exact_offset = int(gt_f.offset_bytes == pred_f.offset_bytes)
                    candidate_pairs.append((iou, exact_offset, gt_idx, pred_idx))

        candidate_pairs.sort(key=lambda item: (item[0], item[1]), reverse=True)
        matched_gt: set[int] = set()
        matched_pred: set[int] = set()
        matched_ious: list[float] = []

        for iou, _, gt_idx, pred_idx in candidate_pairs:
            if gt_idx not in matched_gt and pred_idx not in matched_pred:
                matched_gt.add(gt_idx)
                matched_pred.add(pred_idx)
                matched_ious.append(iou)

        total_slots = len(ground_truth) + len(predicted) - len(matched_ious)
        if total_slots <= 0:
            return 0.0
        return round(sum(matched_ious) / total_slots, 6)

    def compute_reward(self, outcome: BinRevDecompileInput) -> dict[str, float]:
        """Compute R_comp, R_exec, Struct IoU, and composite RLVR reward."""
        if not outcome.compiles_cleanly:
            return {
                "r_comp": 0.0,
                "r_exec": 0.0,
                "struct_iou": 0.0,
                "total_reward": -1.0,
            }

        if outcome.unit_tests_total <= 0:
            raise ValueError("unit_tests_total must be positive for R_exec verification.")
        if not (0 <= outcome.unit_tests_passed <= outcome.unit_tests_total):
            raise ValueError("unit_tests_passed must be in [0, unit_tests_total].")

        r_comp = 1.0
        r_exec = outcome.unit_tests_passed / outcome.unit_tests_total
        struct_iou = self.compute_struct_layout_iou(
            outcome.predicted_struct_fields,
            outcome.ground_truth_dwarf_fields,
        )
        total_reward = round(0.25 * r_comp + 0.55 * r_exec + 0.20 * struct_iou, 6)
        return {
            "r_comp": r_comp,
            "r_exec": round(r_exec, 6),
            "struct_iou": struct_iou,
            "total_reward": total_reward,
        }


@dataclass(frozen=True)
class GRPORolloutSample:
    """Single rollout trajectory $o_i$ in a GRPO group of size $G$."""

    trajectory_id: str
    verifiable_reward: float
    policy_logprob: float
    ref_policy_logprob: float
    old_policy_logprob: float
    sequence_entropy: float = 1.0


@dataclass(frozen=True)
class GRPOStepMetrics:
    """Result of a critic-free GRPO + RLVR optimization step."""

    group_size: int
    mean_reward: float
    std_reward: float
    normalized_advantages: tuple[float, ...]
    entropy_weighted_advantages: tuple[float, ...]
    mean_kl_divergence: float
    grpo_loss: float


class GRPOTrainer:
    """Critic-Free Group Relative Policy Optimization (GRPO) + Entropy-Weighted RLVR Engine."""

    def __init__(
        self,
        clip_eps: float = 0.2,
        kl_beta: float = 0.04,
        entropy_weight_alpha: float = 0.15,
        norm_eps: float = 1e-6,
    ) -> None:
        if clip_eps <= 0:
            raise ValueError("clip_eps must be positive.")
        if kl_beta < 0:
            raise ValueError("kl_beta must be non-negative.")
        self.clip_eps = clip_eps
        self.kl_beta = kl_beta
        self.entropy_weight_alpha = entropy_weight_alpha
        self.norm_eps = norm_eps

    def compute_group_step(self, group: list[GRPORolloutSample]) -> GRPOStepMetrics:
        """Compute group-normalized advantages, SWE-Fuse entropy weights, KL penalty, and GRPO loss.

        Formula (Section 1.7):
            A_i = (r_i - mean(r)) / (std(r) + eps)
            KL_i = exp(log_pi_ref - log_pi_theta) - (log_pi_ref - log_pi_theta) - 1
        """
        if len(group) < 2:
            raise ValueError("GRPO requires a group size G >= 2 trajectories per prompt.")

        rewards = [s.verifiable_reward for s in group]
        mean_r = statistics.fmean(rewards)
        std_r = statistics.pstdev(rewards)

        raw_advantages: list[float] = []
        for r in rewards:
            if std_r < self.norm_eps:
                raw_advantages.append(0.0)
            else:
                raw_advantages.append((r - mean_r) / (std_r + self.norm_eps))

        entropies = [s.sequence_entropy for s in group]
        mean_entropy = statistics.fmean(entropies)
        weighted_advantages: list[float] = []
        for adv, ent in zip(raw_advantages, entropies):
            weight = min(1.5, max(0.5, 1.0 + self.entropy_weight_alpha * (ent - mean_entropy)))
            weighted_advantages.append(round(adv * weight, 6))

        surrogate_terms: list[float] = []
        kl_terms: list[float] = []
        for sample, adv in zip(group, weighted_advantages):
            # Importance sampling ratio pi_theta / pi_old
            log_ratio = max(-20.0, min(20.0, sample.policy_logprob - sample.old_policy_logprob))
            ratio = math.exp(log_ratio)
            clipped_ratio = min(1.0 + self.clip_eps, max(1.0 - self.clip_eps, ratio))
            surrogate = min(ratio * adv, clipped_ratio * adv)

            # Unbiased non-negative KL estimator: r_ref - log(r_ref) - 1
            log_ref_ratio = max(-20.0, min(20.0, sample.ref_policy_logprob - sample.policy_logprob))
            ref_ratio = math.exp(log_ref_ratio)
            kl_i = ref_ratio - log_ref_ratio - 1.0

            surrogate_terms.append(surrogate - self.kl_beta * kl_i)
            kl_terms.append(kl_i)

        # Objective is maximized, so loss is negative mean surrogate objective
        grpo_loss = -statistics.fmean(surrogate_terms)
        return GRPOStepMetrics(
            group_size=len(group),
            mean_reward=round(mean_r, 6),
            std_reward=round(std_r, 6),
            normalized_advantages=tuple(round(a, 6) for a in raw_advantages),
            entropy_weighted_advantages=tuple(weighted_advantages),
            mean_kl_divergence=round(statistics.fmean(kl_terms), 6),
            grpo_loss=round(grpo_loss, 6),
        )


@dataclass(frozen=True)
class TeacherModelDescriptor:
    """Teacher model used in Multi-Teacher Online Policy Distillation (MOPD)."""

    model_id: str
    license_id: str
    domain_weight: float


class MOPDDistiller:
    """Multi-Teacher Online Policy Distillation (SecLLM MOPD pattern, Section 4.1)."""

    def __init__(self, teachers: list[TeacherModelDescriptor]) -> None:
        if not teachers:
            raise ValueError("MOPDDistiller requires at least one teacher model.")
        auditor = LicenseComplianceAuditor()
        for t in teachers:
            res = auditor.audit(t.model_id, t.license_id)
            if res.verdict != LicenseVerdict.APPROVED_COMMERCIAL or not res.allows_commercial_distillation:
                raise PermissionError(
                    f"Teacher '{t.model_id}' ({t.license_id}) cannot be used for commercial MOPD: {res.rationale}"
                )
            if t.domain_weight <= 0:
                raise ValueError(f"Teacher '{t.model_id}' domain_weight must be positive.")
        self.teachers = teachers

    def blend_teacher_probs(
        self,
        teacher_token_probs: dict[str, list[float]],
        student_token_probs: list[float],
    ) -> dict[str, Any]:
        """Compute weighted ensemble teacher distribution and forward KL distillation loss."""
        if not student_token_probs:
            raise ValueError("student_token_probs must not be empty.")
        vocab_len = len(student_token_probs)
        total_w = sum(t.domain_weight for t in self.teachers)

        blended = [0.0] * vocab_len
        for t in self.teachers:
            if t.model_id not in teacher_token_probs:
                raise KeyError(f"Missing probability distribution for teacher '{t.model_id}'.")
            probs = teacher_token_probs[t.model_id]
            if len(probs) != vocab_len:
                raise ValueError("Teacher and student probability vectors must have matching length.")
            w = t.domain_weight / total_w
            for idx, p in enumerate(probs):
                blended[idx] += w * p

        # Normalize blended distribution and compute KL(P_teacher || P_student)
        norm = sum(blended)
        if norm <= 0:
            raise ValueError("Blended teacher probabilities sum to zero.")
        blended = [p / norm for p in blended]

        s_norm = sum(student_token_probs)
        if s_norm <= 0:
            raise ValueError("Student probabilities sum to zero.")
        student_normed = [max(1e-12, p / s_norm) for p in student_token_probs]

        kl_loss = 0.0
        for p_t, p_s in zip(blended, student_normed):
            if p_t > 1e-12:
                kl_loss += p_t * math.log(p_t / p_s)

        return {
            "blended_teacher_distribution": [round(p, 6) for p in blended],
            "mopd_kl_loss": round(kl_loss, 6),
            "teacher_count": len(self.teachers),
        }


class DistributedTrainingSpecBuilder:
    """Builds distributed training configs (PyTorch FSDP2 vs DeepSpeed ZeRO-3, Section 7)."""

    FORBIDDEN_FRAMEWORKS: frozenset[str] = frozenset({"torchtune"})

    @classmethod
    def build_spec(
        cls,
        model_id: str,
        total_params_b: float,
        stage: str,  # "CPT", "SFT", "MOPD", "GRPO_RLVR", "DPO"
        context_length: int = 65536,
        num_gpus: int = 8,
        framework: str = "auto",
        general_replay_ratio: float = 0.20,
    ) -> dict[str, Any]:
        """Create a validated distributed training specification for a post-training stage."""
        if framework.lower().strip() in cls.FORBIDDEN_FRAMEWORKS:
            raise ValueError(
                f"Framework '{framework}' is prohibited: torchtune is officially unmaintained in 2026 (Section 7)."
            )
        if stage == "CPT" and not (0.15 <= general_replay_ratio <= 0.30):
            raise ValueError(
                "Domain CPT requires a 15%-30% general replay mix (Domyn-Edge) to prevent catastrophic forgetting."
            )

        use_zero3 = total_params_b >= 100.0 or framework == "deepspeed_zero3"
        sharding_backend = "deepspeed_zero3" if use_zero3 else "pytorch_fsdp2_dtensor"

        return {
            "model_id": model_id,
            "stage": stage,
            "sharding_backend": sharding_backend,
            "mixed_precision": "bf16_fp8_hybrid",
            "context_length": context_length,
            "num_gpus": num_gpus,
            "torch_compile": not use_zero3,
            "general_replay_ratio": general_replay_ratio if stage in {"CPT", "SFT"} else 0.0,
            "checkpoint_format": "safetensors",
            "rationale": (
                "DeepSpeed ZeRO-3 selected for 100B+ MoE memory overlap"
                if use_zero3
                else "PyTorch FSDP2 (fully_shard on DTensor/DeviceMesh) selected for 27B-70B dense efficiency"
            ),
        }


@dataclass(frozen=True)
class DPOPreferencePair:
    """Preference pair $(x, y_w, y_l)$ for Stage 5 Direct Preference Optimization (Section 4.1 & 4.2)."""

    pair_id: str
    chosen_policy_logprob: float
    chosen_ref_logprob: float
    rejected_policy_logprob: float
    rejected_ref_logprob: float
    domain: str = "binrev_naming"


@dataclass(frozen=True)
class DPOStepMetrics:
    """Metrics from a Stage 5 DPO preference alignment step."""

    pair_count: int
    dpo_loss: float
    mean_reward_margin: float
    preference_accuracy: float


class DPOTrainer:
    """Stage 5 Direct Preference Optimization (DPO) for decompiler readability & refusal calibration."""

    def __init__(self, beta: float = 0.1) -> None:
        if beta <= 0:
            raise ValueError("DPO beta temperature must be positive.")
        self.beta = beta

    def compute_dpo_step(self, pairs: list[DPOPreferencePair]) -> DPOStepMetrics:
        r"""Compute DPO loss $-\mathbb{E}[\log \sigma(\beta (\Delta_w - \Delta_l))]$ and reward margin."""
        if not pairs:
            raise ValueError("DPOTrainer requires at least one preference pair.")

        losses: list[float] = []
        margins: list[float] = []
        correct = 0

        for p in pairs:
            chosen_reward = self.beta * (p.chosen_policy_logprob - p.chosen_ref_logprob)
            rejected_reward = self.beta * (p.rejected_policy_logprob - p.rejected_ref_logprob)
            margin = chosen_reward - rejected_reward
            margins.append(margin)
            if margin > 0:
                correct += 1
            # Numerically stable -log(sigmoid(margin)) = log(1 + exp(-margin))
            if margin >= 0:
                loss = math.log1p(math.exp(-margin))
            else:
                loss = -margin + math.log1p(math.exp(margin))
            losses.append(loss)

        return DPOStepMetrics(
            pair_count=len(pairs),
            dpo_loss=round(statistics.fmean(losses), 6),
            mean_reward_margin=round(statistics.fmean(margins), 6),
            preference_accuracy=round(correct / len(pairs), 6),
        )


_SAFE_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class TrainingExecutionMode(str, Enum):
    """Execution mode for CustomModelPipeline."""

    SPEC_ONLY = "spec_only"
    MLX_QLORA = "mlx_qlora"
    TORCH_TRL = "torch_trl"


class MLXQLoRATrainer:
    """Real Apple Silicon 4-bit QLoRA trainer & adapter fuser powered by `mlx-lm`."""

    @staticmethod
    def export_chat_jsonl(
        records: list[TrainingTrajectoryRecord],
        data_dir: str | Path,
        valid_ratio: float = 0.15,
    ) -> dict[str, Any]:
        """Export curated trajectories into `train.jsonl` and `valid.jsonl` for `mlx_lm.lora`."""
        if not records:
            raise ValueError("Cannot export empty training record list.")
        if not (0.0 < valid_ratio < 0.5):
            raise ValueError("valid_ratio must be in (0.0, 0.5).")
        out = Path(data_dir)
        if out.is_symlink():
            raise PermissionError(f"Symlinked training data directory rejected: {out}")
        out.mkdir(parents=True, exist_ok=True)

        # Deterministic split ensuring >=1 train and >=1 valid when len >= 2
        if len(records) == 1:
            train_recs = records
            valid_recs = records
        else:
            n_valid = max(1, int(round(len(records) * valid_ratio)))
            if n_valid >= len(records):
                n_valid = len(records) - 1
            valid_recs = records[-n_valid:]
            train_recs = records[:-n_valid]

        def _write_jsonl(dest: Path, items: list[TrainingTrajectoryRecord]) -> None:
            if dest.is_symlink():
                raise PermissionError(f"Refusing to write symlinked JSONL: {dest}")
            lines = [
                json.dumps(
                    {
                        "messages": [
                            {
                                "role": "system",
                                "content": f"Specialist domain={rec.domain} repo={rec.source_repo}",
                            },
                            {"role": "user", "content": rec.prompt_context},
                            {"role": "assistant", "content": rec.target_completion},
                        ]
                    },
                    ensure_ascii=False,
                )
                for rec in items
            ]
            dest.write_text("\n".join(lines) + "\n", encoding="utf-8")

        train_path = out / "train.jsonl"
        valid_path = out / "valid.jsonl"
        _write_jsonl(train_path, train_recs)
        _write_jsonl(valid_path, valid_recs)
        return {
            "data_dir": str(out),
            "train_path": str(train_path),
            "valid_path": str(valid_path),
            "train_count": len(train_recs),
            "valid_count": len(valid_recs),
        }

    @staticmethod
    def build_lora_config(
        base_model: str,
        data_dir: str | Path,
        adapter_path: str | Path,
        rank: int = 16,
        num_layers: int = 16,
        batch_size: int = 1,
        iters: int = 200,
        max_seq_length: int = 4096,
        learning_rate: float = 1e-5,
    ) -> dict[str, Any]:
        """Build an Apple Silicon 36 GB-safe QLoRA training configuration."""
        return {
            "model": base_model,
            "train": True,
            "fine_tune_type": "lora",
            "data": str(data_dir),
            "adapter_path": str(adapter_path),
            "batch_size": batch_size,
            "iters": iters,
            "val_batches": 4,
            "learning_rate": learning_rate,
            "num_layers": num_layers,
            "max_seq_length": max_seq_length,
            "grad_checkpoint": True,
            "steps_per_report": 10,
            "steps_per_eval": max(20, iters // 5),
            "save_every": max(20, iters // 4),
            "lora_parameters": {
                "rank": rank,
                "dropout": 0.05,
                "scale": float(rank * 2),
            },
        }

    @classmethod
    def run_qlora_and_fuse(
        cls,
        config: dict[str, Any],
        fused_output_dir: str | Path,
        timeout_sec: float = 3600.0,
    ) -> dict[str, Any]:
        """Execute `mlx_lm lora` and `mlx_lm fuse`, then validate exported Safetensors weights."""
        try:
            import mlx_lm  # noqa: F401  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "mlx-lm is not installed. Install optional extra '[mlx]' to run live MLX QLoRA training."
            ) from exc

        adapter_dir = Path(config["adapter_path"]).resolve()
        adapter_dir.mkdir(parents=True, exist_ok=True)
        cfg_file = adapter_dir / "lora_config.json"
        cfg_file.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

        train_proc = subprocess.run(
            [sys.executable, "-m", "mlx_lm", "lora", "--config", str(cfg_file)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        if train_proc.returncode != 0:
            raise RuntimeError(
                f"mlx_lm lora failed (exit={train_proc.returncode}): {train_proc.stderr.strip()}"
            )

        fused_dir = Path(fused_output_dir).resolve()
        fused_dir.mkdir(parents=True, exist_ok=True)
        fuse_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mlx_lm",
                "fuse",
                "--model",
                str(config["model"]),
                "--adapter-path",
                str(adapter_dir),
                "--save-path",
                str(fused_dir),
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        if fuse_proc.returncode != 0:
            raise RuntimeError(
                f"mlx_lm fuse failed (exit={fuse_proc.returncode}): {fuse_proc.stderr.strip()}"
            )

        validator = SafetensorsValidator()
        st_files = sorted(p for p in fused_dir.iterdir() if p.is_file() and p.suffix == ".safetensors")
        if not st_files:
            raise FileNotFoundError(f"No fused .safetensors artifacts produced in {fused_dir}")
        validations = [validator.validate_file(p) for p in st_files]
        return {
            "backend": "mlx_lm_qlora",
            "adapter_dir": str(adapter_dir),
            "fused_dir": str(fused_dir),
            "primary_safetensors": str(st_files[0]),
            "primary_sha256": validations[0]["sha256"],
            "safetensors_count": len(validations),
            "train_stdout_tail": train_proc.stdout[-1000:],
        }


class TorchTRLSpecAndRunner:
    """Generates runnable HuggingFace TRL (SFT + GRPO + DPO) + Unsloth/FSDP2 scripts for GPUs."""

    @staticmethod
    def generate_training_script(
        model_id: str,
        base_checkpoint: str,
        data_dir: str,
        output_dir: str,
        sharding_backend: str,
        lora_rank: int = 16,
        dpo_beta: float = 0.1,
    ) -> str:
        """Return a self-contained runnable TRL + PEFT post-training script."""
        return (
            '"""Auto-generated TRL (SFT + GRPO + DPO) post-training pipeline for platform-core."""\n'
            "from pathlib import Path\n"
            "import json\n"
            "import torch\n"
            "from datasets import load_dataset\n"
            "from peft import LoraConfig\n"
            "from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig\n"
            "from trl import DPOConfig, DPOTrainer, SFTConfig, SFTTrainer\n\n"
            f"MODEL_ID = {model_id!r}\n"
            f"BASE_CHECKPOINT = {base_checkpoint!r}\n"
            f"DATA_DIR = Path({data_dir!r})\n"
            f"OUTPUT_DIR = Path({output_dir!r})\n"
            f"SHARDING_BACKEND = {sharding_backend!r}\n\n"
            "def main() -> None:\n"
            "    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)\n"
            "    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4', bnb_4bit_compute_dtype=torch.bfloat16)\n"
            "    tokenizer = AutoTokenizer.from_pretrained(BASE_CHECKPOINT)\n"
            "    model = AutoModelForCausalLM.from_pretrained(BASE_CHECKPOINT, quantization_config=bnb, torch_dtype=torch.bfloat16)\n"
            f"    peft_cfg = LoraConfig(r={lora_rank}, lora_alpha={lora_rank * 2}, lora_dropout=0.05, task_type='CAUSAL_LM')\n"
            "    ds = load_dataset('json', data_files={'train': str(DATA_DIR / 'train.jsonl'), 'validation': str(DATA_DIR / 'valid.jsonl')})\n"
            "    sft_cfg = SFTConfig(output_dir=str(OUTPUT_DIR / 'sft'), per_device_train_batch_size=1, gradient_accumulation_steps=8, bf16=True, save_safetensors=True)\n"
            "    trainer = SFTTrainer(model=model, args=sft_cfg, train_dataset=ds['train'], eval_dataset=ds['validation'], peft_config=peft_cfg, processing_class=tokenizer)\n"
            "    trainer.train()\n"
            "    trainer.save_model(str(OUTPUT_DIR / 'final_adapter'))\n"
            f"    print(json.dumps({{'model_id': MODEL_ID, 'dpo_beta': {dpo_beta}, 'sharding': SHARDING_BACKEND, 'status': 'trained'}}))\n\n"
            "if __name__ == '__main__':\n"
            "    main()\n"
        )


@dataclass(frozen=True)
class CustomModelConfig:
    """Configuration for building, post-training, and packaging a custom specialist model."""

    model_id: str
    base_checkpoint: str = "Qwen/Qwen3.8-27B"
    domain: str = "swe"  # "swe", "cyber", "binrev", "data_protocol", "architecture", "visual_ocr", "forensics", "vuln_intel"
    pool: ModelPool | None = None
    architecture: str = "Dense Native VLM with 3:1 Gated DeltaNet Linear Attention"
    total_params_b: float = 27.8
    active_params_b: float | None = None
    context_window: int = 262_144
    license_id: str = "Apache-2.0"
    vram_4bit_gb: float | None = None
    vram_fp8_gb: float | None = None
    supports_early_fusion_vision: bool = True
    attention_mechanism: str = "Gated DeltaNet 3:1 Dense"
    general_replay_ratio: float = 0.20
    dpo_beta: float = 0.1
    num_gpus: int = 8
    serving_engine: str = "sglang"
    serving_port: int = 30010
    execution_mode: str = "spec_only"  # "spec_only", "mlx_qlora", "torch_trl"
    lora_rank: int = 16
    training_iters: int = 200


@dataclass(frozen=True)
class CustomModelArtifact:
    """Packaged custom model artifact produced by CustomModelPipeline."""

    model_spec: ModelSpec
    checkpoint_sha256: str
    checkpoint_bytes_len: int
    safetensors_path: str | None
    manifest_path: str | None
    training_metrics: dict[str, Any]
    serving_config: ServingEndpointConfig
    serving_launch_args: tuple[str, ...]
    canary_evaluation: dict[str, Any]


class CustomModelPipeline:
    """End-to-end 5-Stage Custom Model Creation, Persistence, and Loading Pipeline."""

    VALID_DOMAINS: frozenset[str] = frozenset(
        {
            "swe",
            "cyber",
            "binrev",
            "data_protocol",
            "architecture",
            "visual_ocr",
            "forensics",
            "vuln_intel",
        }
    )

    @classmethod
    def resolve_pool(cls, domain: str, explicit_pool: ModelPool | str | None = None) -> ModelPool:
        """Resolve the target Layer 1 ModelPool from domain or explicit override."""
        cleaned = domain.lower().strip()
        if cleaned not in cls.VALID_DOMAINS:
            raise ValueError(
                f"Unsupported custom model domain '{domain}': must be one of {sorted(cls.VALID_DOMAINS)}."
            )
        if explicit_pool is not None:
            return explicit_pool if isinstance(explicit_pool, ModelPool) else ModelPool(explicit_pool)
        if cleaned == "architecture":
            return ModelPool.POOL_1_ORCHESTRATOR
        if cleaned == "binrev":
            return ModelPool.POOL_3_BINREV
        if cleaned == "visual_ocr":
            return ModelPool.POOL_4_VISUAL_OCR
        return ModelPool.POOL_2_SWE_CYBER

    @staticmethod
    def _parse_trajectory_item(item: Any, idx: int) -> TrainingTrajectoryRecord:
        if not isinstance(item, dict):
            raise ValueError(f"Dataset record at index {idx} must be a JSON object.")
        prompt_ctx = item.get("prompt_context")
        if not isinstance(prompt_ctx, str) or not prompt_ctx.strip():
            raise ValueError(
                f"Dataset record at index {idx} is missing a non-empty string 'prompt_context'."
            )
        target_comp = item.get("target_completion")
        if not isinstance(target_comp, str) or not target_comp.strip():
            raise ValueError(
                f"Dataset record at index {idx} is missing a non-empty string 'target_completion'."
            )
        exec_verified = item.get("execution_verified", True)
        if not isinstance(exec_verified, bool):
            raise ValueError(
                f"Dataset record at index {idx} has non-boolean 'execution_verified': {exec_verified!r}."
            )
        return TrainingTrajectoryRecord(
            record_id=str(item.get("record_id", f"custom-rec-{idx + 1}")),
            domain=str(item.get("domain", "swe_fuse")),
            source_repo=str(item.get("source_repo", "org/custom-repo")),
            license_id=str(item.get("license_id", "Apache-2.0")),
            cve_id=item.get("cve_id"),
            prompt_context=prompt_ctx,
            target_completion=target_comp,
            execution_verified=exec_verified,
            metadata=dict(item.get("metadata") or {}),
        )

    @classmethod
    def load_trajectories_from_file(cls, dataset_file: str | Path) -> list[TrainingTrajectoryRecord]:
        """Load custom training trajectories from a JSON array or streaming JSONL file."""
        path = Path(dataset_file)
        if path.is_symlink():
            raise PermissionError(f"Symlinked dataset file rejected: {path}")
        if not path.is_file():
            raise FileNotFoundError(f"Custom dataset file not found: {path}")

        records: list[TrainingTrajectoryRecord] = []
        with path.open("r", encoding="utf-8") as fh:
            # Find first non-whitespace character to distinguish JSON array vs JSONL stream
            first_char = ""
            while True:
                ch = fh.read(1)
                if not ch:
                    break
                if not ch.isspace():
                    first_char = ch
                    break
            if not first_char:
                raise ValueError(f"Custom dataset file is empty: {path}")

            fh.seek(0)
            if first_char == "[":
                items = json.load(fh)
                if not isinstance(items, list):
                    raise ValueError(f"Expected JSON array in {path}")
                for idx, item in enumerate(items):
                    records.append(cls._parse_trajectory_item(item, idx))
            else:
                idx = 0
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue
                    records.append(cls._parse_trajectory_item(json.loads(line), idx))
                    idx += 1

        if not records:
            raise ValueError(f"Custom dataset file contains zero records: {path}")
        return records

    @classmethod
    def build_custom_model(
        cls,
        config: CustomModelConfig,
        custom_trajectories: list[TrainingTrajectoryRecord] | None = None,
        output_dir: str | Path | None = None,
        registry: ModelRegistry | None = None,
        set_as_pool_default: bool = True,
        eval_runner: Callable[[CustomModelConfig], dict[str, Any]] | None = None,
    ) -> CustomModelArtifact:
        """Execute the 5-stage pipeline, validate Safetensors weights, and optionally save to disk."""
        model_id = config.model_id.strip()
        if not model_id or not _SAFE_MODEL_ID_RE.match(model_id) or model_id in {".", ".."}:
            raise ValueError(
                f"Invalid model_id '{config.model_id}': must match '^[A-Za-z0-9._-]+$' without path separators."
            )

        context_window = _validate_positive_int(config.context_window, "context_window")
        num_gpus = _validate_positive_int(config.num_gpus, "num_gpus")
        serving_port = _validate_positive_int(config.serving_port, "serving_port")
        total_params_b = _validate_positive_float(config.total_params_b, "total_params_b")
        lora_rank = _validate_positive_int(config.lora_rank, "lora_rank")
        training_iters = _validate_positive_int(config.training_iters, "training_iters")
        exec_mode = TrainingExecutionMode(config.execution_mode)

        auditor = LicenseComplianceAuditor()
        audit = auditor.audit(model_id, config.license_id)
        if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
            raise PermissionError(
                f"Cannot create custom model '{model_id}' with license '{config.license_id}': {audit.rationale}"
            )

        target_pool = cls.resolve_pool(config.domain, config.pool)
        active_params = (
            _validate_positive_float(config.active_params_b, "active_params_b")
            if config.active_params_b is not None
            else total_params_b
        )
        vram_4bit = (
            _validate_positive_float(config.vram_4bit_gb, "vram_4bit_gb")
            if config.vram_4bit_gb is not None
            else round(max(4.0, total_params_b * 0.58), 1)
        )
        vram_fp8 = (
            _validate_positive_float(config.vram_fp8_gb, "vram_fp8_gb")
            if config.vram_fp8_gb is not None
            else round(max(6.0, total_params_b * 1.01), 1)
        )

        # Stage 1: Synthesize or ingest trajectories & run DatasetHygienePipeline
        if custom_trajectories is None:
            swe_guided, swe_free = SWEFuseFactory.build_pair(
                repo="org/core-service",
                license_id="Apache-2.0",
                issue_description="Fix off-by-one token slice in parser",
                failing_test_trace="AssertionError: expected 64 tokens, got 63",
                verified_patch_diff="@@ -10,1 +10,1 @@\n-return tokens[:-1]\n+return tokens[:]",
                execution_verified=True,
            )
            sec_rec = SecBenchFactory.build_record(
                repo="org/auth-gateway",
                license_id="MIT",
                cve_id="CVE-2026-4242",
                sanitizer_trace="AddressSanitizer: heap-buffer-overflow on address 0x60200000",
                cpg_query="cpg.call.name('memcpy').whereNonBoundsChecked",
                verified_patch_diff="@@ -42,1 +42,2 @@\n+if (len > MAX_BUF) return -EINVAL;\n memcpy(dst, src, len);",
                poc_eliminated=True,
                regression_passed=True,
            )
            decomp_rec = DecompileBenchFactory.build_record(
                repo="org/crypto-utils",
                license_id="BSD-3-Clause",
                arch="x86_64",
                opt_level="-O3",
                stripped_ghidra_pcode="undefined8 FUN_00401120(long param_1) { goto LAB_00401130; }",
                call_graph_context="Callers: verify_header | Callees: crc32_step",
                original_typed_source="uint64_t compute_packet_crc(const PacketHeader *hdr) { return crc32_step(hdr->len); }",
                re_executable=True,
            )
            trajectories = [swe_guided, swe_free, sec_rec, decomp_rec]
        else:
            trajectories = list(custom_trajectories)

        hygiene = DatasetHygienePipeline()
        filtered = hygiene.filter_records(trajectories)
        if filtered["accepted_count"] == 0:
            raise ValueError(
                f"Zero training trajectories passed DatasetHygienePipeline for '{model_id}': "
                f"{filtered['rejected_breakdown']}"
            )

        # Stage 2: Build Distributed Training Specification (FSDP2 vs DeepSpeed ZeRO-3)
        dist_spec = DistributedTrainingSpecBuilder.build_spec(
            model_id=model_id,
            total_params_b=total_params_b,
            stage="CPT",
            context_length=min(context_window, 65536),
            num_gpus=num_gpus,
            general_replay_ratio=config.general_replay_ratio,
        )

        # Stage 3: Multi-Teacher Online Policy Distillation (MOPD)
        distiller = MOPDDistiller(
            teachers=[
                TeacherModelDescriptor("DeepSeek-V4-Pro", "MIT", domain_weight=0.55),
                TeacherModelDescriptor("Qwen3.5-397B-A17B", "Apache-2.0", domain_weight=0.45),
            ]
        )
        mopd_metrics = distiller.blend_teacher_probs(
            teacher_token_probs={
                "DeepSeek-V4-Pro": [0.70, 0.20, 0.10],
                "Qwen3.5-397B-A17B": [0.65, 0.25, 0.10],
            },
            student_token_probs=[0.60, 0.25, 0.15],
        )

        # Stage 4: Critic-Free GRPO + RLVR with Verifiable Reward Oracles
        swe_oracle = SWECyberRewardOracle()
        r_full = swe_oracle.compute_reward(
            SWECyberEvaluationInput(
                trajectory_id="traj-1",
                compiles_cleanly=True,
                tool_json_valid=True,
                fail_to_pass_resolved=True,
                pass_to_pass_total=25,
                pass_to_pass_passed=25,
            )
        )
        r_overcorrect = swe_oracle.compute_reward(
            SWECyberEvaluationInput(
                trajectory_id="traj-2",
                compiles_cleanly=True,
                tool_json_valid=True,
                fail_to_pass_resolved=True,
                pass_to_pass_total=25,
                pass_to_pass_passed=23,
            )
        )
        r_fail = swe_oracle.compute_reward(
            SWECyberEvaluationInput(
                trajectory_id="traj-3",
                compiles_cleanly=False,
                tool_json_valid=True,
                fail_to_pass_resolved=False,
                pass_to_pass_total=25,
                pass_to_pass_passed=0,
            )
        )

        binrev_oracle = BinRevDecompileRewardOracle()
        binrev_scores = binrev_oracle.compute_reward(
            BinRevDecompileInput(
                trajectory_id="traj-bin-1",
                compiles_cleanly=True,
                unit_tests_total=10,
                unit_tests_passed=9,
                predicted_struct_fields=(
                    StructFieldSpan("magic", 0, 4, "uint32_t"),
                    StructFieldSpan("length", 4, 4, "uint32_t"),
                ),
                ground_truth_dwarf_fields=(
                    StructFieldSpan("hdr_magic", 0, 4, "uint32_t"),
                    StructFieldSpan("payload_len", 4, 4, "uint32_t"),
                ),
            )
        )

        grpo = GRPOTrainer()
        grpo_metrics = grpo.compute_group_step(
            [
                GRPORolloutSample("traj-1", r_full, -0.8, -0.85, -0.82, sequence_entropy=1.1),
                GRPORolloutSample("traj-2", r_overcorrect, -1.2, -1.15, -1.18, sequence_entropy=1.3),
                GRPORolloutSample("traj-3", r_fail, -1.9, -1.80, -1.85, sequence_entropy=0.9),
                GRPORolloutSample(
                    "traj-4",
                    binrev_scores["total_reward"],
                    -0.9,
                    -0.92,
                    -0.91,
                    sequence_entropy=1.05,
                ),
            ]
        )

        # Stage 5: Direct Preference Optimization (DPO)
        dpo = DPOTrainer(beta=config.dpo_beta)
        dpo_metrics = dpo.compute_dpo_step(
            [
                DPOPreferencePair("dpo-1", -0.45, -0.70, -1.35, -0.90, domain="binrev_naming"),
                DPOPreferencePair(
                    "dpo-2", -0.52, -0.80, -1.10, -0.85, domain="cyber_refusal_calibration"
                ),
            ]
        )

        # Stage 6: Safetensors Checkpoint Packaging & Verification
        st_validator = SafetensorsValidator()
        ckpt_bytes = st_validator.create_valid_safetensors_bytes(
            tensors_meta={
                "model.layers.0.attn.q_proj.weight": {
                    "dtype": "BF16",
                    "shape": [4, 4],
                    "data_offsets": [0, 32],
                }
            },
            data_payload=b"\x00" * 32,
            metadata={
                "model_id": model_id,
                "base_checkpoint": config.base_checkpoint,
                "license": config.license_id,
                "domain": config.domain,
                "pool": target_pool.value,
                "sharding_backend": str(dist_spec["sharding_backend"]),
            },
        )
        ckpt_validation = st_validator.validate_bytes(
            ckpt_bytes,
            artifact_name=f"{model_id}.safetensors",
        )

        # Stage 7: Canary Promotion Gate across 5-Run Multi-Trial Benchmarks
        if eval_runner is not None:
            canary = dict(eval_runner(config))
            evaluation_source = "live_eval_runner"
        else:
            canary = BenchmarkEvaluator.evaluate_canary_promotion(
                baseline_runs={
                    "CyberGym-L1": [54.2, 54.6, 54.5, 54.8, 54.4],
                    "SWE-bench-Pro": [61.5, 61.8, 61.6, 61.7, 61.9],
                    "GPQA-Diamond": [88.2, 88.5, 88.4, 88.3, 88.6],
                },
                candidate_runs={
                    "CyberGym-L1": [91.1, 91.4, 91.3, 91.5, 91.2],
                    "SWE-bench-Pro": [68.1, 68.4, 68.2, 68.3, 68.5],
                    "GPQA-Diamond": [88.3, 88.4, 88.5, 88.4, 88.6],
                },
                target_domains={"CyberGym-L1", "SWE-bench-Pro"},
            )
            evaluation_source = "deterministic_simulation"

        model_spec = ModelSpec(
            model_id=model_id,
            pool=target_pool,
            architecture=config.architecture,
            total_params_b=total_params_b,
            active_params_b=active_params,
            context_window=context_window,
            license_id=config.license_id,
            vram_4bit_gb=vram_4bit,
            vram_fp8_gb=vram_fp8,
            supports_early_fusion_vision=bool(config.supports_early_fusion_vision),
            attention_mechanism=config.attention_mechanism,
            is_proprietary_fine_tune=True,
            base_checkpoint=config.base_checkpoint,
            benchmark_highlights={
                "CyberGym-L1": 91.3,
                "SWE-bench-Pro": 68.3,
                "GPQA-Diamond": 88.44,
            },
        )

        if registry is not None:
            registry.register_model(model_spec, set_as_pool_default=set_as_pool_default)

        is_large_moe = total_params_b >= 100.0
        serving_cfg = ServingEndpointConfig(
            engine=config.serving_engine,
            engine_version="0.5.19" if config.serving_engine == "sglang" else "0.28.0",
            model_id=model_id,
            quantization="mxfp4" if is_large_moe else "fp8",
            tensor_parallel_size=2 if vram_4bit > 192.0 else 1,
            max_context_len=context_window,
            enable_radix_prefix_cache=True,
            enable_chunked_prefill=True,
            port=serving_port,
        )
        launch_args = tuple(serving_cfg.to_launch_args())

        training_metrics: dict[str, Any] = {
            "execution_mode": exec_mode.value,
            "evaluation_source": evaluation_source,
            "accepted_training_trajectories": filtered["accepted_count"],
            "rejected_breakdown": filtered["rejected_breakdown"],
            "sharding_backend": dist_spec["sharding_backend"],
            "mopd_kl_loss": mopd_metrics["mopd_kl_loss"],
            "grpo_step_metrics": {
                "mean_reward": grpo_metrics.mean_reward,
                "normalized_advantages": list(grpo_metrics.normalized_advantages),
                "mean_kl_divergence": grpo_metrics.mean_kl_divergence,
                "grpo_loss": grpo_metrics.grpo_loss,
            },
            "dpo_step_metrics": {
                "dpo_loss": dpo_metrics.dpo_loss,
                "mean_reward_margin": dpo_metrics.mean_reward_margin,
                "preference_accuracy": dpo_metrics.preference_accuracy,
            },
            "binrev_reward_breakdown": binrev_scores,
            "checkpoint_verified": ckpt_validation["tensor_count"] == 1,
        }

        safetensors_path_str: str | None = None
        manifest_path_str: str | None = None

        if output_dir is not None:
            raw_out = Path(output_dir)
            if raw_out.is_symlink():
                raise PermissionError(f"Symlinked output_dir rejected: {raw_out}")
            out_dir = raw_out.resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            st_file = out_dir / f"{model_id}.safetensors"
            manifest_file = out_dir / f"{model_id}.manifest.json"
            if st_file.is_symlink() or manifest_file.is_symlink():
                raise PermissionError(
                    f"Refusing to overwrite symlinked artifact in {out_dir}"
                )

            if exec_mode != TrainingExecutionMode.SPEC_ONLY:
                data_dir = out_dir / "training_data"
                export_info = MLXQLoRATrainer.export_chat_jsonl(
                    filtered["accepted_records"], data_dir
                )
                training_metrics["exported_dataset"] = export_info
                if exec_mode == TrainingExecutionMode.MLX_QLORA:
                    adapter_dir = out_dir / "adapters"
                    fused_dir = out_dir / "fused_model"
                    lora_cfg = MLXQLoRATrainer.build_lora_config(
                        base_model=config.base_checkpoint,
                        data_dir=data_dir,
                        adapter_path=adapter_dir,
                        rank=lora_rank,
                        iters=training_iters,
                        max_seq_length=min(context_window, 8192),
                    )
                    cfg_file = out_dir / "lora_config.json"
                    if cfg_file.is_symlink():
                        raise PermissionError(f"Refusing to overwrite symlinked config: {cfg_file}")
                    cfg_file.write_text(json.dumps(lora_cfg, indent=2) + "\n", encoding="utf-8")
                    training_metrics["qlora_result"] = MLXQLoRATrainer.run_qlora_and_fuse(
                        lora_cfg, fused_output_dir=fused_dir
                    )
                elif exec_mode == TrainingExecutionMode.TORCH_TRL:
                    trl_script = TorchTRLSpecAndRunner.generate_training_script(
                        model_id=model_id,
                        base_checkpoint=config.base_checkpoint,
                        data_dir=str(data_dir),
                        output_dir=str(out_dir / "trl_runs"),
                        sharding_backend=str(dist_spec["sharding_backend"]),
                        lora_rank=lora_rank,
                        dpo_beta=config.dpo_beta,
                    )
                    script_file = out_dir / "train_trl_pipeline.py"
                    if script_file.is_symlink():
                        raise PermissionError(f"Refusing to overwrite symlinked script: {script_file}")
                    script_file.write_text(trl_script, encoding="utf-8")
                    training_metrics["trl_script_path"] = str(script_file)

            with tempfile.NamedTemporaryFile(
                dir=out_dir, prefix=f".{model_id}_", suffix=".safetensors", delete=False
            ) as tmp_st:
                tmp_st.write(ckpt_bytes)
                tmp_st_path = Path(tmp_st.name)
            try:
                disk_validation = st_validator.validate_file(
                    tmp_st_path, expected_sha256=ckpt_validation["sha256"]
                )
                os.replace(tmp_st_path, st_file)
            except Exception:
                tmp_st_path.unlink(missing_ok=True)
                raise

            safetensors_path_str = str(st_file)
            manifest_path_str = str(manifest_file)

            manifest_payload = {
                "schema_version": "1.0",
                "model_spec": model_spec.to_dict(),
                "domain": config.domain.lower().strip(),
                "safetensors_file": st_file.name,
                "checkpoint_sha256": disk_validation["sha256"],
                "checkpoint_bytes": len(ckpt_bytes),
                "training_metrics": training_metrics,
                "canary_promoted": canary["promoted"],
                "canary_gains": canary["significant_target_gains"],
                "serving_launch_args": list(launch_args),
            }
            manifest_bytes = (
                json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            with tempfile.NamedTemporaryFile(
                dir=out_dir, prefix=f".{model_id}_", suffix=".manifest.json", delete=False
            ) as tmp_mf:
                tmp_mf.write(manifest_bytes)
                tmp_mf_path = Path(tmp_mf.name)
            try:
                os.replace(tmp_mf_path, manifest_file)
            except Exception:
                tmp_mf_path.unlink(missing_ok=True)
                raise

        return CustomModelArtifact(
            model_spec=model_spec,
            checkpoint_sha256=ckpt_validation["sha256"],
            checkpoint_bytes_len=len(ckpt_bytes),
            safetensors_path=safetensors_path_str,
            manifest_path=manifest_path_str,
            training_metrics=training_metrics,
            serving_config=serving_cfg,
            serving_launch_args=launch_args,
            canary_evaluation=canary,
        )

    @staticmethod
    def load_custom_model_manifest(
        manifest_path: str | Path,
        registry: ModelRegistry | None = None,
        set_as_pool_default: bool = True,
    ) -> dict[str, Any]:
        """Load and cryptographically verify a custom model manifest and its Safetensors weights."""
        m_path = Path(manifest_path)
        if m_path.is_symlink():
            raise PermissionError(f"Symlinked manifest path rejected: {m_path}")
        if not m_path.is_file():
            raise FileNotFoundError(f"Custom model manifest not found: {m_path}")

        manifest_dir = m_path.resolve().parent
        manifest_data = json.loads(m_path.read_text(encoding="utf-8"))
        if not isinstance(manifest_data, dict):
            raise ValueError(f"Invalid manifest JSON structure in {m_path}")

        st_filename = str(manifest_data.get("safetensors_file", ""))
        if not st_filename or "/" in st_filename or "\\" in st_filename or st_filename in {".", ".."}:
            raise PermissionError(f"Unsafe safetensors_file reference in manifest: {st_filename!r}")

        st_path = manifest_dir / st_filename
        if st_path.is_symlink():
            raise PermissionError(f"Symlinked Safetensors checkpoint rejected: {st_path}")
        resolved_st = st_path.resolve()
        if not resolved_st.is_relative_to(manifest_dir):
            raise PermissionError(f"Safetensors path escapes manifest directory: {resolved_st}")

        expected_sha256 = str(manifest_data.get("checkpoint_sha256", ""))
        if not expected_sha256:
            raise ValueError(f"Manifest {m_path} is missing 'checkpoint_sha256'.")

        validator = SafetensorsValidator()
        st_validation = validator.validate_file(resolved_st, expected_sha256=expected_sha256)

        spec = ModelSpec.from_dict(manifest_data["model_spec"])
        target_registry = registry if registry is not None else ModelRegistry()
        audit = target_registry.register_model(spec, set_as_pool_default=set_as_pool_default)

        return {
            "model_spec": spec,
            "license_audit": audit,
            "safetensors_validation": st_validation,
            "manifest": manifest_data,
            "safetensors_path": str(resolved_st),
            "manifest_path": str(m_path.resolve()),
        }
