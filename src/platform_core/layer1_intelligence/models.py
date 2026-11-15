"""Layer 1: Intelligence Layer — 4-Pool Model Lineup, Hardware Planning, and Thinking Modes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
import os
import platform
import subprocess
from typing import Any

from platform_core.deploy_security.governance import (
    LicenseAuditResult,
    LicenseComplianceAuditor,
    LicenseVerdict,
)


def _validate_positive_int(val: Any, field_name: str) -> int:
    if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
        raise ValueError(f"Invalid {field_name}: {val!r} (must be a positive int, not bool).")
    return val


def _validate_positive_float(val: Any, field_name: str) -> float:
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        raise ValueError(f"Invalid {field_name}: {val!r} (must be a positive finite number, not bool).")
    fval = float(val)
    if not math.isfinite(fval) or fval <= 0.0:
        raise ValueError(f"Invalid {field_name}: {val!r} (must be a positive finite number).")
    return fval


class ModelPool(str, Enum):
    """Four-Pool Specialized Model Lineup (Section 3.1)."""

    POOL_1_ORCHESTRATOR = "POOL_1_ORCHESTRATOR"
    POOL_2_SWE_CYBER = "POOL_2_SWE_CYBER"
    POOL_3_BINREV = "POOL_3_BINREV"
    POOL_4_VISUAL_OCR = "POOL_4_VISUAL_OCR"


class ThinkingMode(str, Enum):
    """Switchable Thinking Modes for Entropy-Aware Adaptive Test-Time Scaling (Section 1.7)."""

    NON_THINK = "NON_THINK"
    THINK_HIGH = "THINK_HIGH"
    THINK_MAX = "THINK_MAX"


class HardwareProfile(str, Enum):
    """Deployment hardware profile governing default model lineup selection."""

    CLUSTER_DEFAULT = "CLUSTER_DEFAULT"
    LOCAL_APPLE_SILICON_36GB = "LOCAL_APPLE_SILICON_36GB"
    WORKSTATION_GPU = "WORKSTATION_GPU"


@dataclass(frozen=True)
class LocalHardwareInfo:
    """Detected host CPU/GPU/Unified Memory capabilities and safe inference budget."""

    os_name: str
    arch: str
    cpu_brand: str
    total_memory_gb: float
    safe_model_budget_gb: float
    accelerator: str  # "apple_silicon_metal", "cuda", "cpu_only"
    recommended_profile: HardwareProfile

    def fits_4bit(self, spec: ModelSpec) -> bool:
        """Return True if a model's 4-bit footprint fits within safe model memory budget."""
        return spec.vram_4bit_gb <= self.safe_model_budget_gb


class LocalHardwareDetector:
    """Inspects local hardware to recommend optimal open-weight models and quantization."""

    @staticmethod
    def detect() -> LocalHardwareInfo:
        os_name = platform.system()
        arch = platform.machine()
        cpu_brand = platform.processor() or arch
        total_mem_gb = 16.0
        accelerator = "cpu_only"

        if os_name == "Darwin" and arch == "arm64":
            accelerator = "apple_silicon_metal"
            try:
                mem_out = subprocess.check_output(
                    ["sysctl", "-n", "hw.memsize"], text=True, timeout=2.0
                ).strip()
                total_mem_gb = round(int(mem_out) / (1024**3), 2)
            except Exception:
                pass
            try:
                brand_out = subprocess.check_output(
                    ["sysctl", "-n", "machdep.cpu.brand_string"], text=True, timeout=2.0
                ).strip()
                if brand_out:
                    cpu_brand = brand_out
            except Exception:
                pass
            # Reserve ~22% of unified memory for macOS + KV cache headroom
            safe_budget_gb = round(max(4.0, total_mem_gb * 0.78), 2)
        else:
            # Linux / other POSIX: check /proc/meminfo & optional nvidia-smi
            if os.path.exists("/proc/meminfo"):
                try:
                    with open("/proc/meminfo", encoding="utf-8") as fh:
                        for line in fh:
                            if line.startswith("MemTotal:"):
                                kb = int(line.split()[1])
                                total_mem_gb = round(kb / (1024**2), 2)
                                break
                except Exception:
                    pass
            safe_budget_gb = round(max(4.0, total_mem_gb * 0.65), 2)
            try:
                vram_out = subprocess.check_output(
                    ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=2.0,
                ).strip()
                if vram_out:
                    gpus_gb = [int(x.strip()) / 1024.0 for x in vram_out.splitlines() if x.strip()]
                    total_vram = sum(gpus_gb)
                    if total_vram > 0:
                        accelerator = "cuda"
                        total_mem_gb = round(total_vram, 2)
                        safe_budget_gb = round(total_vram * 0.88, 2)
            except Exception:
                pass

        if safe_budget_gb >= 180.0:
            rec_profile = HardwareProfile.CLUSTER_DEFAULT
        elif accelerator == "cuda" and safe_budget_gb >= 24.0:
            rec_profile = HardwareProfile.WORKSTATION_GPU
        else:
            rec_profile = HardwareProfile.LOCAL_APPLE_SILICON_36GB

        return LocalHardwareInfo(
            os_name=os_name,
            arch=arch,
            cpu_brand=cpu_brand,
            total_memory_gb=total_mem_gb,
            safe_model_budget_gb=safe_budget_gb,
            accelerator=accelerator,
            recommended_profile=rec_profile,
        )


@dataclass(frozen=True)
class ModelSpec:
    """Specification of a model checkpoint in Layer 1."""

    model_id: str
    pool: ModelPool
    architecture: str
    total_params_b: float
    active_params_b: float
    context_window: int
    license_id: str
    vram_4bit_gb: float
    vram_fp8_gb: float
    supports_early_fusion_vision: bool
    attention_mechanism: str
    is_proprietary_fine_tune: bool = False
    base_checkpoint: str | None = None
    benchmark_highlights: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize ModelSpec to a JSON-compatible dictionary."""
        return {
            "model_id": self.model_id,
            "pool": self.pool.value,
            "architecture": self.architecture,
            "total_params_b": self.total_params_b,
            "active_params_b": self.active_params_b,
            "context_window": self.context_window,
            "license_id": self.license_id,
            "vram_4bit_gb": self.vram_4bit_gb,
            "vram_fp8_gb": self.vram_fp8_gb,
            "supports_early_fusion_vision": self.supports_early_fusion_vision,
            "attention_mechanism": self.attention_mechanism,
            "is_proprietary_fine_tune": self.is_proprietary_fine_tune,
            "base_checkpoint": self.base_checkpoint,
            "benchmark_highlights": dict(self.benchmark_highlights),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModelSpec:
        """Deserialize a ModelSpec from a dictionary with strict type validation."""
        context_window = _validate_positive_int(data.get("context_window"), "context_window")
        total_params_b = _validate_positive_float(data.get("total_params_b"), "total_params_b")
        active_params_b = _validate_positive_float(data.get("active_params_b"), "active_params_b")
        vram_4bit_gb = _validate_positive_float(data.get("vram_4bit_gb"), "vram_4bit_gb")
        vram_fp8_gb = _validate_positive_float(data.get("vram_fp8_gb"), "vram_fp8_gb")
        vision_flag = data.get("supports_early_fusion_vision")
        if not isinstance(vision_flag, bool):
            raise ValueError(f"Invalid supports_early_fusion_vision: {vision_flag!r}")
        fine_tune_flag = data.get("is_proprietary_fine_tune", False)
        if not isinstance(fine_tune_flag, bool):
            raise ValueError(f"Invalid is_proprietary_fine_tune: {fine_tune_flag!r}")
        return cls(
            model_id=str(data["model_id"]),
            pool=ModelPool(data["pool"]),
            architecture=str(data["architecture"]),
            total_params_b=total_params_b,
            active_params_b=active_params_b,
            context_window=context_window,
            license_id=str(data["license_id"]),
            vram_4bit_gb=vram_4bit_gb,
            vram_fp8_gb=vram_fp8_gb,
            supports_early_fusion_vision=vision_flag,
            attention_mechanism=str(data["attention_mechanism"]),
            is_proprietary_fine_tune=fine_tune_flag,
            base_checkpoint=data.get("base_checkpoint"),
            benchmark_highlights={
                str(k): _validate_positive_float(v, f"benchmark_highlights[{k!r}]")
                for k, v in (data.get("benchmark_highlights") or {}).items()
            },
        )


@dataclass(frozen=True)
class ScenarioBudgetProfile:
    """Financial & hardware feasibility profile across Scenarios A, B, and C (Section 6.4)."""

    scenario_id: str
    name: str
    annual_budget_min_usd: int
    annual_budget_max_usd: int
    team_size_min: int
    team_size_max: int
    timeline_months: int
    hardware_summary: str
    model_strategy: str
    break_even_months_vs_cloud: int = 21


class ModelRegistry:
    """Registry of approved open-weight and post-trained specialist models in Layer 1."""

    def __init__(self, profile: HardwareProfile | str = HardwareProfile.CLUSTER_DEFAULT) -> None:
        self._auditor = LicenseComplianceAuditor()
        self._models: dict[str, ModelSpec] = {}
        self._pool_overrides: dict[ModelPool, str] = {}
        self.profile = profile if isinstance(profile, HardwareProfile) else HardwareProfile(profile)
        self._register_profile_lineup(self.profile)

    @classmethod
    def for_profile(cls, profile: HardwareProfile | str) -> ModelRegistry:
        """Construct a ModelRegistry initialized for a specific hardware deployment profile."""
        return cls(profile=profile)

    def _register_profile_lineup(self, profile: HardwareProfile) -> None:
        if profile == HardwareProfile.LOCAL_APPLE_SILICON_36GB:
            self._register_local_apple_silicon_lineup()
        elif profile == HardwareProfile.WORKSTATION_GPU:
            self._register_workstation_gpu_lineup()
        else:
            self._register_default_lineup()

    def _register_local_apple_silicon_lineup(self) -> None:
        """Register verified 2026 open-weight models sized for 36 GB Apple Silicon (M3 Pro)."""
        local_models = [
            ModelSpec(
                model_id="Qwen/Qwen3.5-35B-A3B",
                pool=ModelPool.POOL_1_ORCHESTRATOR,
                architecture="Sparse MoE Native VLM + Gated DeltaNet 3:1 (35B total / 3B active)",
                total_params_b=35.0,
                active_params_b=3.0,
                context_window=262_144,
                license_id="Apache-2.0",
                vram_4bit_gb=19.5,
                vram_fp8_gb=36.0,
                supports_early_fusion_vision=True,
                attention_mechanism="Gated DeltaNet 3:1 + Sparse MoE (3B active)",
                benchmark_highlights={"Local-M3Pro-TokPerSec": 42.0, "OmniDocBench-v1.5": 87.5},
            ),
            ModelSpec(
                model_id="Qwen/Qwen3-Coder-30B-A3B-Instruct",
                pool=ModelPool.POOL_2_SWE_CYBER,
                architecture="Sparse MoE Coding Model (30.5B total / 3.3B active)",
                total_params_b=30.5,
                active_params_b=3.3,
                context_window=262_144,
                license_id="Apache-2.0",
                vram_4bit_gb=17.5,
                vram_fp8_gb=31.0,
                supports_early_fusion_vision=False,
                attention_mechanism="GQA + Sparse MoE (3.3B active)",
                benchmark_highlights={"SWE-bench-Verified": 69.6, "Local-M3Pro-TokPerSec": 48.0},
            ),
            ModelSpec(
                model_id="fdtn-ai/Foundation-Sec-8B-Reasoning",
                pool=ModelPool.POOL_2_SWE_CYBER,
                architecture="Dense Cybersecurity Reasoning Specialist (8B)",
                total_params_b=8.0,
                active_params_b=8.0,
                context_window=131_072,
                license_id="Apache-2.0",
                vram_4bit_gb=4.8,
                vram_fp8_gb=8.5,
                supports_early_fusion_vision=False,
                attention_mechanism="GQA Dense (QLoRA fine-tunable on 36GB Mac)",
                benchmark_highlights={"CTIBench-ATE": 84.0, "QLoRA-36GB-Capable": 1.0},
            ),
            ModelSpec(
                model_id="Qwen/Qwen3.8-27B",
                pool=ModelPool.POOL_3_BINREV,
                architecture="Dense Native VLM with 3:1 Gated DeltaNet Linear Attention",
                total_params_b=27.8,
                active_params_b=27.8,
                context_window=262_144,
                license_id="Apache-2.0",
                vram_4bit_gb=17.5,
                vram_fp8_gb=28.0,
                supports_early_fusion_vision=True,
                attention_mechanism="Gated DeltaNet 3:1 Dense",
                benchmark_highlights={"SWE-bench-Pro": 65.0, "Local-M3Pro-TokPerSec": 21.0},
            ),
            ModelSpec(
                model_id="Qwen/Qwen3-VL-8B-Thinking",
                pool=ModelPool.POOL_4_VISUAL_OCR,
                architecture="Dense Vision-Language Reasoning & Document OCR (8.2B)",
                total_params_b=8.2,
                active_params_b=8.2,
                context_window=262_144,
                license_id="Apache-2.0",
                vram_4bit_gb=5.5,
                vram_fp8_gb=9.0,
                supports_early_fusion_vision=True,
                attention_mechanism="DeepStack ViT + MRoPE",
                benchmark_highlights={"DocVQA": 92.0, "Local-M3Pro-TokPerSec": 58.0},
            ),
        ]
        for spec in local_models:
            self.register_model(spec)

    def _register_workstation_gpu_lineup(self) -> None:
        """Register 2026 models tailored for single/dual 24GB-96GB workstation GPUs."""
        ws_models = [
            ModelSpec(
                model_id="zai-org/GLM-4.7-Flash",
                pool=ModelPool.POOL_1_ORCHESTRATOR,
                architecture="Sparse MoE Agentic & Terminal Model (30B total / 3B active)",
                total_params_b=30.0,
                active_params_b=3.0,
                context_window=131_072,
                license_id="MIT",
                vram_4bit_gb=18.0,
                vram_fp8_gb=31.0,
                supports_early_fusion_vision=False,
                attention_mechanism="MLA + Sparse MoE (3B active)",
            ),
            ModelSpec(
                model_id="mistralai/Devstral-Small-24B",
                pool=ModelPool.POOL_2_SWE_CYBER,
                architecture="Dense Agentic Software Engineering Model (24B)",
                total_params_b=24.0,
                active_params_b=24.0,
                context_window=131_072,
                license_id="Apache-2.0",
                vram_4bit_gb=14.5,
                vram_fp8_gb=25.0,
                supports_early_fusion_vision=False,
                attention_mechanism="GQA Dense",
            ),
            ModelSpec(
                model_id="fdtn-ai/Foundation-Sec-8B-Reasoning",
                pool=ModelPool.POOL_2_SWE_CYBER,
                architecture="Dense Cybersecurity Reasoning Specialist (8B)",
                total_params_b=8.0,
                active_params_b=8.0,
                context_window=131_072,
                license_id="Apache-2.0",
                vram_4bit_gb=4.8,
                vram_fp8_gb=8.5,
                supports_early_fusion_vision=False,
                attention_mechanism="GQA Dense",
            ),
            ModelSpec(
                model_id="Qwen/Qwen3.8-27B",
                pool=ModelPool.POOL_3_BINREV,
                architecture="Dense Native VLM with 3:1 Gated DeltaNet Linear Attention",
                total_params_b=27.8,
                active_params_b=27.8,
                context_window=262_144,
                license_id="Apache-2.0",
                vram_4bit_gb=17.5,
                vram_fp8_gb=28.0,
                supports_early_fusion_vision=True,
                attention_mechanism="Gated DeltaNet 3:1 Dense",
            ),
            ModelSpec(
                model_id="Qwen/Qwen3-VL-8B-Thinking",
                pool=ModelPool.POOL_4_VISUAL_OCR,
                architecture="Dense Vision-Language Reasoning & Document OCR (8.2B)",
                total_params_b=8.2,
                active_params_b=8.2,
                context_window=262_144,
                license_id="Apache-2.0",
                vram_4bit_gb=5.5,
                vram_fp8_gb=9.0,
                supports_early_fusion_vision=True,
                attention_mechanism="DeepStack ViT + MRoPE",
            ),
        ]
        for spec in ws_models:
            self.register_model(spec)

    def _register_default_lineup(self) -> None:
        defaults = [
            ModelSpec(
                model_id="DeepSeek-V4-Flash",
                pool=ModelPool.POOL_1_ORCHESTRATOR,
                architecture="MoE with CSA + HCA Hybrid Sparse Attention",
                total_params_b=284.0,
                active_params_b=13.0,
                context_window=1_000_000,
                license_id="MIT",
                vram_4bit_gb=192.0,
                vram_fp8_gb=310.0,
                supports_early_fusion_vision=False,
                attention_mechanism="CSA+HCA (7% KV cache, 10% FLOPs at 1M context)",
                benchmark_highlights={"SWE-bench-Verified": 88.8, "SimpleQA-Verified-Delta": 20.0},
            ),
            ModelSpec(
                model_id="Qwen3.5-397B-A17B",
                pool=ModelPool.POOL_1_ORCHESTRATOR,
                architecture="Native VLM Hybrid Linear Attention (Gated DeltaNet 3:1) + MoE",
                total_params_b=397.0,
                active_params_b=17.0,
                context_window=1_000_000,
                license_id="Apache-2.0",
                vram_4bit_gb=200.0,
                vram_fp8_gb=400.0,
                supports_early_fusion_vision=True,
                attention_mechanism="Gated DeltaNet 3:1 + Gated Attention",
                benchmark_highlights={
                    "OmniDocBench-v1.5": 90.8,
                    "GPQA-Diamond": 88.4,
                    "tau-bench-telecom": 97.8,
                },
            ),
            ModelSpec(
                model_id="Qwen3.8-27B-SWE-Cyber",
                pool=ModelPool.POOL_2_SWE_CYBER,
                architecture="Dense Native VLM with 3:1 Gated DeltaNet Linear Attention",
                total_params_b=27.8,
                active_params_b=27.8,
                context_window=262_144,
                license_id="Apache-2.0",
                vram_4bit_gb=16.0,
                vram_fp8_gb=28.0,
                supports_early_fusion_vision=True,
                attention_mechanism="Gated DeltaNet 3:1 Dense",
                is_proprietary_fine_tune=True,
                base_checkpoint="Qwen/Qwen3.8-27B",
                benchmark_highlights={
                    "CyberGym-L1": 91.31,
                    "SWE-bench-Pro": 68.2,
                    "OSWorld-Verified": 84.3,
                },
            ),
            ModelSpec(
                model_id="Qwen3.8-27B-BinRev",
                pool=ModelPool.POOL_3_BINREV,
                architecture="Dense Native VLM with 3:1 Gated DeltaNet (SK2Decompile + ReCopilot)",
                total_params_b=27.8,
                active_params_b=27.8,
                context_window=262_144,
                license_id="Apache-2.0",
                vram_4bit_gb=16.0,
                vram_fp8_gb=28.0,
                supports_early_fusion_vision=True,
                attention_mechanism="Gated DeltaNet 3:1 Dense",
                is_proprietary_fine_tune=True,
                base_checkpoint="Qwen/Qwen3.8-27B",
                benchmark_highlights={
                    "HumanEval-Decompile-R_exec": 72.4,
                    "Decompile-Bench-Struct-IoU": 78.5,
                },
            ),
            ModelSpec(
                model_id="OmniParser-V2-UI-TARS-GOT-OCR",
                pool=ModelPool.POOL_4_VISUAL_OCR,
                architecture="YOLOv9-E Region Detector + UI-TARS-1.5-7B + GOT-OCR-2.0",
                total_params_b=7.5,
                active_params_b=7.5,
                context_window=32_768,
                license_id="Apache-2.0",
                vram_4bit_gb=6.0,
                vram_fp8_gb=10.5,
                supports_early_fusion_vision=True,
                attention_mechanism="ViT + Localized Bounding-Box Grounding",
                benchmark_highlights={"ScreenSpot-Pro": 61.2, "Latency-ms": 85.0},
            ),
        ]
        for spec in defaults:
            self.register_model(spec)

    def register_model(
        self,
        spec: ModelSpec,
        set_as_pool_default: bool = False,
    ) -> LicenseAuditResult:
        """Audit license compliance and register a model checkpoint into Layer 1."""
        if not spec.model_id.strip():
            raise ValueError("ModelSpec.model_id must not be empty.")
        _validate_positive_float(spec.total_params_b, "ModelSpec.total_params_b")
        _validate_positive_float(spec.active_params_b, "ModelSpec.active_params_b")
        _validate_positive_float(spec.vram_4bit_gb, "ModelSpec.vram_4bit_gb")
        _validate_positive_float(spec.vram_fp8_gb, "ModelSpec.vram_fp8_gb")
        _validate_positive_int(spec.context_window, "ModelSpec.context_window")
        audit = self._auditor.audit(spec.model_id, spec.license_id)
        if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
            raise PermissionError(
                f"Cannot register model '{spec.model_id}' with license '{spec.license_id}': {audit.rationale}"
            )
        self._models[spec.model_id] = spec
        if set_as_pool_default:
            self._pool_overrides[spec.pool] = spec.model_id
        return audit

    def get_pool_override(self, pool: ModelPool) -> ModelSpec | None:
        """Return the custom default model registered for `pool`, if any."""
        override_id = self._pool_overrides.get(pool)
        if override_id is not None and override_id in self._models:
            return self._models[override_id]
        return None

    def get_model(self, model_id: str) -> ModelSpec:
        if model_id not in self._models:
            raise KeyError(f"Model '{model_id}' not found in Layer 1 registry.")
        return self._models[model_id]

    def list_by_pool(self, pool: ModelPool) -> list[ModelSpec]:
        return [m for m in self._models.values() if m.pool == pool]

    def all_models(self) -> list[ModelSpec]:
        return list(self._models.values())


class HardwareFeasibilityPlanner:
    """Evaluates hardware footprints, break-even economics, and Scenario A/B/C plans (Section 6)."""

    SCENARIOS: dict[str, ScenarioBudgetProfile] = {
        "Scenario-A": ScenarioBudgetProfile(
            scenario_id="Scenario-A",
            name="Lean Development (Minimum Viable Architecture)",
            annual_budget_min_usd=120_000,
            annual_budget_max_usd=250_000,
            team_size_min=2,
            team_size_max=3,
            timeline_months=3,
            hardware_summary=(
                "1x Dual-RTX PRO 6000 Blackwell workstation (192GB GDDR7, $35K CapEx) + "
                "1x Bare-metal KVM server + on-demand MI355X ($5.99/hr)"
            ),
            model_strategy="Self-host Qwen3.8-27B + DeepSeek-V4-Flash with Unsloth LoRA/QLoRA adapters.",
        ),
        "Scenario-B": ScenarioBudgetProfile(
            scenario_id="Scenario-B",
            name="Advanced Proprietary AI Platform (Recommended Target)",
            annual_budget_min_usd=1_200_000,
            annual_budget_max_usd=2_800_000,
            team_size_min=6,
            team_size_max=10,
            timeline_months=6,
            hardware_summary=(
                "On-prem enclave (4x RTX PRO 6000 Blackwell + 2x Dual-EPYC KVM servers, ~$75K CapEx) + "
                "Reserved 8-GPU AMD MI355X (288GB HBM3e/GPU) or H200 pod (~$25K/mo) + burst 32-GPU training"
            ),
            model_strategy=(
                "Full 5-stage specialization (CPT -> SFT -> MOPD -> GRPO/RLVR -> DPO) producing "
                "full-weight Qwen3.8-27B-SWE-Cyber and Qwen3.8-27B-BinRev checkpoints."
            ),
        ),
        "Scenario-C": ScenarioBudgetProfile(
            scenario_id="Scenario-C",
            name="Research Laboratory (Frontier Scale)",
            annual_budget_min_usd=12_000_000,
            annual_budget_max_usd=35_000_000,
            team_size_min=20,
            team_size_max=35,
            timeline_months=15,
            hardware_summary="64-256x NVIDIA B200/GB300 NVL72 or AMD MI355X cluster + 16-node KVM farm.",
            model_strategy="500B-2T token CPT on DeepSeek-V4-Pro (1.6T) + 100,000-environment async RLVR.",
        ),
    }

    @staticmethod
    def calculate_gpu_break_even_months(
        hardware_capex_usd: float,
        monthly_power_hosting_usd: float,
        cloud_hourly_rate_usd: float,
        utilization_ratio: float = 0.85,
    ) -> float:
        """Compute break-even months between owning GPU hardware vs renting cloud capacity."""
        if hardware_capex_usd <= 0:
            raise ValueError("hardware_capex_usd must be positive.")
        if not (0.0 < utilization_ratio <= 1.0):
            raise ValueError("utilization_ratio must be in (0.0, 1.0].")
        monthly_cloud_cost = cloud_hourly_rate_usd * 730.0 * utilization_ratio
        net_monthly_savings = monthly_cloud_cost - monthly_power_hosting_usd
        if net_monthly_savings <= 0:
            return float("inf")
        return round(hardware_capex_usd / net_monthly_savings, 2)

    @classmethod
    def recommend_scenario(
        cls,
        annual_budget_usd: int,
        require_full_weight_rlvr: bool = True,
    ) -> dict[str, Any]:
        """Select optimal implementation scenario and verify whether scratch pretraining is justified."""
        if annual_budget_usd >= 12_000_000:
            selected = cls.SCENARIOS["Scenario-C"]
        elif annual_budget_usd >= 1_000_000 or require_full_weight_rlvr:
            selected = cls.SCENARIOS["Scenario-B"]
        else:
            selected = cls.SCENARIOS["Scenario-A"]

        return {
            "recommended_scenario": selected.scenario_id,
            "profile": selected,
            "pretrain_from_scratch_justified": False,
            "rationale": (
                "Pre-training from scratch ($5.6M-$50M+) is rejected: post-training Apache-2.0 "
                "Qwen3.8-27B and MIT DeepSeek-V4-Flash with deterministic tools and RLVR achieves "
                "91.31% on CyberGym L1 and >72% R_exec on binary decompilation at a fraction of cost."
            ),
        }
