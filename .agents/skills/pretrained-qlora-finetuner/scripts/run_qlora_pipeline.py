#!/usr/bin/env python3
"""CLI wrapper for pre-trained QLoRA planning, hygiene-gated post-training, and evaluation."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


def _ensure_src_on_path() -> None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "src"
        if (candidate / "platform_core").is_dir():
            src_str = str(candidate)
            if src_str not in sys.path:
                sys.path.insert(0, src_str)
            return


_ensure_src_on_path()


def _positive_int(raw: str) -> int:
    try:
        val = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected positive integer, got {raw!r}.") from exc
    if val <= 0:
        raise argparse.ArgumentTypeError(f"Value must be > 0, got {val}.")
    return val


def _validate_safe_input_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if ".." in path.parts:
        raise PermissionError(f"Path traversal '..' rejected in input path: {raw_path}")
    if path.is_symlink():
        raise PermissionError(f"Symlinked input path rejected: {path}")
    return path


def _validate_safe_output_path(raw_path: str, is_dir: bool = False) -> Path:
    path = Path(raw_path)
    if not raw_path.strip():
        raise ValueError("Output path must not be empty.")
    if ".." in path.parts:
        raise PermissionError(f"Path traversal '..' rejected in output path: {raw_path}")
    if path.is_symlink():
        raise PermissionError(f"Refusing to write to symlinked output path: {path}")
    if not path.is_absolute():
        cwd = Path.cwd().resolve()
        resolved = (cwd / path).resolve()
        if not resolved.is_relative_to(cwd):
            raise PermissionError(f"Relative output path escapes working directory: {raw_path}")
        cur = cwd
        for part in path.parts[:-1]:
            cur = cur / part
            if cur.is_symlink():
                raise PermissionError(f"Symlinked parent directory rejected: {cur}")
    if is_dir:
        if path.exists() and not path.is_dir():
            raise NotADirectoryError(f"Expected directory path, got file: {path}")
        path.mkdir(parents=True, exist_ok=True)
    else:
        if path.exists() and path.is_dir():
            raise IsADirectoryError(f"Output path is a directory: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_output(data: Any, output_file: str) -> None:
    """Write JSON result to `--output` after symlink and path-escape validation."""
    try:
        dest = _validate_safe_output_path(output_file, is_dir=False)
        with dest.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"Success! Data written to: {dest}")
    except (OSError, PermissionError, ValueError, TypeError) as exc:
        print(f"Error writing output to {output_file}: {exc}", file=sys.stderr)
        sys.exit(1)


def _probe_optional_packages() -> dict[str, bool]:
    pkgs = ("mlx", "mlx_lm", "torch", "transformers", "peft", "trl", "huggingface_hub")
    return {name: importlib.util.find_spec(name) is not None for name in pkgs}


def _handle_plan(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.deploy_security.governance import LicenseComplianceAuditor, LicenseVerdict
    from platform_core.layer1_intelligence.models import (
        HardwareFeasibilityPlanner,
        LocalHardwareDetector,
        ModelRegistry,
    )
    from platform_core.layer1_intelligence.training import (
        CustomModelPipeline,
        DistributedTrainingSpecBuilder,
        MLXQLoRATrainer,
        TorchTRLSpecAndRunner,
    )
    from platform_core.data_ingestion.data_factory import DatasetHygienePipeline

    auditor = LicenseComplianceAuditor()
    audit = auditor.audit(args.base_checkpoint, args.license)
    if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
        raise PermissionError(
            f"Base checkpoint '{args.base_checkpoint}' ({args.license}) failed license gate: {audit.rationale}"
        )

    hw = LocalHardwareDetector.detect()
    reg = ModelRegistry.for_profile(hw.recommended_profile)
    models = reg.all_models()
    matched_spec = next((m for m in models if m.model_id == args.base_checkpoint), None)
    packages = _probe_optional_packages()

    hygiene_summary: dict[str, Any] | None = None
    if args.dataset_file:
        ds_path = _validate_safe_input_path(args.dataset_file)
        records = CustomModelPipeline.load_trajectories_from_file(ds_path)[: args.limit]
        filtered = DatasetHygienePipeline().filter_records(records)
        hygiene_summary = {
            "total_input": filtered["total_input"],
            "accepted_count": filtered["accepted_count"],
            "rejected_breakdown": filtered["rejected_breakdown"],
        }

    mlx_lora_cfg = MLXQLoRATrainer.build_lora_config(
        base_model=args.base_checkpoint,
        data_dir="training_data",
        adapter_path="adapters",
        rank=args.lora_rank,
        iters=args.training_iters,
    )
    est_params_b = matched_spec.total_params_b if matched_spec is not None else 8.0
    dist_spec = DistributedTrainingSpecBuilder.build_spec(
        model_id=args.base_checkpoint.split("/")[-1],
        total_params_b=est_params_b,
        stage="SFT",
        context_length=8192,
        num_gpus=1 if hw.accelerator != "cuda" else 4,
    )
    trl_script_preview = TorchTRLSpecAndRunner.generate_training_script(
        model_id=args.base_checkpoint.split("/")[-1],
        base_checkpoint=args.base_checkpoint,
        data_dir="training_data",
        output_dir="trl_runs",
        sharding_backend=str(dist_spec["sharding_backend"]),
        lora_rank=args.lora_rank,
    )
    blueprint_scenario = HardwareFeasibilityPlanner.recommend_scenario(
        annual_budget_usd=200_000,
        require_full_weight_rlvr=False,
    )

    return {
        "command": "plan",
        "limit": args.limit,
        "base_checkpoint": args.base_checkpoint,
        "domain": args.domain,
        "license_audit": {
            "verdict": audit.verdict.value,
            "eu_compliant": audit.eu_compliant,
            "allows_commercial_distillation": audit.allows_commercial_distillation,
            "rationale": audit.rationale,
        },
        "hardware": {
            "os_name": hw.os_name,
            "arch": hw.arch,
            "accelerator": hw.accelerator,
            "total_memory_gb": hw.total_memory_gb,
            "safe_model_budget_gb": hw.safe_model_budget_gb,
            "recommended_profile": hw.recommended_profile.value,
            "base_model_fits_4bit": hw.fits_4bit(matched_spec) if matched_spec else None,
        },
        "blueprint_scenario": blueprint_scenario["recommended_scenario"],
        "optional_packages": packages,
        "dataset_hygiene": hygiene_summary,
        "mlx_qlora_config": mlx_lora_cfg,
        "distributed_training_spec": dist_spec,
        "torch_peft_trl_script_lines": len(trl_script_preview.splitlines()),
        "profile_models_checked": [
            {
                "model_id": m.model_id,
                "vram_4bit_gb": m.vram_4bit_gb,
                "fits_4bit": hw.fits_4bit(m),
            }
            for m in models[: args.limit]
        ],
    }


def _handle_train(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.deploy_security.governance import LicenseComplianceAuditor, LicenseVerdict
    from platform_core.layer1_intelligence.models import LocalHardwareDetector, ModelRegistry
    from platform_core.layer1_intelligence.training import (
        CustomModelConfig,
        CustomModelPipeline,
        MLXQLoRATrainer,
    )
    from platform_core.data_ingestion.data_factory import DatasetHygienePipeline

    auditor = LicenseComplianceAuditor()
    audit = auditor.audit(args.model_id, args.license)
    if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
        raise PermissionError(
            f"License gate rejected '{args.model_id}' ({args.license}): {audit.rationale}"
        )

    out_dir = _validate_safe_output_path(args.output_dir, is_dir=True)
    packages = _probe_optional_packages()
    hw = LocalHardwareDetector.detect()
    reg = ModelRegistry.for_profile(hw.recommended_profile)
    matched_spec = next((m for m in reg.all_models() if m.model_id == args.base_checkpoint), None)

    trajectories = None
    if args.dataset_file:
        ds_path = _validate_safe_input_path(args.dataset_file)
        loaded = CustomModelPipeline.load_trajectories_from_file(ds_path)
        trajectories = loaded[: args.limit]
        pre_filter = DatasetHygienePipeline().filter_records(trajectories)
        if pre_filter["accepted_count"] == 0:
            raise ValueError(
                f"Zero trajectories passed DatasetHygienePipeline: {pre_filter['rejected_breakdown']}"
            )

    requested_mode = args.execution_mode
    fallback_note: str | None = None
    if requested_mode == "auto":
        if args.live_mlx and packages["mlx_lm"]:
            effective_mode = "mlx_qlora"
        else:
            effective_mode = "torch_trl"
            if args.live_mlx and not packages["mlx_lm"]:
                fallback_note = "mlx_lm not installed; generated torch_trl + lora_config plan safely."
    else:
        effective_mode = requested_mode

    cfg = CustomModelConfig(
        model_id=args.model_id,
        base_checkpoint=args.base_checkpoint,
        domain=args.domain,
        total_params_b=matched_spec.total_params_b if matched_spec else 8.0,
        active_params_b=matched_spec.active_params_b if matched_spec else 8.0,
        license_id=args.license,
        num_gpus=1 if hw.accelerator != "cuda" else 8,
        execution_mode=effective_mode,
        lora_rank=args.lora_rank,
        training_iters=args.training_iters,
    )

    artifact = CustomModelPipeline.build_custom_model(
        config=cfg,
        custom_trajectories=trajectories,
        output_dir=out_dir,
    )

    lora_cfg_path: str | None = None
    if effective_mode != "mlx_qlora":
        lora_cfg = MLXQLoRATrainer.build_lora_config(
            base_model=args.base_checkpoint,
            data_dir=out_dir / "training_data",
            adapter_path=out_dir / "adapters",
            rank=args.lora_rank,
            iters=args.training_iters,
        )
        cfg_file = out_dir / "lora_config.json"
        if cfg_file.is_symlink():
            raise PermissionError(f"Refusing to overwrite symlinked config: {cfg_file}")
        cfg_file.write_text(json.dumps(lora_cfg, indent=2) + "\n", encoding="utf-8")
        lora_cfg_path = str(cfg_file)

    return {
        "command": "train",
        "limit": args.limit,
        "requested_mode": requested_mode,
        "effective_mode": effective_mode,
        "fallback_note": fallback_note,
        "optional_packages": packages,
        "model_id": artifact.model_spec.model_id,
        "base_checkpoint": artifact.model_spec.base_checkpoint,
        "pool": artifact.model_spec.pool.value,
        "license_id": artifact.model_spec.license_id,
        "safetensors_path": artifact.safetensors_path,
        "manifest_path": artifact.manifest_path,
        "lora_config_path": lora_cfg_path or str(out_dir / "lora_config.json"),
        "checkpoint_sha256": artifact.checkpoint_sha256,
        "training_metrics": artifact.training_metrics,
        "canary_promoted": artifact.canary_evaluation["promoted"],
        "canary_gains": artifact.canary_evaluation["significant_target_gains"],
    }


def _handle_evaluate(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer1_intelligence.training import CustomModelPipeline
    from platform_core.layer3_evolution.evaluation import BenchmarkSuiteRunner

    manifest_path = _validate_safe_input_path(args.manifest)
    loaded = CustomModelPipeline.load_custom_model_manifest(manifest_path)

    benchmark_report: dict[str, Any] | None = None
    if args.run_benchmarks:
        all_suites = ["coding", "reasoning", "cyber_vuln", "forensics", "hallucination_resistance"]
        selected_suites = all_suites[: args.limit]
        benchmark_report = BenchmarkSuiteRunner.run_all_suites(suites=selected_suites)

    return {
        "command": "evaluate",
        "limit": args.limit,
        "manifest_path": loaded["manifest_path"],
        "safetensors_path": loaded["safetensors_path"],
        "model_id": loaded["model_spec"].model_id,
        "pool": loaded["model_spec"].pool.value,
        "license_audit": {
            "verdict": loaded["license_audit"].verdict.value,
            "rationale": loaded["license_audit"].rationale,
        },
        "safetensors_validation": loaded["safetensors_validation"],
        "canary_promoted": loaded["manifest"].get("canary_promoted"),
        "canary_gains": loaded["manifest"].get("canary_gains"),
        "benchmark_report": benchmark_report,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Orchestrate pre-trained QLoRA planning, hygiene-gated post-training, and evaluation."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan", help="Audit license, hardware fit, dataset hygiene, and emit QLoRA specs")
    p_plan.add_argument("--base-checkpoint", default="fdtn-ai/Foundation-Sec-8B-Reasoning")
    p_plan.add_argument("--license", default="Apache-2.0")
    p_plan.add_argument("--domain", default="cyber")
    p_plan.add_argument("--dataset-file", default=None, help="Optional JSON/JSONL trajectories to pre-audit")
    p_plan.add_argument("--lora-rank", type=_positive_int, default=16)
    p_plan.add_argument("--training-iters", type=_positive_int, default=100)
    p_plan.add_argument("--limit", type=_positive_int, required=True, help="Max records/models to inspect")
    p_plan.add_argument("--output", required=True, help="Output JSON plan path")

    p_train = sub.add_parser("train", help="Run 5-stage QLoRA/post-training pipeline and export Safetensors")
    p_train.add_argument("--model-id", required=True, help="Output custom model ID")
    p_train.add_argument("--base-checkpoint", default="fdtn-ai/Foundation-Sec-8B-Reasoning")
    p_train.add_argument("--domain", default="cyber")
    p_train.add_argument("--license", default="Apache-2.0")
    p_train.add_argument("--dataset-file", default=None, help="Optional JSON/JSONL training trajectories")
    p_train.add_argument("--output-dir", required=True, help="Output directory for Safetensors & training artifacts")
    p_train.add_argument(
        "--execution-mode",
        choices=["auto", "spec_only", "mlx_qlora", "torch_trl"],
        default="auto",
    )
    p_train.add_argument("--live-mlx", action="store_true", help="Invoke live mlx_lm training in auto mode if installed")
    p_train.add_argument("--lora-rank", type=_positive_int, default=16)
    p_train.add_argument("--training-iters", type=_positive_int, default=100)
    p_train.add_argument("--limit", type=_positive_int, required=True, help="Max dataset trajectories to ingest")
    p_train.add_argument("--output", required=True, help="Output JSON report path")

    p_eval = sub.add_parser("evaluate", help="Verify custom Safetensors manifest and run platform benchmarks")
    p_eval.add_argument("--manifest", required=True, help="Path to <model_id>.manifest.json")
    p_eval.add_argument("--run-benchmarks", action="store_true", help="Execute live BenchmarkSuiteRunner suites")
    p_eval.add_argument("--limit", type=_positive_int, required=True, help="Max benchmark suites to run")
    p_eval.add_argument("--output", required=True, help="Output JSON evaluation path")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            data = _handle_plan(args)
        elif args.command == "train":
            data = _handle_train(args)
        elif args.command == "evaluate":
            data = _handle_evaluate(args)
        else:
            print(f"Unknown command: {args.command}", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"Error ({args.command}): {exc}", file=sys.stderr)
        return 1

    write_output(data, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
