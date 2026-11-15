#!/usr/bin/env python3
"""CLI wrapper for hardware inspection and pre-trained vs. from-scratch strategy advising."""

from __future__ import annotations

import argparse
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


def _non_negative_int(raw: str) -> int:
    try:
        val = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected non-negative integer, got {raw!r}.") from exc
    if val < 0:
        raise argparse.ArgumentTypeError(f"Value must be >= 0, got {val}.")
    return val


def _validate_safe_output_path(raw_path: str) -> Path:
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
    if path.exists() and path.is_dir():
        raise IsADirectoryError(f"Output path is a directory: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_output(data: Any, output_file: str) -> None:
    """Write JSON result to `--output` after symlink and path-escape validation."""
    try:
        dest = _validate_safe_output_path(output_file)
        with dest.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"Success! Data written to: {dest}")
    except (OSError, PermissionError, ValueError, TypeError) as exc:
        print(f"Error writing output to {output_file}: {exc}", file=sys.stderr)
        sys.exit(1)


def _build_override_hardware(profile_name: str):
    from platform_core.layer1_intelligence.models import HardwareProfile, LocalHardwareInfo

    profile = HardwareProfile(profile_name)
    if profile == HardwareProfile.CLUSTER_DEFAULT:
        return LocalHardwareInfo(
            os_name="Linux",
            arch="x86_64",
            cpu_brand="Simulated 8x GPU Cluster",
            total_memory_gb=640.0,
            safe_model_budget_gb=560.0,
            accelerator="cuda",
            recommended_profile=profile,
        )
    if profile == HardwareProfile.WORKSTATION_GPU:
        return LocalHardwareInfo(
            os_name="Linux",
            arch="x86_64",
            cpu_brand="Simulated Workstation GPU",
            total_memory_gb=96.0,
            safe_model_budget_gb=84.48,
            accelerator="cuda",
            recommended_profile=profile,
        )
    return LocalHardwareInfo(
        os_name="Darwin",
        arch="arm64",
        cpu_brand="Simulated Apple M3 Pro (36 GB)",
        total_memory_gb=36.0,
        safe_model_budget_gb=28.08,
        accelerator="apple_silicon_metal",
        recommended_profile=profile,
    )


def _handle_hardware_check(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer1_intelligence.models import LocalHardwareDetector, ModelRegistry

    hw = LocalHardwareDetector.detect()
    reg = ModelRegistry.for_profile(hw.recommended_profile)
    models = reg.all_models()[: args.limit]
    return {
        "command": "hardware-check",
        "limit": args.limit,
        "hardware": {
            "os_name": hw.os_name,
            "arch": hw.arch,
            "cpu_brand": hw.cpu_brand,
            "total_memory_gb": hw.total_memory_gb,
            "safe_model_budget_gb": hw.safe_model_budget_gb,
            "accelerator": hw.accelerator,
            "recommended_profile": hw.recommended_profile.value,
        },
        "candidate_model_count": len(models),
        "candidate_models": [
            {
                "model_id": m.model_id,
                "pool": m.pool.value,
                "architecture": m.architecture,
                "total_params_b": m.total_params_b,
                "active_params_b": m.active_params_b,
                "vram_4bit_gb": m.vram_4bit_gb,
                "vram_fp8_gb": m.vram_fp8_gb,
                "fits_4bit_budget": hw.fits_4bit(m),
                "license_id": m.license_id,
            }
            for m in models
        ],
    }


def _handle_recommend(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer1_intelligence.models import LocalHardwareDetector, ModelRegistry
    from platform_core.layer1_intelligence.scratch_trainer import CreationStrategyAdvisor

    hw = (
        _build_override_hardware(args.profile_override)
        if args.profile_override
        else LocalHardwareDetector.detect()
    )
    rec = CreationStrategyAdvisor.recommend(
        corpus_tokens=args.corpus_tokens,
        domain=args.domain,
        hardware_info=hw,
        custom_vocab_required=args.custom_vocab_required,
        target_params_m=args.target_params_m,
    )
    reg = ModelRegistry.for_profile(hw.recommended_profile)
    models = reg.all_models()[: args.limit]
    return {
        "command": "recommend",
        "limit": args.limit,
        "corpus_tokens": args.corpus_tokens,
        "domain": args.domain,
        "custom_vocab_required": bool(args.custom_vocab_required),
        "target_params_m": args.target_params_m,
        "recommended_path": rec.recommended_path.value,
        "base_model_id": rec.base_model_id,
        "rationale": rec.rationale,
        "hardware_summary": rec.hardware_summary,
        "estimated_vram_gb": rec.estimated_vram_gb,
        "fits_local_budget": rec.fits_local_budget,
        "warnings": list(rec.warnings),
        "profile_candidate_models": [
            {
                "model_id": m.model_id,
                "pool": m.pool.value,
                "vram_4bit_gb": m.vram_4bit_gb,
                "fits_4bit_budget": hw.fits_4bit(m),
                "license_id": m.license_id,
            }
            for m in models
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect host hardware and recommend RAG, QLoRA fine-tuning, or from-scratch SLM creation."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_hw = sub.add_parser("hardware-check", help="Detect local hardware & fitting open-weight models")
    p_hw.add_argument("--limit", type=_positive_int, required=True, help="Maximum candidate models to return")
    p_hw.add_argument("--output", required=True, help="Output JSON file path")

    p_rec = sub.add_parser("recommend", help="Recommend optimal local AI model creation strategy")
    p_rec.add_argument("--corpus-tokens", type=_non_negative_int, required=True, help="Estimated corpus token count")
    p_rec.add_argument("--domain", default="swe", help="Target domain (swe, cyber, binrev, visual_ocr, etc.)")
    p_rec.add_argument(
        "--custom-vocab-required",
        action="store_true",
        help="Set if custom byte-level BPE vocabulary is strictly required",
    )
    p_rec.add_argument(
        "--target-params-m",
        type=_positive_int,
        default=None,
        help="Optional target compact SLM parameter count in millions (e.g., 10..350)",
    )
    p_rec.add_argument(
        "--profile-override",
        choices=["LOCAL_APPLE_SILICON_36GB", "WORKSTATION_GPU", "CLUSTER_DEFAULT"],
        default=None,
        help="Optional simulated hardware profile for capacity planning",
    )
    p_rec.add_argument("--limit", type=_positive_int, required=True, help="Maximum candidate models to include")
    p_rec.add_argument("--output", required=True, help="Output JSON file path")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "hardware-check":
            data = _handle_hardware_check(args)
        elif args.command == "recommend":
            data = _handle_recommend(args)
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
