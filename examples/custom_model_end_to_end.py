"""End-to-End Real-Life Demonstration: Creating, Saving, Loading & Running Custom Specialist Models.

Run from the repository root:
    PYTHONPATH=src .venv/bin/python examples/custom_model_end_to_end.py
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

from platform_core.cli import run_demo_workflow
from platform_core.layer1_intelligence import (
    CustomModelConfig,
    CustomModelPipeline,
)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    sample_dataset = repo_root / "examples" / "sample_custom_trajectories.jsonl"
    sample_task = repo_root / "examples" / "sample_cyber_workflow.json"

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = Path(tmp_dir) / "artifacts"

        # 1. Load custom verified trajectories & build a custom 27.8B SWE/Cyber model
        trajectories = CustomModelPipeline.load_trajectories_from_file(sample_dataset)
        config = CustomModelConfig(
            model_id="Acme-SecCoder-27B-v1",
            base_checkpoint="Qwen/Qwen3.8-27B",
            domain="cyber",
            total_params_b=27.8,
            context_window=262_144,
            license_id="Apache-2.0",
            serving_engine="sglang",
            serving_port=30015,
        )
        artifact = CustomModelPipeline.build_custom_model(
            config=config,
            custom_trajectories=trajectories,
            output_dir=out_dir,
        )

        # 2. Load the saved custom model from disk (.manifest.json + .safetensors)
        assert artifact.manifest_path is not None
        loaded = CustomModelPipeline.load_custom_model_manifest(artifact.manifest_path)

        # 3. Execute the 10-step agent workflow using the loaded custom model
        workflow_result = run_demo_workflow(
            domain="cyber",
            manifest_path=artifact.manifest_path,
            payload_file=sample_task,
        )

        summary = {
            "step1_custom_model_created": {
                "model_id": artifact.model_spec.model_id,
                "pool": artifact.model_spec.pool.value,
                "base_checkpoint": artifact.model_spec.base_checkpoint,
                "license": artifact.model_spec.license_id,
                "accepted_trajectories": artifact.training_metrics["accepted_training_trajectories"],
                "sharding_backend": artifact.training_metrics["sharding_backend"],
                "checkpoint_sha256": artifact.checkpoint_sha256,
                "canary_promoted": artifact.canary_evaluation["promoted"],
                "serving_launch_command": " ".join(artifact.serving_launch_args),
            },
            "step2_disk_verification": {
                "safetensors_verified": loaded["safetensors_validation"]["tensor_count"] == 1,
                "license_verdict": loaded["license_audit"].verdict.value,
            },
            "step3_workflow_execution": workflow_result,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
