"""Tests for Layer 1 hardware profiling, inference backends, tool-calling, and training execution."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from platform_core.layer1_intelligence import (
    AdaptiveModelRouter,
    ChatMessage,
    CustomModelConfig,
    CustomModelPipeline,
    DeterministicMockBackend,
    HardwareProfile,
    InferenceRequest,
    InferenceResponse,
    LocalHardwareDetector,
    MemoryResidencyGuard,
    MLXLocalBackend,
    MLXQLoRATrainer,
    ModelDownloadManager,
    ModelPool,
    ModelRegistry,
    OpenAICompatibleClient,
    RoutingRequest,
    ServingEndpointConfig,
    ToolCall,
    ToolDefinition,
    TorchTRLSpecAndRunner,
    TrainingExecutionMode,
)
from platform_core.layer2_execution import AgentToolLoop


class TestInferenceAndTraining(unittest.TestCase):
    def test_hardware_detection_and_local_profile_routing(self) -> None:
        hw = LocalHardwareDetector.detect()
        self.assertGreater(hw.total_memory_gb, 0.0)
        self.assertGreater(hw.safe_model_budget_gb, 0.0)

        local_reg = ModelRegistry.for_profile(HardwareProfile.LOCAL_APPLE_SILICON_36GB)
        local_models = local_reg.all_models()
        self.assertGreaterEqual(len(local_models), 5)
        self.assertTrue(any(m.model_id == "Qwen/Qwen3.5-35B-A3B" for m in local_models))
        self.assertTrue(any(m.model_id == "fdtn-ai/Foundation-Sec-8B-Reasoning" for m in local_models))

        router = AdaptiveModelRouter(registry=local_reg)
        dec_forensics = router.route(
            RoutingRequest(
                task_id="t-for-1",
                task_domain="forensics",
                prompt_tokens=2048,
                uncertainty_entropy=0.6,
            )
        )
        self.assertEqual(dec_forensics.selected_pool, ModelPool.POOL_2_SWE_CYBER)
        self.assertIn(
            dec_forensics.primary_model.model_id,
            {"Qwen/Qwen3-Coder-30B-A3B-Instruct", "fdtn-ai/Foundation-Sec-8B-Reasoning"},
        )

    def test_serving_config_supports_mlx_and_llama_cpp(self) -> None:
        mlx_cfg = ServingEndpointConfig(
            engine="mlx_lm",
            engine_version="0.32.0",
            model_id="Qwen/Qwen3.5-35B-A3B",
            quantization="4bit",
            tensor_parallel_size=1,
            max_context_len=32768,
            enable_radix_prefix_cache=True,
            enable_chunked_prefill=True,
            port=8081,
        )
        args = mlx_cfg.to_launch_args()
        self.assertIn("mlx_lm.server", args)
        self.assertIn("8081", args)

        llama_cfg = ServingEndpointConfig(
            engine="llama_cpp",
            engine_version="b4000",
            model_id="/models/qwen.gguf",
            quantization="q4_k_m",
            tensor_parallel_size=1,
            max_context_len=16384,
            enable_radix_prefix_cache=True,
            enable_chunked_prefill=False,
            port=8082,
        )
        l_args = llama_cfg.to_launch_args()
        self.assertIn("llama-server", l_args)
        self.assertIn("8082", l_args)

    def test_memory_residency_guard_eviction_and_agent_tool_loop(self) -> None:
        evicted: list[str] = []
        guard = MemoryResidencyGuard(max_budget_gb=25.0)
        guard.acquire("model-a", 18.0, on_evict=lambda mid: evicted.append(mid))
        guard.acquire("model-b", 12.0, on_evict=lambda mid: evicted.append(mid))
        self.assertEqual(evicted, ["model-a"])
        self.assertEqual(guard.resident_models(), ["model-b"])

        with self.assertRaises(MemoryError):
            guard.acquire("too-big", 30.0)

        backend = DeterministicMockBackend(
            scripted_responses=[
                InferenceResponse(
                    model_id="mock-model",
                    content="Calling sum tool",
                    tool_calls=(ToolCall("call-1", "add_nums", {"a": 19, "b": 23}),),
                    prompt_tokens=10,
                    completion_tokens=8,
                ),
                InferenceResponse(
                    model_id="mock-model",
                    content="The verified sum is 42.",
                    tool_calls=(),
                    prompt_tokens=16,
                    completion_tokens=8,
                ),
            ]
        )
        loop = AgentToolLoop(
            backend=backend,
            model_id="mock-model",
            tools=[
                ToolDefinition(
                    name="add_nums",
                    description="Add two integers",
                    parameters={"type": "object"},
                )
            ],
            handlers={"add_nums": lambda args: {"sum": int(args["a"]) + int(args["b"])}},
        )
        res = loop.run(system_prompt="You are precise.", user_prompt="Please compute sum.")
        self.assertEqual(res["final_text"], "The verified sum is 42.")
        self.assertEqual(len(res["tool_trace"]), 1)
        self.assertEqual(res["tool_trace"][0]["result"], {"sum": 42})

    def test_openai_client_and_download_manager_guards(self) -> None:
        client = OpenAICompatibleClient(base_url="http://127.0.0.1:8080")
        with patch.object(
            client,
            "_post_json",
            side_effect=[
                {
                    "model": "local-qwen",
                    "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 7},
                },
                {"data": [{"index": 0, "embedding": [0.25, 0.75]}]},
            ],
        ):
            resp = client.generate(
                InferenceRequest(
                    model_id="local-qwen",
                    messages=(ChatMessage(role="user", content="ping"),),
                )
            )
            self.assertEqual(resp.content, "ok")
            self.assertEqual(client.embed("local-qwen", ["hello"]), [[0.25, 0.75]])

        mgr = ModelDownloadManager()
        with self.assertRaises(PermissionError):
            mgr.download_from_huggingface(
                repo_id="meta-llama/Llama-4-Maverick-17B-128E",
                license_id="Llama-4-Community",
                local_dir="/tmp/blocked",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = Path(tmpdir) / "bad_link"
            real_dir = Path(tmpdir) / "real"
            real_dir.mkdir()
            link_path.symlink_to(real_dir)
            with self.assertRaises(FileNotFoundError):
                mgr.audit_local_model_dir(link_path, license_id="Apache-2.0", model_id="m1")
            with self.assertRaises(ValueError):
                OpenAICompatibleClient(base_url="ftp://invalid.local")
            _ = MLXLocalBackend(residency_guard=MemoryResidencyGuard(max_budget_gb=20.0))

    def test_training_execution_modes_and_live_eval_hook(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "trl_out"
            cfg = CustomModelConfig(
                model_id="custom-sec-trl",
                base_checkpoint="Qwen/Qwen3-Coder-30B-A3B-Instruct",
                domain="vuln_intel",
                license_id="Apache-2.0",
                execution_mode=TrainingExecutionMode.TORCH_TRL.value,
                lora_rank=8,
                training_iters=50,
            )
            artifact = CustomModelPipeline.build_custom_model(
                config=cfg,
                output_dir=out_dir,
                eval_runner=lambda c: {
                    "promoted": True,
                    "significant_target_gains": ["CyberGym-L1"],
                    "custom_eval_model": c.model_id,
                },
            )
            self.assertEqual(artifact.training_metrics["execution_mode"], "torch_trl")
            self.assertEqual(artifact.training_metrics["evaluation_source"], "live_eval_runner")
            self.assertTrue((out_dir / "training_data" / "train.jsonl").is_file())
            self.assertTrue((out_dir / "training_data" / "valid.jsonl").is_file())
            script_path = Path(artifact.training_metrics["trl_script_path"])
            self.assertTrue(script_path.is_file())
            self.assertIn("SFTTrainer", script_path.read_text(encoding="utf-8"))

            mlx_out = Path(tmpdir) / "mlx_out"
            mlx_cfg = CustomModelConfig(
                model_id="custom-mlx-sec",
                base_checkpoint="fdtn-ai/Foundation-Sec-8B-Reasoning",
                domain="forensics",
                license_id="Apache-2.0",
                execution_mode=TrainingExecutionMode.MLX_QLORA.value,
            )
            with patch.object(
                MLXQLoRATrainer,
                "run_qlora_and_fuse",
                return_value={"backend": "mlx_lm_qlora", "primary_sha256": "abc123"},
            ) as mock_run:
                mlx_art = CustomModelPipeline.build_custom_model(config=mlx_cfg, output_dir=mlx_out)
                mock_run.assert_called_once()
                self.assertEqual(mlx_art.training_metrics["qlora_result"]["backend"], "mlx_lm_qlora")
                self.assertTrue(json.loads((mlx_out / "lora_config.json").read_text(encoding="utf-8"))["train"])
                self.assertIn("from trl import", TorchTRLSpecAndRunner.generate_training_script("m", "b", "d", "o", "fsdp2"))


if __name__ == "__main__":
    unittest.main()
