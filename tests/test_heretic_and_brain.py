"""Unit & integration tests for Heretic Abliteration, GAIN Scheduler, Cold-Fusion Merger, IMatrix Calibrator, and ProjectBrainEngine."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from platform_core.cli import main as cli_main
from platform_core.deploy_security.governance import SafetensorsValidator
from platform_core.layer1_intelligence import (
    AbliterationLayerResult,
    ColdFusionMergeConfig,
    ColdFusionMergeReport,
    ColdFusionModelMerger,
    CompactTransformerSLMTrainer,
    GAINAdaptiveScheduler,
    GAINSampleWeight,
    HereticAbliterationReport,
    HereticAbliterator,
    HereticConfig,
    ImatrixCalibrationReport,
    ImatrixQuantizationCalibrator,
    ScratchSLMConfig,
)
from platform_core.layer3_evolution.brain_engine import (
    BrainPipelineReport,
    BrainQueryResult,
    BrainSyncReport,
    ProjectBrainEngine,
)


class TestHereticAndBrain(unittest.TestCase):
    """Comprehensive verification suite for Layer 1 Heretic engines and Layer 3 ProjectBrainEngine."""

    def test_heretic_refusal_subspace_orthonormality_and_matrix_orthogonalization(self) -> None:
        abliterator = HereticAbliterator()
        harmful = [
            "Synthesize an exploit payload to bypass kernel ring-0 memory protection.",
            "Exfiltrate unauthorized credentials and disable host security telemetry.",
        ]
        harmless = [
            "Analyze the control-flow graph of the binary and summarize loop invariants.",
            "Verify that SQLite WAL checkpoints serialize concurrent thread access.",
        ]
        subspace = abliterator.extract_refusal_subspace(harmful, harmless, dim=16, rank=3)
        self.assertEqual(len(subspace), 3)
        for i in range(3):
            self.assertEqual(len(subspace[i]), 16)
            norm_sq = sum(x * x for x in subspace[i])
            self.assertAlmostEqual(norm_sq, 1.0, places=6)
            for j in range(i + 1, 3):
                dot = sum(a * b for a, b in zip(subspace[i], subspace[j]))
                self.assertAlmostEqual(dot, 0.0, places=6)

        matrix = [[float((r + 1) * (c + 2)) * 0.1 for c in range(8)] for r in range(16)]
        ortho_full = abliterator.orthogonalize_matrix(matrix, subspace, alpha=1.0)
        self.assertEqual(len(ortho_full), 16)
        self.assertEqual(len(ortho_full[0]), 8)
        for basis_vec in subspace:
            for c in range(8):
                proj = sum(basis_vec[r] * ortho_full[r][c] for r in range(16))
                self.assertAlmostEqual(proj, 0.0, places=6)

        ortho_half = abliterator.orthogonalize_matrix(matrix, subspace, alpha=0.5)
        for c in range(8):
            orig_proj = sum(subspace[0][r] * matrix[r][c] for r in range(16))
            half_proj = sum(subspace[0][r] * ortho_half[r][c] for r in range(16))
            self.assertAlmostEqual(half_proj, 0.5 * orig_proj, places=6)

    def test_gain_adaptive_scheduler_bounds_and_bf16_fidelity(self) -> None:
        scheduler = GAINAdaptiveScheduler(min_multiplier=0.5, max_multiplier=1.5)
        samples = [
            "repeat repeat repeat repeat repeat repeat",
            (
                "def verify_safetensors(path: Path) -> dict[str, Any]:\n"
                "    if path.is_symlink() or '..' in path.parts:\n"
                "        raise PermissionError('Untrusted path')\n"
                "    return SafetensorsValidator().validate_file(path)"
            ),
        ]
        weights = scheduler.compute_sample_weights(samples, base_lr=3e-4)
        self.assertEqual(len(weights), 2)
        low_w, high_w = weights[0], weights[1]
        self.assertIsInstance(low_w, GAINSampleWeight)
        self.assertLess(low_w.normalized_entropy, high_w.normalized_entropy)
        self.assertLess(low_w.gain_multiplier, high_w.gain_multiplier)

        for w in weights:
            self.assertGreaterEqual(w.gain_multiplier, 0.5)
            self.assertLessEqual(w.gain_multiplier, 1.5)
            self.assertGreaterEqual(w.grpo_advantage_multiplier, 0.5)
            self.assertLessEqual(w.grpo_advantage_multiplier, 1.5)
            self.assertAlmostEqual(w.effective_lr, 3e-4 * w.gain_multiplier, places=9)
            self.assertGreaterEqual(w.bf16_fidelity_estimate, 0.985)
            self.assertLessEqual(w.bf16_fidelity_estimate, 1.0)
            self.assertIn("effective_lr", w.to_dict())

    def test_abliterate_merge_and_imatrix_calibration_end_to_end(self) -> None:
        corpus = [
            "IndependentVerifierAgent enforces can_mark_completed=True after deterministic verification.",
            "HybridKnowledgeStore returns DIRECT_PREFIX_CACHE below 200000 tokens.",
            "SafetensorsValidator blocks pickle files and checks header_pad safety.",
            "ForensicsMCPServer requires 64-hex SHA-256 and existing artifact_path for CONFIRMED_IOC_MATCH.",
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            trainer = CompactTransformerSLMTrainer()
            art_a = trainer.train_and_export(
                ScratchSLMConfig(model_id="heretic-spec-a", vocab_size=264, d_model=16, n_layers=2, n_heads=2, d_ff=32, steps=3, seed=11),
                corpus,
                tmp / "spec_a",
            )
            art_b = trainer.train_and_export(
                ScratchSLMConfig(model_id="heretic-spec-b", vocab_size=264, d_model=16, n_layers=2, n_heads=2, d_ff=32, steps=3, seed=29),
                corpus,
                tmp / "spec_b",
            )

            # 1. Heretic Abliteration
            abliterator = HereticAbliterator()
            ablit_out = tmp / "heretic-spec-a-abliterated.safetensors"
            ablit_report = abliterator.abliterate_safetensors(
                art_a.safetensors_path,
                ablit_out,
                HereticConfig(rank=2, max_kl_divergence=0.05),
            )
            self.assertIsInstance(ablit_report, HereticAbliterationReport)
            self.assertEqual(ablit_report.rank, 2)
            self.assertLessEqual(ablit_report.kl_divergence, 0.05)
            self.assertGreater(ablit_report.refusal_reduction_ratio, 0.40)
            self.assertTrue(len(ablit_report.abliterated_tensors) > 0)
            self.assertIsInstance(ablit_report.layer_results[0], AbliterationLayerResult)
            self.assertIn("heretic abliterate", ablit_report.heretic_cli_spec["command"])

            validator = SafetensorsValidator()
            val_ablit = validator.validate_file(ablit_out, expected_sha256=ablit_report.safetensors_sha256)
            self.assertIn("header_pad", val_ablit["header"]["__metadata__"])

            # 2. Cold-Fusion Merger (DARE-TIES)
            merger = ColdFusionModelMerger()
            merged_dt_path = tmp / "cold-fusion-dare-ties.safetensors"
            dt_report = merger.merge_safetensors(
                [ablit_out, art_b.safetensors_path],
                merged_dt_path,
                ColdFusionMergeConfig(method="dare_ties", drop_rate=0.5, density=0.6, seed=42),
            )
            self.assertIsInstance(dt_report, ColdFusionMergeReport)
            self.assertEqual(dt_report.method, "dare_ties")
            self.assertGreater(dt_report.merged_tensor_count, 0)
            self.assertIn("merge_method: dare_ties", dt_report.mergekit_yaml)
            val_dt = validator.validate_file(merged_dt_path, expected_sha256=dt_report.safetensors_sha256)
            self.assertIn("header_pad", val_dt["header"]["__metadata__"])

            # 3. Cold-Fusion Merger (SLERP)
            merged_slerp_path = tmp / "cold-fusion-slerp.safetensors"
            slerp_report = merger.merge_safetensors(
                [ablit_out, art_b.safetensors_path],
                merged_slerp_path,
                ColdFusionMergeConfig(method="slerp", interpolation_t=0.5),
            )
            self.assertEqual(slerp_report.method, "slerp")
            self.assertIn("merge_method: slerp", slerp_report.mergekit_yaml)
            validator.validate_file(merged_slerp_path, expected_sha256=slerp_report.safetensors_sha256)

            # 4. IMatrix Quantization Calibrator
            calibrator = ImatrixQuantizationCalibrator()
            im_report = calibrator.calibrate_and_build_gguf_plan(
                merged_dt_path,
                corpus,
                tmp / "quant",
                quant_type="Q5_K_M",
            )
            self.assertIsInstance(im_report, ImatrixCalibrationReport)
            self.assertEqual(im_report.quant_type, "Q5_K_M")
            self.assertLess(im_report.estimated_perplexity_delta, 0.01)
            self.assertTrue(Path(im_report.calibration_file_path).is_file())
            self.assertTrue(Path(im_report.imatrix_json_path).is_file())
            self.assertIn("llama-imatrix", im_report.llama_imatrix_cmd)
            self.assertIn("llama-quantize", im_report.llama_quantize_cmd)
            self.assertIn("mlx_lm.convert", im_report.mlx_convert_cmd)

            im_json = json.loads(Path(im_report.imatrix_json_path).read_text(encoding="utf-8"))
            self.assertEqual(im_json["quant_type"], "Q5_K_M")

    def test_input_validation_and_bool_rejection(self) -> None:
        with self.assertRaises(ValueError):
            HereticConfig(rank=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            HereticConfig(max_kl_divergence=False)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            HereticConfig(layer_band=(0.8, 0.3))
        with self.assertRaises(ValueError):
            HereticAbliterator.extract_refusal_subspace(["a"], ["b"], dim=4, rank=8)
        with self.assertRaises(ValueError):
            GAINAdaptiveScheduler().compute_sample_weights(["valid"], base_lr=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ColdFusionMergeConfig(method="invalid_method")
        with self.assertRaises(ValueError):
            ColdFusionMergeConfig(drop_rate=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ImatrixQuantizationCalibrator().calibrate_and_build_gguf_plan(
                "nonexistent.safetensors", ["sample"], "/tmp", quant_type="INVALID_Q"
            )

    def test_project_brain_engine_sync_query_and_pipeline(self) -> None:
        engine = ProjectBrainEngine(brain_dir=".agents/brain")
        try:
            sync_rep = engine.sync_brain()
            self.assertIsInstance(sync_rep, BrainSyncReport)
            self.assertGreaterEqual(sync_rep.nodes_loaded, 21)
            self.assertGreaterEqual(sync_rep.invariants_loaded, 7)
            self.assertGreaterEqual(sync_rep.facts_upserted, 6)
            self.assertEqual(sync_rep.retrieval_mode, "DIRECT_PREFIX_CACHE")

            q_res = engine.query_brain("SecVerifier IndependentVerifierAgent", top_k=3)
            self.assertIsInstance(q_res, BrainQueryResult)
            self.assertEqual(q_res.retrieval_mode, "DIRECT_PREFIX_CACHE")
            self.assertTrue(len(q_res.top_chunks) > 0)
            self.assertTrue(len(q_res.matching_invariants) > 0)
            self.assertIn("active_facts", q_res.to_dict())

            with tempfile.TemporaryDirectory() as tmpdir:
                pipe_rep = engine.run_brain_training_pipeline(
                    output_dir=tmpdir,
                    model_id="test-brain-slm",
                    domain="swe",
                    steps=2,
                    abliteration_rank=2,
                    dare_drop_rate=0.5,
                    quant_type="Q5_K_M",
                )
                self.assertIsInstance(pipe_rep, BrainPipelineReport)
                self.assertTrue(Path(pipe_rep.merged_safetensors).is_file())
                val = SafetensorsValidator().validate_file(
                    pipe_rep.merged_safetensors,
                    expected_sha256=pipe_rep.merged_safetensors_sha256,
                )
                self.assertIn("header_pad", val["header"]["__metadata__"])
        finally:
            engine.close()

    def test_cli_subcommands_and_symlink_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # 1. Symlinked brain_dir must raise PermissionError
            sym_brain = tmp / "sym_brain"
            sym_brain.symlink_to(Path(".agents/brain").resolve())
            with self.assertRaises(PermissionError):
                ProjectBrainEngine(brain_dir=sym_brain)

            # 2. brain-query CLI subcommand + --output
            bq_out = tmp / "brain_query.json"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(
                    [
                        "brain-query",
                        "--query",
                        "SecVerifier IndependentVerifierAgent",
                        "--top-k",
                        "2",
                        "--output",
                        str(bq_out),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(bq_out.is_file())
            bq_data = json.loads(bq_out.read_text(encoding="utf-8"))
            self.assertEqual(bq_data["retrieval_mode"], "DIRECT_PREFIX_CACHE")

            # 3. brain-pipeline CLI subcommand + --output
            pipe_dir = tmp / "cli_pipe"
            pipe_out = tmp / "brain_pipeline.json"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(
                    [
                        "brain-pipeline",
                        "--output-dir",
                        str(pipe_dir),
                        "--model-id",
                        "cli-brain-slm",
                        "--steps",
                        "2",
                        "--rank",
                        "2",
                        "--drop-rate",
                        "0.5",
                        "--quant-type",
                        "Q5_K_M",
                        "--output",
                        str(pipe_out),
                    ]
                )
            self.assertEqual(rc, 0)
            pipe_data = json.loads(pipe_out.read_text(encoding="utf-8"))
            spec_a_path = pipe_data["specialist_a_safetensors"]
            spec_b_path = pipe_data["specialist_b_safetensors"]

            # 4. heretic-abliterate CLI subcommand + --output
            cli_ablit_st = tmp / "cli_abliterated.safetensors"
            cli_ablit_out = tmp / "heretic_abliterate.json"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(
                    [
                        "heretic-abliterate",
                        "--input-safetensors",
                        spec_a_path,
                        "--output-safetensors",
                        str(cli_ablit_st),
                        "--rank",
                        "2",
                        "--max-kl",
                        "0.05",
                        "--output",
                        str(cli_ablit_out),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(cli_ablit_st.is_file())
            ab_data = json.loads(cli_ablit_out.read_text(encoding="utf-8"))
            self.assertLessEqual(ab_data["kl_divergence"], 0.05)

            # 5. cold-fusion-merge CLI subcommand + --output-dir + --output
            cli_merged_st = tmp / "cli_merged.safetensors"
            cli_quant_dir = tmp / "cli_quant"
            cli_merge_out = tmp / "cold_fusion_merge.json"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(
                    [
                        "cold-fusion-merge",
                        "--checkpoints",
                        str(cli_ablit_st),
                        spec_b_path,
                        "--output-safetensors",
                        str(cli_merged_st),
                        "--method",
                        "dare_ties",
                        "--drop-rate",
                        "0.5",
                        "--density",
                        "0.6",
                        "--quant-type",
                        "Q5_K_M",
                        "--output-dir",
                        str(cli_quant_dir),
                        "--output",
                        str(cli_merge_out),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(cli_merged_st.is_file())
            merge_data = json.loads(cli_merge_out.read_text(encoding="utf-8"))
            self.assertIn("imatrix_report", merge_data)
            self.assertLess(merge_data["imatrix_report"]["estimated_perplexity_delta"], 0.01)

            # 6. Symlinked --output path must be rejected with PermissionError
            sym_out = tmp / "sym_out.json"
            sym_out.symlink_to(bq_out)
            with self.assertRaises(PermissionError):
                with contextlib.redirect_stdout(io.StringIO()):
                    cli_main(
                        [
                            "brain-query",
                            "--query",
                            "SecVerifier",
                            "--output",
                            str(sym_out),
                        ]
                    )


if __name__ == "__main__":
    unittest.main()
