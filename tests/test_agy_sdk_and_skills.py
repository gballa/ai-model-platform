"""Tests for Layer 2 Google Antigravity SDK bridge, skill discovery, stdio MCP, CLI subcommands, and skill scripts."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from platform_core.layer1_intelligence import DeterministicMockBackend, InferenceResponse
from platform_core.layer2_execution import (
    AgyLocalAgentSpec,
    AgyLocalOrchestrator,
    AgySkillDiscovery,
    AgyStdioMCPBridge,
)
from platform_core.layer2_execution.agy_sdk_bridge import MAX_JSONRPC_LINE_BYTES

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_ROOT = REPO_ROOT / ".agents" / "skills"


def _run_py(args: list[str], stdin_text: str | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    src_path = str(REPO_ROOT / "src")
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{existing_pp}" if existing_pp else src_path
    return subprocess.run(
        [sys.executable, "-W", "error", *args],
        cwd=str(REPO_ROOT),
        env=env,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


class TestAgySdkBridge(unittest.TestCase):
    def test_skill_discovery_finds_all_five_workspace_skills_and_rejects_symlinks(self) -> None:
        discovered = AgySkillDiscovery.discover_skills([SKILLS_ROOT])
        names = {item["name"] for item in discovered}
        expected = {
            "corpus-harvester",
            "local-model-advisor",
            "scratch-slm-trainer",
            "pretrained-qlora-finetuner",
            "agy-local-agent-runner",
        }
        self.assertEqual(names, expected)
        for item in discovered:
            self.assertTrue(item["description"], msg=f"Missing description for {item['name']}")
            self.assertTrue(Path(item["skill_file"]).is_file())

        with self.assertRaises(PermissionError):
            AgySkillDiscovery.discover_skills(["../outside"])

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outside = root / "outside_skill"
            outside.mkdir()
            (outside / "SKILL.md").write_text("---\nname: evil\ndescription: x\n---\n", encoding="utf-8")

            skills_dir = root / "skills"
            skills_dir.mkdir()
            (skills_dir / "sym_skill").symlink_to(outside)
            with self.assertRaises(PermissionError):
                AgySkillDiscovery.discover_skills([skills_dir])

            # Symlinked SKILL.md inside real skill dir
            bad_skill = root / "skills2" / "real_dir"
            bad_skill.mkdir(parents=True)
            (bad_skill / "SKILL.md").symlink_to(outside / "SKILL.md")
            with self.assertRaises(PermissionError):
                AgySkillDiscovery.discover_skills([root / "skills2"])

    def test_stdio_mcp_bridge_tool_identifiers_taint_policy_and_jsonrpc_stdio(self) -> None:
        with AgyStdioMCPBridge() as bridge:
            clean_tools = bridge.list_tools(session_tainted=False)
            tainted_tools = bridge.list_tools(session_tainted=True)

            self.assertGreaterEqual(len(clean_tools), 15)
            for tool in clean_tools:
                self.assertTrue(tool["name"].isidentifier(), msg=f"Invalid identifier: {tool['name']}")
                for prop_name in tool["inputSchema"].get("properties", {}):
                    self.assertTrue(str(prop_name).isidentifier())

            clean_names = {t["name"] for t in clean_tools}
            tainted_names = {t["name"] for t in tainted_tools}
            self.assertIn("vuln_sync_live_feeds", clean_names)
            self.assertNotIn("vuln_sync_live_feeds", tainted_names)

            # Newline-delimited JSON-RPC over stdio including oversized bounded line recovery
            oversized_line = "x" * (MAX_JSONRPC_LINE_BYTES + 128)
            requests = [
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "data_classify_transformation",
                            "arguments": {"utf8_text": "hello world telemetry"},
                        },
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {"name": "vuln_sync_live_feeds", "arguments": {"feeds": ["kev"]}},
                    }
                ),
                oversized_line,
                json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping", "params": {}}),
            ]
            stdin_buf = io.StringIO("\n".join(requests) + "\n")
            stdout_buf = io.StringIO()

            processed = bridge.serve_stdio(stdin=stdin_buf, stdout=stdout_buf, session_tainted=True)
            self.assertEqual(processed, 6)

            responses = [json.loads(line) for line in stdout_buf.getvalue().splitlines() if line.strip()]
            self.assertEqual(len(responses), 6)

            init_resp, list_resp, call_ok, call_blocked, err_big, ping_resp = responses
            self.assertEqual(init_resp["id"], 1)
            self.assertTrue(init_resp["result"]["serverInfo"]["session_tainted"])

            listed_names = {t["name"] for t in list_resp["result"]["tools"]}
            self.assertNotIn("vuln_sync_live_feeds", listed_names)
            self.assertIn("data_classify_transformation", listed_names)

            self.assertFalse(call_ok["result"]["isError"])
            self.assertEqual(
                call_ok["result"]["structuredContent"]["transformation_class"],
                "ENCODING_SERIALIZATION",
            )

            self.assertEqual(call_blocked["error"]["code"], -32003)
            self.assertIn("TAINTED_UNTRUSTED", call_blocked["error"]["message"])

            self.assertEqual(err_big["error"]["code"], -32600)
            self.assertIn("exceeded", err_big["error"]["message"])

            self.assertEqual(ping_resp, {"jsonrpc": "2.0", "id": 5, "result": {}})

    def test_agy_local_orchestrator_configs_taint_and_secverifier_gate(self) -> None:
        self.assertIsInstance(AgyLocalOrchestrator.is_sdk_installed(), bool)
        orchestrator = AgyLocalOrchestrator()

        # LiteRT config expands '~' and validates model path
        litert_spec = AgyLocalAgentSpec(
            agent_name="litert-auditor",
            runtime_kind="litert",
            model_or_path="~/models/gemma4-26b.litertlm",
            base_url=None,
            litert_backend="gpu",
            skills_paths=(str(SKILLS_ROOT),),
            session_tainted=True,
        )
        litert_cfg = orchestrator.build_sdk_config(litert_spec)
        if isinstance(litert_cfg, dict):
            self.assertEqual(litert_cfg["config_class"], "LiteRTAgentConfig")
            self.assertFalse(litert_cfg["model_path"].startswith("~"))
            self.assertEqual(litert_cfg["model_path"], os.path.expanduser("~/models/gemma4-26b.litertlm"))

        # Tainted LocalOpenAI blocks remote non-loopback base_url
        remote_tainted = AgyLocalAgentSpec(
            agent_name="bad-remote",
            runtime_kind="local_openai",
            base_url="https://remote.example.com/v1",
            skills_paths=(str(SKILLS_ROOT),),
            session_tainted=True,
        )
        with self.assertRaises(PermissionError):
            orchestrator.build_sdk_config(remote_tainted)

        # Fallback execution with valid response passes IndependentVerifierAgent -> COMPLETED
        ok_spec = AgyLocalAgentSpec(
            agent_name="swe-verifier-ok",
            runtime_kind="local_openai",
            base_url="http://127.0.0.1:8080/v1",
            skills_paths=(str(SKILLS_ROOT),),
            session_tainted=True,
        )
        ok_orch = AgyLocalOrchestrator(
            inference_backend=DeterministicMockBackend(
                scripted_responses=[
                    InferenceResponse(
                        model_id="Qwen/Qwen3.5-35B-A3B",
                        content="Verified patch summary: bounds check added.",
                        tool_calls=(),
                        prompt_tokens=12,
                        completion_tokens=10,
                    )
                ]
            )
        )
        res_ok = ok_orch.run_local_agent(ok_spec, prompt="Audit module", force_fallback=True)
        self.assertEqual(res_ok.execution_backend, "stdlib_fallback")
        self.assertTrue(res_ok.verified_by_independent_verifier)
        self.assertEqual(res_ok.status, "COMPLETED")
        self.assertEqual(res_ok.taint_level, "TAINTED_UNTRUSTED")
        self.assertEqual(len(res_ok.loaded_skills), 5)

        # Fallback execution with empty response is rejected by IndependentVerifierAgent -> VERIFIER_REJECTED
        empty_orch = AgyLocalOrchestrator(
            inference_backend=DeterministicMockBackend(
                scripted_responses=[
                    InferenceResponse(
                        model_id="Qwen/Qwen3.5-35B-A3B",
                        content="   ",
                        tool_calls=(),
                        prompt_tokens=10,
                        completion_tokens=0,
                    )
                ]
            )
        )
        res_bad = empty_orch.run_local_agent(ok_spec, prompt="Audit module", force_fallback=True)
        self.assertFalse(res_bad.verified_by_independent_verifier)
        self.assertEqual(res_bad.status, "VERIFIER_REJECTED")


class TestCliAndWorkspaceSkillSubprocesses(unittest.TestCase):
    def test_platform_cli_new_subcommands(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            book = root / "book.md"
            book.write_text(
                "# Defensive Systems\nValidate magic headers and enforce bounds checking.\n",
                encoding="utf-8",
            )

            # 1. recommend-strategy
            rec_out = root / "rec.json"
            rec_proc = _run_py(
                [
                    "-m",
                    "platform_core.cli",
                    "recommend-strategy",
                    "--corpus-tokens",
                    "120000",
                    "--domain",
                    "cyber",
                    "--output",
                    str(rec_out),
                ]
            )
            self.assertEqual(rec_proc.returncode, 0, msg=rec_proc.stderr)
            rec_data = json.loads(rec_out.read_text(encoding="utf-8"))
            self.assertIn(
                rec_data["recommended_path"],
                {"PRETRAINED_QLORA_FIRST", "MULTI_GPU_FULL_POST_TRAIN"},
            )

            # 2. harvest-corpus + --limit 0 rejection
            harv_out = root / "harvest.json"
            harv_proc = _run_py(
                [
                    "-m",
                    "platform_core.cli",
                    "harvest-corpus",
                    "--pdf",
                    str(book),
                    "--limit",
                    "5",
                    "--output",
                    str(harv_out),
                ]
            )
            self.assertEqual(harv_proc.returncode, 0, msg=harv_proc.stderr)
            harv_data = json.loads(harv_out.read_text(encoding="utf-8"))
            self.assertEqual(harv_data["documents_harvested"], 1)
            self.assertEqual(harv_data["rag_ingestion_stats"]["retrieval_mode"], "DIRECT_PREFIX_CACHE")

            bad_limit = _run_py(
                ["-m", "platform_core.cli", "harvest-corpus", "--pdf", str(book), "--limit", "0"]
            )
            self.assertNotEqual(bad_limit.returncode, 0)

            # 3. train-scratch-slm
            slm_dir = root / "slm_artifacts"
            slm_out = root / "slm.json"
            slm_proc = _run_py(
                [
                    "-m",
                    "platform_core.cli",
                    "train-scratch-slm",
                    "--model-id",
                    "cli-micro-slm",
                    "--text",
                    "def add(a, b): return a + b\ndef sub(a, b): return a - b\n",
                    "--text",
                    "def mul(a, b): return a * b\ndef div(a, b): return a / b\n",
                    "--output-dir",
                    str(slm_dir),
                    "--steps",
                    "6",
                    "--vocab-size",
                    "280",
                    "--d-model",
                    "16",
                    "--n-layers",
                    "1",
                    "--n-heads",
                    "2",
                    "--d-ff",
                    "32",
                    "--max-seq-len",
                    "32",
                    "--batch-size",
                    "2",
                    "--learning-rate",
                    "0.25",
                    "--backend",
                    "stdlib",
                    "--sample-prompt",
                    "def ",
                    "--output",
                    str(slm_out),
                ]
            )
            self.assertEqual(slm_proc.returncode, 0, msg=slm_proc.stderr)
            slm_data = json.loads(slm_out.read_text(encoding="utf-8"))
            self.assertLess(slm_data["final_loss"], slm_data["initial_loss"])
            self.assertTrue(Path(slm_data["safetensors_path"]).is_file())
            self.assertTrue(Path(slm_data["manifest_path"]).is_file())

            # 4. run-agy-local
            agy_out = root / "agy.json"
            agy_proc = _run_py(
                [
                    "-m",
                    "platform_core.cli",
                    "run-agy-local",
                    "--prompt",
                    "Inspect local security controls",
                    "--force-fallback",
                    "--tainted",
                    "--output",
                    str(agy_out),
                ]
            )
            self.assertEqual(agy_proc.returncode, 0, msg=agy_proc.stderr)
            agy_data = json.loads(agy_out.read_text(encoding="utf-8"))
            self.assertEqual(agy_data["status"], "COMPLETED")
            self.assertTrue(agy_data["verified_by_independent_verifier"])

            # 5. mcp-stdio-bridge
            rpc_input = "\n".join(
                [
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "data_classify_transformation",
                                "arguments": {"utf8_text": "hello mcp"},
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 4,
                            "method": "tools/call",
                            "params": {"name": "vuln_sync_live_feeds", "arguments": {}},
                        }
                    ),
                ]
            ) + "\n"
            mcp_proc = _run_py(
                ["-m", "platform_core.cli", "mcp-stdio-bridge", "--server", "data_visual", "vuln_intel", "--tainted"],
                stdin_text=rpc_input,
            )
            self.assertEqual(mcp_proc.returncode, 0, msg=mcp_proc.stderr)
            mcp_lines = [json.loads(l) for l in mcp_proc.stdout.splitlines() if l.strip()]
            self.assertEqual(len(mcp_lines), 4)
            self.assertEqual(mcp_lines[2]["result"]["structuredContent"]["transformation_class"], "ENCODING_SERIALIZATION")
            self.assertEqual(mcp_lines[3]["error"]["code"], -32003)

    def test_all_five_workspace_skill_scripts_cli_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            corpus_file = root / "corpus.md"
            corpus_file.write_text(
                "def parse_header(b): return b[:4]\n"
                "def check_crc(b): return sum(b) & 0xff\n" * 4,
                encoding="utf-8",
            )
            sym_target = root / "protected.json"
            sym_target.write_text('{"keep": true}\n', encoding="utf-8")
            sym_out = root / "symlink_out.json"
            sym_out.symlink_to(sym_target)

            cases = [
                {
                    "script": SKILLS_ROOT / "corpus-harvester" / "scripts" / "harvest_corpus.py",
                    "ok_args": [
                        "harvest-pdfs",
                        "--paths",
                        str(corpus_file),
                        "--limit",
                        "5",
                        "--output",
                        str(root / "skill_harvest.json"),
                    ],
                    "bad_limit_args": [
                        "harvest-pdfs",
                        "--paths",
                        str(corpus_file),
                        "--limit",
                        "0",
                        "--output",
                        str(root / "unused1.json"),
                    ],
                    "sym_args": [
                        "harvest-pdfs",
                        "--paths",
                        str(corpus_file),
                        "--limit",
                        "5",
                        "--output",
                        str(sym_out),
                    ],
                    "expected_out": root / "skill_harvest.json",
                    "assert_key": "document_count",
                },
                {
                    "script": SKILLS_ROOT / "local-model-advisor" / "scripts" / "recommend_strategy.py",
                    "ok_args": [
                        "recommend",
                        "--corpus-tokens",
                        "120000",
                        "--domain",
                        "cyber",
                        "--limit",
                        "5",
                        "--output",
                        str(root / "skill_advise.json"),
                    ],
                    "bad_limit_args": [
                        "recommend",
                        "--corpus-tokens",
                        "1000",
                        "--limit",
                        "0",
                        "--output",
                        str(root / "unused2.json"),
                    ],
                    "sym_args": [
                        "recommend",
                        "--corpus-tokens",
                        "120000",
                        "--limit",
                        "5",
                        "--output",
                        str(sym_out),
                    ],
                    "expected_out": root / "skill_advise.json",
                    "assert_key": "recommended_path",
                },
                {
                    "script": SKILLS_ROOT / "scratch-slm-trainer" / "scripts" / "train_scratch_slm.py",
                    "ok_args": [
                        "train-slm",
                        "--model-id",
                        "skill-micro-slm",
                        "--corpus-files",
                        str(corpus_file),
                        "--output-dir",
                        str(root / "skill_slm_dir"),
                        "--steps",
                        "6",
                        "--vocab-size",
                        "280",
                        "--d-model",
                        "16",
                        "--n-layers",
                        "1",
                        "--n-heads",
                        "2",
                        "--d-ff",
                        "32",
                        "--max-seq-len",
                        "32",
                        "--batch-size",
                        "2",
                        "--learning-rate",
                        "0.25",
                        "--backend",
                        "stdlib",
                        "--limit",
                        "10",
                        "--output",
                        str(root / "skill_slm.json"),
                    ],
                    "bad_limit_args": [
                        "train-slm",
                        "--model-id",
                        "skill-micro-slm",
                        "--corpus-files",
                        str(corpus_file),
                        "--output-dir",
                        str(root / "unused_dir"),
                        "--steps",
                        "4",
                        "--limit",
                        "0",
                        "--output",
                        str(root / "unused3.json"),
                    ],
                    "sym_args": [
                        "train-slm",
                        "--model-id",
                        "skill-micro-slm",
                        "--corpus-files",
                        str(corpus_file),
                        "--output-dir",
                        str(root / "skill_slm_dir_sym"),
                        "--steps",
                        "4",
                        "--vocab-size",
                        "280",
                        "--d-model",
                        "16",
                        "--n-layers",
                        "1",
                        "--n-heads",
                        "2",
                        "--d-ff",
                        "32",
                        "--max-seq-len",
                        "32",
                        "--batch-size",
                        "2",
                        "--backend",
                        "stdlib",
                        "--limit",
                        "10",
                        "--output",
                        str(sym_out),
                    ],
                    "expected_out": root / "skill_slm.json",
                    "assert_key": "checkpoint_sha256",
                },
                {
                    "script": SKILLS_ROOT / "pretrained-qlora-finetuner" / "scripts" / "run_qlora_pipeline.py",
                    "ok_args": [
                        "plan",
                        "--base-checkpoint",
                        "fdtn-ai/Foundation-Sec-8B-Reasoning",
                        "--license",
                        "Apache-2.0",
                        "--domain",
                        "cyber",
                        "--limit",
                        "5",
                        "--output",
                        str(root / "skill_qlora.json"),
                    ],
                    "bad_limit_args": [
                        "plan",
                        "--limit",
                        "0",
                        "--output",
                        str(root / "unused4.json"),
                    ],
                    "sym_args": [
                        "plan",
                        "--limit",
                        "5",
                        "--output",
                        str(sym_out),
                    ],
                    "expected_out": root / "skill_qlora.json",
                    "assert_key": "mlx_qlora_config",
                },
                {
                    "script": SKILLS_ROOT / "agy-local-agent-runner" / "scripts" / "run_agy_agent.py",
                    "ok_args": [
                        "discover",
                        "--skills-paths",
                        str(SKILLS_ROOT),
                        "--session-tainted",
                        "--limit",
                        "25",
                        "--output",
                        str(root / "skill_agy.json"),
                    ],
                    "bad_limit_args": [
                        "discover",
                        "--limit",
                        "0",
                        "--output",
                        str(root / "unused5.json"),
                    ],
                    "sym_args": [
                        "discover",
                        "--skills-paths",
                        str(SKILLS_ROOT),
                        "--limit",
                        "25",
                        "--output",
                        str(sym_out),
                    ],
                    "expected_out": root / "skill_agy.json",
                    "assert_key": "discovered_skill_count",
                },
            ]

            for case in cases:
                script_str = str(case["script"])
                help_proc = _run_py([script_str, "--help"])
                self.assertEqual(help_proc.returncode, 0, msg=f"--help failed for {script_str}: {help_proc.stderr}")

                bad_proc = _run_py([script_str, *case["bad_limit_args"]])
                self.assertNotEqual(bad_proc.returncode, 0, msg=f"--limit 0 should fail for {script_str}")

                ok_proc = _run_py([script_str, *case["ok_args"]])
                self.assertEqual(ok_proc.returncode, 0, msg=f"Run failed for {script_str}: {ok_proc.stderr}")
                out_path: Path = case["expected_out"]
                self.assertTrue(out_path.is_file(), msg=f"Missing output JSON for {script_str}")
                payload = json.loads(out_path.read_text(encoding="utf-8"))
                self.assertIn(case["assert_key"], payload)

                sym_proc = _run_py([script_str, *case["sym_args"]])
                self.assertNotEqual(sym_proc.returncode, 0, msg=f"Symlink --output should fail for {script_str}")
                self.assertEqual(sym_target.read_text(encoding="utf-8"), '{"keep": true}\n')

            # SEC-02: run_agy_agent.py defaults to session_tainted=True even without --tainted
            agy_default_out = root / "agy_default.json"
            agy_default_proc = _run_py(
                [
                    str(SKILLS_ROOT / "agy-local-agent-runner" / "scripts" / "run_agy_agent.py"),
                    "discover",
                    "--skills-paths",
                    str(SKILLS_ROOT),
                    "--limit",
                    "30",
                    "--output",
                    str(agy_default_out),
                ]
            )
            self.assertEqual(agy_default_proc.returncode, 0, msg=agy_default_proc.stderr)
            agy_default_data = json.loads(agy_default_out.read_text(encoding="utf-8"))
            self.assertTrue(agy_default_data["session_tainted"])
            self.assertNotIn("vuln_sync_live_feeds", {t["name"] for t in agy_default_data["tools"]})

            # SEC-02: --clean explicitly forwards --clean in mcp-config args and exposes vuln_sync_live_feeds
            agy_clean_out = root / "agy_clean_cfg.json"
            agy_clean_proc = _run_py(
                [
                    str(SKILLS_ROOT / "agy-local-agent-runner" / "scripts" / "run_agy_agent.py"),
                    "mcp-config",
                    "--clean",
                    "--limit",
                    "30",
                    "--output",
                    str(agy_clean_out),
                ]
            )
            self.assertEqual(agy_clean_proc.returncode, 0, msg=agy_clean_proc.stderr)
            agy_clean_data = json.loads(agy_clean_out.read_text(encoding="utf-8"))
            self.assertFalse(agy_clean_data["session_tainted"])
            self.assertIn("vuln_sync_live_feeds", agy_clean_data["enabled_tools"])
            self.assertIn("--clean", agy_clean_data["mcp_stdio_config"]["args"])

            # SEC-05: run_agy_agent.py mcp-serve --request-file enforces bounded line reads
            req_file = root / "batch_rpc.jsonl"
            req_file.write_text(
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})
                + "\n"
                + ("A" * (MAX_JSONRPC_LINE_BYTES + 64))
                + "\n",
                encoding="utf-8",
            )
            batch_out = root / "batch_rpc_out.json"
            batch_proc = _run_py(
                [
                    str(SKILLS_ROOT / "agy-local-agent-runner" / "scripts" / "run_agy_agent.py"),
                    "mcp-serve",
                    "--request-file",
                    str(req_file),
                    "--limit",
                    "5",
                    "--output",
                    str(batch_out),
                ]
            )
            self.assertEqual(batch_proc.returncode, 0, msg=batch_proc.stderr)
            batch_data = json.loads(batch_out.read_text(encoding="utf-8"))
            self.assertEqual(batch_data["response_count"], 2)
            self.assertEqual(batch_data["responses"][1]["error"]["code"], -32600)

            # SEC-07: train_scratch_slm.py generate returns non-empty model_id
            slm_manifest = json.loads((root / "skill_slm.json").read_text(encoding="utf-8"))["manifest_path"]
            gen_out = root / "skill_gen.json"
            gen_proc = _run_py(
                [
                    str(SKILLS_ROOT / "scratch-slm-trainer" / "scripts" / "train_scratch_slm.py"),
                    "generate",
                    "--manifest",
                    slm_manifest,
                    "--prompt",
                    "def ",
                    "--limit",
                    "4",
                    "--output",
                    str(gen_out),
                ]
            )
            self.assertEqual(gen_proc.returncode, 0, msg=gen_proc.stderr)
            gen_data = json.loads(gen_out.read_text(encoding="utf-8"))
            self.assertEqual(gen_data["model_id"], "skill-micro-slm")


if __name__ == "__main__":
    unittest.main()
