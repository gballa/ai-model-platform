"""Unified CLI Entrypoint for the Proprietary Technical Intelligence Platform (`platform-cli`).

Provides subcommands for the end-to-end platform and custom model lifecycle:
- `evaluate-blueprint`: Audits the 4-Pool model lineup, license compliance, hardware break-even,
  and PropBench-9 readiness.
- `train-model` / `create-custom-model`: Runs the 5-Stage Model Creation & Post-Training Pipeline
  (Data Factories -> Decontamination -> FSDP2/ZeRO-3 Spec -> MOPD -> Critic-Free GRPO+RLVR -> DPO ->
  Safetensors Checkpoint -> Canary Gate) and optionally saves `.safetensors` + `.manifest.json`.
- `run-workflow` / `run-custom-model`: Executes the 10-step checkpointed agent lifecycle inside a
  Firecracker microVM with `IndependentVerifierAgent` gating using either built-in or custom models.
- `inspect-data`: Runs the Domain D transformation classifier and synthesizes a Kaitai `.ksy` schema.
- `harvest-corpus`: Harvests technical PDFs/books and firewall-approved URLs into RAG / distilled JSONL.
- `recommend-strategy`: Advises pre-trained RAG/QLoRA vs. compact from-scratch SLM vs. multi-GPU.
- `train-scratch-slm`: Trains a byte-level BPE tokenizer and compact causal Transformer to `.safetensors`.
- `run-agy-local`: Runs a local Google Antigravity SDK (or stdlib fallback) agent with SecVerifier gating.
- `mcp-stdio-bridge`: Serves `platform_core` MCP tools over newline-delimited JSON-RPC 2.0 stdio.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import math
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

from platform_core.layer1_intelligence.inference import ModelDownloadManager
from platform_core.layer1_intelligence.models import (
    HardwareFeasibilityPlanner,
    LocalHardwareDetector,
    ModelPool,
    ModelRegistry,
)
from platform_core.layer1_intelligence.serving import RadixPrefixCacheSimulator
from platform_core.layer1_intelligence.training import (
    CustomModelConfig,
    CustomModelPipeline,
)
from platform_core.layer2_execution.forensics_mcp import ForensicsMCPServer
from platform_core.layer2_execution.mcp_tools import (
    DataAndVisualMCPServer,
    DefensiveCyberMCPServer,
    VisualRegionObservation,
)
from platform_core.layer2_execution.orchestrator import ExecutionLifecycleOrchestrator
from platform_core.layer2_execution.vuln_intel_mcp import VulnIntelMCPServer
from platform_core.layer3_evolution.evaluation import BenchmarkSuiteRunner, PropBench9Suite


def run_evaluate_blueprint(budget_usd: int = 1_800_000) -> dict[str, Any]:
    """Evaluate the deep research architecture, model licenses, hardware ROI, and PropBench-9."""
    registry = ModelRegistry()
    models = registry.all_models()
    serving_configs = RadixPrefixCacheSimulator.build_default_pool_configs(models)
    scenario_rec = HardwareFeasibilityPlanner.recommend_scenario(
        annual_budget_usd=budget_usd,
        require_full_weight_rlvr=True,
    )
    break_even_months = HardwareFeasibilityPlanner.calculate_gpu_break_even_months(
        hardware_capex_usd=470_000.0,
        monthly_power_hosting_usd=2_500.0,
        cloud_hourly_rate_usd=38.0,
        utilization_ratio=0.85,
    )
    return {
        "architecture": "Three-Layer Hybrid Technical Intelligence Platform",
        "registered_models": [
            {
                "model_id": m.model_id,
                "pool": m.pool.value,
                "total_params_b": m.total_params_b,
                "active_params_b": m.active_params_b,
                "license": m.license_id,
                "vram_fp8_gb": m.vram_fp8_gb,
            }
            for m in models
        ],
        "serving_endpoints": len(serving_configs),
        "recommended_scenario": scenario_rec["recommended_scenario"],
        "pretrain_from_scratch_justified": scenario_rec["pretrain_from_scratch_justified"],
        "gpu_ownership_break_even_months": break_even_months,
        "propbench_9_suites": [s.bench_id for s in PropBench9Suite.all_specs()],
    }


def run_model_creation_pipeline(
    model_id: str = "Qwen3.8-27B-SWE-Cyber-v1.0",
    base_checkpoint: str = "Qwen/Qwen3.8-27B",
    domain: str = "swe",
    pool: str | None = None,
    total_params_b: float = 27.8,
    active_params_b: float | None = None,
    context_window: int = 262_144,
    license_id: str = "Apache-2.0",
    output_dir: str | Path | None = None,
    dataset_file: str | Path | None = None,
    execution_mode: str = "spec_only",
    lora_rank: int = 16,
    training_iters: int = 200,
) -> dict[str, Any]:
    """Execute the 5-Stage Model Creation & Post-Training Pipeline (CPT -> SFT -> MOPD -> GRPO/RLVR -> DPO)."""
    custom_trajectories = (
        CustomModelPipeline.load_trajectories_from_file(dataset_file)
        if dataset_file is not None
        else None
    )
    resolved_pool = ModelPool(pool) if pool is not None else None
    config = CustomModelConfig(
        model_id=model_id,
        base_checkpoint=base_checkpoint,
        domain=domain,
        pool=resolved_pool,
        total_params_b=total_params_b,
        active_params_b=active_params_b,
        context_window=context_window,
        license_id=license_id,
        execution_mode=execution_mode,
        lora_rank=lora_rank,
        training_iters=training_iters,
    )
    artifact = CustomModelPipeline.build_custom_model(
        config=config,
        custom_trajectories=custom_trajectories,
        output_dir=output_dir,
    )
    metrics = artifact.training_metrics
    result: dict[str, Any] = {
        "model_id": artifact.model_spec.model_id,
        "base_checkpoint": artifact.model_spec.base_checkpoint,
        "pool": artifact.model_spec.pool.value,
        "license": artifact.model_spec.license_id,
        "accepted_training_trajectories": metrics["accepted_training_trajectories"],
        "sharding_backend": metrics["sharding_backend"],
        "mopd_kl_loss": metrics["mopd_kl_loss"],
        "grpo_step_metrics": metrics["grpo_step_metrics"],
        "dpo_step_metrics": metrics["dpo_step_metrics"],
        "binrev_reward_breakdown": metrics["binrev_reward_breakdown"],
        "checkpoint_verified": metrics["checkpoint_verified"],
        "checkpoint_sha256": artifact.checkpoint_sha256,
        "canary_promoted": artifact.canary_evaluation["promoted"],
        "canary_gains": artifact.canary_evaluation["significant_target_gains"],
        "serving_launch_args": list(artifact.serving_launch_args),
    }
    if artifact.safetensors_path is not None:
        result["safetensors_path"] = artifact.safetensors_path
        result["manifest_path"] = artifact.manifest_path
    return result


def _load_custom_workflow_payload(
    payload_file: str | Path,
    default_domain: str,
) -> tuple[str, str, str, dict[str, str | bytes], dict[str, Any]]:
    """Load custom workflow objective, workspace_files, and task_payload from a JSON file."""
    path = Path(payload_file)
    if path.is_symlink():
        raise PermissionError(f"Symlinked workflow payload file rejected: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"Workflow payload file not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Workflow payload file must contain a JSON object: {path}")

    domain = str(raw.get("domain", default_domain)).lower().strip()
    if domain not in CustomModelPipeline.VALID_DOMAINS:
        raise ValueError(
            f"Unsupported workflow domain '{domain}' in {path}: must be one of {sorted(CustomModelPipeline.VALID_DOMAINS)}."
        )
    session_id = str(raw.get("session_id", f"cli-{domain}-custom-session")).strip()
    objective = str(raw.get("objective", f"Execute custom {domain} workflow"))
    ws_raw = raw.get("workspace_files")
    if ws_raw is not None and not isinstance(ws_raw, dict):
        raise ValueError(f"'workspace_files' in {path} must be a JSON object.")
    workspace_files: dict[str, str | bytes] = {str(k): str(v) for k, v in (ws_raw or {}).items()}
    tp_raw = raw.get("task_payload")
    if tp_raw is not None and not isinstance(tp_raw, dict):
        raise ValueError(f"'task_payload' in {path} must be a JSON object.")
    task_payload: dict[str, Any] = dict(tp_raw or {})

    if "binary_payload_hex" in task_payload:
        task_payload["binary_payload"] = bytes.fromhex(str(task_payload.pop("binary_payload_hex")))
    if "sample_payload_hex" in task_payload:
        task_payload["sample_payload"] = bytes.fromhex(str(task_payload.pop("sample_payload_hex")))
    if "magic_bytes_hex" in task_payload:
        task_payload["magic_bytes"] = bytes.fromhex(str(task_payload.pop("magic_bytes_hex")))
    elif isinstance(task_payload.get("magic_bytes"), str):
        task_payload["magic_bytes"] = task_payload["magic_bytes"].encode("utf-8")
    if isinstance(task_payload.get("sample_payload"), str):
        task_payload["sample_payload"] = task_payload["sample_payload"].encode("utf-8")

    if "visual_regions" in task_payload:
        raw_regions = task_payload["visual_regions"]
        if not isinstance(raw_regions, list):
            raise ValueError(f"'visual_regions' in {path} must be a list.")
        parsed_regions: list[VisualRegionObservation] = []
        for idx, reg in enumerate(raw_regions):
            if isinstance(reg, VisualRegionObservation):
                parsed_regions.append(reg)
            elif isinstance(reg, dict):
                raw_bbox = reg.get("bbox") or reg.get("bbox_xyxy") or (0, 0, 0, 0)
                if not isinstance(raw_bbox, (list, tuple)) or len(raw_bbox) != 4:
                    raise ValueError(f"Invalid visual region bbox at index {idx} in {path}: {raw_bbox!r}")
                parsed_regions.append(
                    VisualRegionObservation(
                        region_id=int(reg.get("region_id", idx + 1)),
                        bbox=(int(raw_bbox[0]), int(raw_bbox[1]), int(raw_bbox[2]), int(raw_bbox[3])),
                        ocr_text=str(reg.get("ocr_text", "")),
                        confidence=float(reg.get("confidence", 0.0)),
                        is_obscured_or_low_res=bool(reg.get("is_obscured_or_low_res", False)),
                    )
                )
            else:
                raise ValueError(f"Visual region at index {idx} in {path} must be an object.")
        task_payload["visual_regions"] = parsed_regions

    return session_id, objective, domain, workspace_files, task_payload


def run_demo_workflow(
    domain: str | None = None,
    model_id: str | None = None,
    manifest_path: str | Path | None = None,
    payload_file: str | Path | None = None,
) -> dict[str, Any]:
    """Execute a 10-step agent workflow inside a Firecracker sandbox and return the verified state."""
    orchestrator = ExecutionLifecycleOrchestrator()
    try:
        effective_domain = domain.lower().strip() if domain is not None else None
        effective_model_id = model_id

        if manifest_path is not None:
            loaded = CustomModelPipeline.load_custom_model_manifest(
                manifest_path=manifest_path,
                registry=orchestrator.router.registry,
                set_as_pool_default=True,
            )
            if effective_model_id is None:
                effective_model_id = loaded["model_spec"].model_id
            manifest_domain = str(loaded["manifest"].get("domain", "")).lower().strip()
            if effective_domain is None and manifest_domain in CustomModelPipeline.VALID_DOMAINS:
                effective_domain = manifest_domain

        if effective_domain is None:
            effective_domain = "swe"
        if effective_domain not in CustomModelPipeline.VALID_DOMAINS:
            raise ValueError(
                f"Unsupported workflow domain '{effective_domain}': must be one of {sorted(CustomModelPipeline.VALID_DOMAINS)}."
            )

        if payload_file is not None:
            session_id, objective, effective_domain, workspace_files, task_payload = (
                _load_custom_workflow_payload(payload_file, effective_domain)
            )
            state = orchestrator.run_workflow(
                session_id=session_id,
                objective=objective,
                task_domain=effective_domain,
                workspace_files=workspace_files,
                task_payload=task_payload,
                preferred_model_id=effective_model_id,
            )
        elif effective_domain in {"swe", "architecture"}:
            state = orchestrator.run_workflow(
                session_id=f"cli-{effective_domain}-session",
                objective="Fix division-by-zero bug in metrics accumulator",
                task_domain=effective_domain,
                workspace_files={
                    "app.py": "def compute_rate(passed: int, total: int) -> float:\n    return passed / total\n"
                },
                task_payload={
                    "target_file": "app.py",
                    "old_str": "    return passed / total",
                    "new_str": "    return (passed / total) if total > 0 else 0.0",
                    "test_script": (
                        "from app import compute_rate\n"
                        "assert compute_rate(0, 0) == 0.0\n"
                        "assert compute_rate(3, 4) == 0.75\n"
                    ),
                },
                preferred_model_id=effective_model_id,
            )
        elif effective_domain == "cyber":
            state = orchestrator.run_workflow(
                session_id="cli-cyber-session",
                objective="Remediate CWE-78 command injection in ping handler",
                task_domain="cyber",
                workspace_files={
                    "service.py": (
                        "import subprocess\n"
                        "def run_check(host: str) -> int:\n"
                        "    return subprocess.call(f'ping -c 1 {host}', shell=True)\n"
                    )
                },
                task_payload={
                    "target_file": "service.py",
                    "old_str": "    return subprocess.call(f'ping -c 1 {host}', shell=True)",
                    "new_str": "    return subprocess.call(['ping', '-c', '1', host], shell=False)",
                    "poc_still_crashes": False,
                    "regression_tests_passed": 12,
                    "regression_tests_total": 12,
                },
                preferred_model_id=effective_model_id,
            )
        elif effective_domain == "binrev":
            state = orchestrator.run_workflow(
                session_id="cli-binrev-session",
                objective="Decompile stripped ELF function via SK2Decompile + ReCopilot",
                task_domain="binrev",
                task_payload={
                    "binary_payload": b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00",
                    "raw_pseudocode": (
                        "undefined8 FUN_00401000(undefined4 param_1) {\n"
                        "  goto LAB_00401010;\n"
                        "LAB_00401010:\n"
                        "  return param_1;\n"
                        "}"
                    ),
                    "callers": ["main"],
                    "callees": ["crc32_step"],
                    "dataflow_aliases": {"FUN_00401000": "verify_header_crc", "param_1": "hdr_len"},
                },
                preferred_model_id=effective_model_id,
            )
        elif effective_domain == "visual_ocr":
            state = orchestrator.run_workflow(
                session_id="cli-visualocr-session",
                objective="Ground UI/diagram bounding boxes with epistemic zoom calibration",
                task_domain="visual_ocr",
                task_payload={
                    "sample_payload": b"MAGIC\x01\x02",
                    "format_id": "telemetry_packet",
                    "magic_bytes": b"MAGIC",
                    "fields": [{"id": "body", "type": "u2", "size_bytes": 2}],
                    "visual_regions": [
                        VisualRegionObservation(1, (10, 10, 140, 45), "Ghidra CFG Node", 0.96, False),
                        VisualRegionObservation(2, (200, 300, 260, 330), "0x401???", 0.42, True),
                    ],
                },
                preferred_model_id=effective_model_id,
            )
        elif effective_domain == "vuln_intel":
            state = orchestrator.run_workflow(
                session_id="cli-vulnintel-session",
                objective="Audit project dependencies and CPG findings against vulnerability feeds",
                task_domain="vuln_intel",
                workspace_files={
                    "requirements.txt": "requests==2.32.3\n",
                    "handler.py": "def health_check() -> str:\n    return 'ok'\n",
                },
                task_payload={},
                preferred_model_id=effective_model_id,
            )
        elif effective_domain == "forensics":
            state = orchestrator.run_workflow(
                session_id="cli-forensics-session",
                objective="Triage sample artifact bundle for STIX2 spyware indicators without fabrication",
                task_domain="forensics",
                workspace_files={
                    "Shutdown.log": "2026-10-01T08:00:00Z SIGTERM SpringBoard\n",
                },
                task_payload={"platform": "ios"},
                preferred_model_id=effective_model_id,
            )
        else:
            state = orchestrator.run_workflow(
                session_id="cli-dataprotocol-session",
                objective="Synthesize Kaitai .ksy schema for binary packet",
                task_domain="data_protocol",
                task_payload={
                    "sample_payload": b"MAGIC\x01\x02",
                    "format_id": "telemetry_packet",
                    "magic_bytes": b"MAGIC",
                    "fields": [{"id": "body", "type": "u2", "size_bytes": 2}],
                    "visual_regions": [],
                },
                preferred_model_id=effective_model_id,
            )

        return {
            "session_id": state.session_id,
            "status": state.status.value,
            "current_step": int(state.current_step),
            "taint_level": state.taint_level.value,
            "routed_model_id": state.routing_summary.get("primary_model"),
            "selected_pool": state.routing_summary.get("selected_pool"),
            "thinking_mode": state.routing_summary.get("thinking_mode"),
            "max_thinking_tokens_per_turn": state.routing_summary.get("max_thinking_tokens_per_turn"),
            "verified_by": state.final_deliverable.get("verified_by"),
            "consolidated_memory_event_id": state.final_deliverable.get("consolidated_memory_event_id"),
            "telemetry_span_count": len(state.telemetry_spans),
            "deliverable_outputs": state.final_deliverable.get("subtask_outputs", {}),
        }
    finally:
        orchestrator.close()


def _require_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer, got {value!r}.")
    return value


def _require_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer, got {value!r}.")
    return value


def _require_positive_float(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a positive number, got {value!r}.")
    fval = float(value)
    if math.isnan(fval) or math.isinf(fval) or fval <= 0.0:
        raise ValueError(f"{field_name} must be a finite positive number, got {value!r}.")
    return fval


def _positive_int_arg(raw: str) -> int:
    try:
        val = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected positive integer, got {raw!r}.") from exc
    if val <= 0:
        raise argparse.ArgumentTypeError(f"Expected positive integer (> 0), got {val}.")
    return val


def _non_negative_int_arg(raw: str) -> int:
    try:
        val = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected non-negative integer, got {raw!r}.") from exc
    if val < 0:
        raise argparse.ArgumentTypeError(f"Expected non-negative integer (>= 0), got {val}.")
    return val


def _positive_float_arg(raw: str) -> float:
    try:
        val = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected positive number, got {raw!r}.") from exc
    if math.isnan(val) or math.isinf(val) or val <= 0.0:
        raise argparse.ArgumentTypeError(f"Expected finite positive number (> 0), got {val!r}.")
    return val


def _validate_safe_file_target(path_value: str | Path, label: str) -> Path:
    dest = Path(path_value)
    if dest.is_symlink():
        raise PermissionError(f"Symlinked {label} rejected: {dest}")
    if dest.parent.exists() and dest.parent.is_symlink():
        raise PermissionError(f"Symlinked parent directory for {label} rejected: {dest.parent}")
    return dest


def _write_json_output(output_path: str | Path, payload: dict[str, Any]) -> str:
    dest = _validate_safe_file_target(output_path, "output path")
    dest.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=dest.parent,
            prefix=".cli_out_",
            suffix=".json",
            delete=False,
        ) as tmp_fh:
            tmp_path = Path(tmp_fh.name)
            tmp_fh.write(raw)
        os.replace(tmp_path, dest)
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise
    return str(dest)


def _add_taint_flags(parser: argparse.ArgumentParser, default_tainted: bool) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--tainted",
        dest="session_tainted",
        action="store_true",
        help="Mark session TAINTED_UNTRUSTED (enforces internal network & blocks egress/admin tools).",
    )
    group.add_argument(
        "--clean",
        dest="session_tainted",
        action="store_false",
        help="Mark session CLEAN (allows allowlisted read-only egress where permitted).",
    )
    parser.set_defaults(session_tainted=default_tainted)


def run_harvest_corpus(
    pdf_paths: list[str | Path] | None = None,
    book_dirs: list[str | Path] | None = None,
    urls: list[str] | None = None,
    domain: str = "swe",
    license_id: str = "Apache-2.0",
    limit: int = 50,
    allowed_domains: list[str] | None = None,
    requests_per_second: float = 1.0,
    distill_output: str | Path | None = None,
    teacher_model_id: str = "Qwen/Qwen3.5-35B-A3B",
    teacher_license_id: str = "Apache-2.0",
    max_samples_per_doc: int = 3,
    session_tainted: bool = False,
    ingest_into_rag: bool = True,
    rag_db_path: str | Path = ":memory:",
) -> dict[str, Any]:
    """Harvest PDFs/books and firewall-approved URLs, sanitize, index in RAG, and optionally distill."""
    limit = _require_positive_int(limit, "limit")
    max_samples_per_doc = _require_positive_int(max_samples_per_doc, "max_samples_per_doc")
    requests_per_second = _require_positive_float(requests_per_second, "requests_per_second")

    pdfs = list(pdf_paths or [])
    dirs = list(book_dirs or [])
    url_list = list(urls or [])
    if not pdfs and not dirs and not url_list:
        raise ValueError("Provide at least one --pdf, --book-dir, or --url source.")

    if str(rag_db_path) != ":memory:":
        _validate_safe_file_target(rag_db_path, "rag_db_path")
    if distill_output is not None:
        _validate_safe_file_target(distill_output, "distill_output")

    from platform_core.layer1_intelligence.inference import DeterministicMockBackend
    from platform_core.layer3_evolution.corpus_harvester import (
        CorpusHarvesterPipeline,
        HarvestedDocument,
        PDFBookExtractor,
        RateLimitedWebHarvester,
        TeacherDistiller,
    )
    from platform_core.layer3_evolution.memory import HybridKnowledgeStore

    bounded_pdfs = pdfs[:limit]
    remaining = max(0, limit - len(bounded_pdfs))
    bounded_dirs = dirs if remaining > 0 else []
    bounded_urls = url_list[:remaining] if remaining > 0 else []

    class _BoundedPDFBookExtractor(PDFBookExtractor):
        def __init__(self, max_files_limit: int) -> None:
            super().__init__()
            self._max_files_limit = max_files_limit
            self._consumed = 0

        def extract_directory(
            self,
            root_dir: str | Path,
            domain: str = "swe",
            license_id: str = "Apache-2.0",
            max_files: int = 50,
        ) -> list[HarvestedDocument]:
            budget = max(0, self._max_files_limit - self._consumed)
            if budget == 0:
                return []
            docs = super().extract_directory(
                root_dir,
                domain=domain,
                license_id=license_id,
                max_files=min(max_files, budget),
            )
            self._consumed += len(docs)
            return docs

    pdf_extractor = _BoundedPDFBookExtractor(max_files_limit=max(1, remaining))
    web_harvester = RateLimitedWebHarvester(
        allowed_domains=set(allowed_domains) if allowed_domains else None,
        requests_per_second=requests_per_second,
        session_tainted=session_tainted,
    )
    store = HybridKnowledgeStore(rag_db_path)
    try:
        with CorpusHarvesterPipeline(
            knowledge_store=store,
            web_harvester=web_harvester,
            pdf_extractor=pdf_extractor,
        ) as pipeline:
            remaining_after_dirs = max(0, remaining - pdf_extractor._consumed)
            report = pipeline.run_harvest(
                pdf_paths=bounded_pdfs,
                book_dirs=bounded_dirs,
                urls=bounded_urls[:remaining_after_dirs],
                domain=domain,
                license_id=license_id,
                session_tainted=session_tainted,
                ingest_into_rag=ingest_into_rag,
            )
    finally:
        store.close()

    result: dict[str, Any] = {
        "domain": domain,
        "license_id": license_id,
        "session_tainted": bool(session_tainted),
        "limit": limit,
        "documents_harvested": len(report.documents),
        "total_chunks": report.total_chunks,
        "total_tokens_est": report.total_tokens_est,
        "rejected_sources": list(report.rejected_sources),
        "rag_ingestion_stats": report.rag_ingestion_stats,
        "documents": [
            {
                "doc_id": doc.doc_id,
                "source_uri": doc.source_uri,
                "source_type": doc.source_type,
                "title": doc.title,
                "sha256": doc.sha256,
                "chunk_count": len(doc.chunks),
                "injection_alerts": list(doc.injection_alerts),
            }
            for doc in report.documents
        ],
    }

    if distill_output is not None:
        distiller = TeacherDistiller(
            backend=DeterministicMockBackend(),
            teacher_model_id=teacher_model_id,
            teacher_license_id=teacher_license_id,
        )
        records = distiller.synthesize_trajectories(
            list(report.documents),
            target_domain=domain,
            max_samples_per_doc=max_samples_per_doc,
        )
        result["distillation"] = distiller.export_distilled_jsonl(records, distill_output)

    return result


def run_recommend_strategy(
    corpus_tokens: int,
    domain: str = "swe",
    custom_vocab_required: bool = False,
    target_params_m: float | None = None,
) -> dict[str, Any]:
    """Recommend pre-trained RAG/QLoRA-first vs. compact scratch SLM vs. multi-GPU."""
    corpus_tokens = _require_non_negative_int(corpus_tokens, "corpus_tokens")
    params_m_int: int | None = None
    if target_params_m is not None:
        validated_params = _require_positive_float(target_params_m, "target_params_m")
        params_m_int = int(validated_params) if validated_params.is_integer() else max(1, round(validated_params))

    from platform_core.layer1_intelligence.scratch_trainer import CreationStrategyAdvisor

    rec = CreationStrategyAdvisor.recommend(
        corpus_tokens=corpus_tokens,
        domain=domain,
        custom_vocab_required=bool(custom_vocab_required),
        target_params_m=params_m_int,
    )
    return {
        "recommended_path": rec.recommended_path.value,
        "base_model_id": rec.base_model_id,
        "rationale": rec.rationale,
        "hardware_summary": rec.hardware_summary,
        "estimated_vram_gb": rec.estimated_vram_gb,
        "fits_local_budget": rec.fits_local_budget,
        "warnings": list(rec.warnings),
    }


def _collect_scratch_corpus_texts(
    corpus_files: list[str | Path],
    corpus_dirs: list[str | Path],
    inline_texts: list[str],
    domain: str,
    license_id: str,
) -> list[str]:
    from platform_core.layer3_evolution.corpus_harvester import (
        PDFBookExtractor,
        PromptInjectionSanitizer,
    )

    texts: list[str] = []
    extractor = PDFBookExtractor()

    for raw_text in inline_texts:
        if raw_text and raw_text.strip():
            cleaned, _ = PromptInjectionSanitizer.sanitize(raw_text)
            if cleaned.strip():
                texts.append(cleaned)

    for file_item in corpus_files:
        fpath = Path(file_item)
        if fpath.is_symlink():
            raise PermissionError(f"Symlinked corpus_file rejected: {fpath}")
        if not fpath.is_file():
            raise FileNotFoundError(f"Corpus file not found: {fpath}")
        suffix = fpath.suffix.lower()
        if suffix in PDFBookExtractor.SUPPORTED_EXTENSIONS:
            doc = extractor.extract_book(fpath, domain=domain, license_id=license_id)
            if doc.sanitized_text.strip():
                texts.append(doc.sanitized_text)
        elif suffix == ".jsonl":
            for line in fpath.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    parts = [
                        str(obj[k])
                        for k in ("prompt_context", "target_completion", "text", "content")
                        if isinstance(obj.get(k), str) and obj[k].strip()
                    ]
                    joined = "\n".join(parts)
                else:
                    joined = str(obj)
                cleaned, _ = PromptInjectionSanitizer.sanitize(joined)
                if cleaned.strip():
                    texts.append(cleaned)
        else:
            raw = fpath.read_text(encoding="utf-8")
            cleaned, _ = PromptInjectionSanitizer.sanitize(raw)
            if cleaned.strip():
                texts.append(cleaned)

    for dir_item in corpus_dirs:
        docs = extractor.extract_directory(dir_item, domain=domain, license_id=license_id)
        for doc in docs:
            if doc.sanitized_text.strip():
                texts.append(doc.sanitized_text)

    if not any(t.strip() for t in texts):
        raise ValueError("No non-empty corpus texts collected from --corpus-file, --corpus-dir, or --text.")
    return texts


def run_train_scratch_slm(
    model_id: str = "custom-scratch-slm",
    corpus_files: list[str | Path] | None = None,
    corpus_dirs: list[str | Path] | None = None,
    inline_texts: list[str] | None = None,
    output_dir: str | Path = "models/scratch_slm",
    tier: str | None = None,
    steps: int | None = None,
    d_model: int | None = None,
    n_layers: int | None = None,
    n_heads: int | None = None,
    d_ff: int | None = None,
    vocab_size: int | None = None,
    max_seq_len: int | None = None,
    batch_size: int | None = None,
    learning_rate: float | None = None,
    seed: int | None = None,
    execution_backend: str = "auto",
    license_id: str = "Apache-2.0",
    domain: str = "swe",
    sample_prompt: str | None = None,
    max_new_tokens: int = 16,
) -> dict[str, Any]:
    """Train a byte-level BPE tokenizer and compact causal Transformer SLM to Safetensors."""
    max_new_tokens = _require_positive_int(max_new_tokens, "max_new_tokens")
    corpus_texts = _collect_scratch_corpus_texts(
        corpus_files=list(corpus_files or []),
        corpus_dirs=list(corpus_dirs or []),
        inline_texts=list(inline_texts or []),
        domain=domain,
        license_id=license_id,
    )

    from platform_core.layer1_intelligence.scratch_trainer import (
        CompactTransformerSLMTrainer,
        ScratchSLMConfig,
    )

    if tier is not None:
        config = ScratchSLMConfig.preset_tier(model_id=model_id, tier=tier, domain=domain)
    else:
        config = ScratchSLMConfig(model_id=model_id, domain=domain)

    overrides: dict[str, Any] = {
        "license_id": license_id,
        "execution_backend": execution_backend,
    }
    int_overrides = {
        "steps": steps,
        "d_model": d_model,
        "n_layers": n_layers,
        "n_heads": n_heads,
        "d_ff": d_ff,
        "vocab_size": vocab_size,
        "max_seq_len": max_seq_len,
        "batch_size": batch_size,
    }
    for key, val in int_overrides.items():
        if val is not None:
            overrides[key] = _require_positive_int(val, key)
    if seed is not None:
        overrides["seed"] = _require_non_negative_int(seed, "seed")
    if learning_rate is not None:
        overrides["learning_rate"] = _require_positive_float(learning_rate, "learning_rate")

    config = replace(config, **overrides)
    trainer = CompactTransformerSLMTrainer()
    artifact = trainer.train_and_export(config=config, corpus_texts=corpus_texts, output_dir=output_dir)

    result: dict[str, Any] = {
        "model_id": artifact.model_id,
        "domain": config.domain,
        "license_id": config.license_id,
        "param_count": artifact.param_count,
        "vocab_size": artifact.vocab_size,
        "backend_used": artifact.backend_used,
        "initial_loss": artifact.initial_loss,
        "final_loss": artifact.final_loss,
        "loss_history": list(artifact.loss_history),
        "safetensors_path": artifact.safetensors_path,
        "tokenizer_path": artifact.tokenizer_path,
        "manifest_path": artifact.manifest_path,
        "checkpoint_sha256": artifact.checkpoint_sha256,
    }
    if sample_prompt is not None:
        result["sample_prompt"] = sample_prompt
        result["sample_generation"] = CompactTransformerSLMTrainer.generate_sample(
            manifest_path=artifact.manifest_path,
            prompt=sample_prompt,
            max_new_tokens=max_new_tokens,
        )
    return result


def run_agy_local_command(
    agent_name: str = "local-sec-swe-agent",
    prompt: str = "",
    runtime_kind: str = "local_openai",
    model_or_path: str = "Qwen/Qwen3.5-35B-A3B",
    base_url: str | None = "http://127.0.0.1:8080/v1",
    litert_backend: str = "gpu",
    skills_dirs: list[str] | None = None,
    mcp_servers: list[str] | None = None,
    max_subagent_depth: int = 2,
    session_tainted: bool = True,
    force_fallback: bool = False,
) -> dict[str, Any]:
    """Run a local AGY SDK agent (or deterministic stdlib fallback) gated by SecVerifier."""
    max_subagent_depth = _require_non_negative_int(max_subagent_depth, "max_subagent_depth")

    from platform_core.layer2_execution.agy_sdk_bridge import (
        AgyLocalAgentSpec,
        AgyLocalOrchestrator,
        AgyStdioMCPBridge,
    )

    mcp_configs: tuple[dict[str, Any], ...] = ()
    if mcp_servers:
        AgyStdioMCPBridge._validate_server_names(mcp_servers)
        mcp_configs = (
            AgyStdioMCPBridge.build_mcp_stdio_config(
                server_names=mcp_servers,
                session_tainted=session_tainted,
            ),
        )

    spec = AgyLocalAgentSpec(
        agent_name=agent_name,
        runtime_kind=runtime_kind,
        model_or_path=model_or_path,
        base_url=base_url if runtime_kind == "local_openai" else None,
        litert_backend=litert_backend,
        skills_paths=tuple(skills_dirs) if skills_dirs else (".agents/skills",),
        mcp_servers=mcp_configs,
        max_subagent_depth=max_subagent_depth,
        session_tainted=session_tainted,
    )
    orchestrator = AgyLocalOrchestrator()
    exec_result = orchestrator.run_local_agent(
        spec=spec,
        prompt=prompt,
        force_fallback=force_fallback,
    )
    return exec_result.to_dict()


def run_mcp_stdio_bridge(
    server_names: list[str] | None = None,
    vuln_db_path: str | Path = ":memory:",
    session_tainted: bool = True,
) -> int:
    """Serve `platform_core` MCP tools over newline-delimited JSON-RPC 2.0 stdin/stdout."""
    if str(vuln_db_path) != ":memory:":
        _validate_safe_file_target(vuln_db_path, "vuln_db_path")

    from platform_core.layer2_execution.agy_sdk_bridge import AgyStdioMCPBridge

    allowed_servers: set[str] | None = None
    if server_names:
        allowed_servers = AgyStdioMCPBridge._validate_server_names(server_names)

    with AgyStdioMCPBridge(vuln_db_path=vuln_db_path) as bridge:
        if allowed_servers is not None:
            bridge._tools = {
                name: tool
                for name, tool in bridge._tools.items()
                if tool.server in allowed_servers
            }
        bridge.serve_stdio(session_tainted=session_tainted)
    return 0


def _configure_train_parser(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--model-id",
        default="Qwen3.8-27B-SWE-Cyber-v1.0",
        help="Identifier for the custom model checkpoint",
    )
    p.add_argument(
        "--base-checkpoint",
        default="Qwen/Qwen3.8-27B",
        help="Base open-weight checkpoint used for post-training",
    )
    p.add_argument(
        "--domain",
        choices=sorted(CustomModelPipeline.VALID_DOMAINS),
        default="swe",
        help="Target specialist domain",
    )
    p.add_argument(
        "--pool",
        choices=[m.value for m in ModelPool],
        default=None,
        help="Explicit Layer 1 ModelPool override",
    )
    p.add_argument("--params-b", type=float, default=27.8, help="Total parameters in billions")
    p.add_argument(
        "--active-params-b",
        type=float,
        default=None,
        help="Active parameters in billions (defaults to --params-b)",
    )
    p.add_argument("--context-window", type=int, default=262_144, help="Maximum context length")
    p.add_argument(
        "--license",
        default="Apache-2.0",
        help="SPDX license identifier (must pass LicenseComplianceAuditor)",
    )
    p.add_argument(
        "--dataset-file",
        default=None,
        help="Optional path to custom JSON/JSONL training trajectories",
    )
    p.add_argument(
        "--output-dir",
        default=None,
        help="Optional directory to write <model-id>.safetensors and <model-id>.manifest.json",
    )
    p.add_argument(
        "--execution-mode",
        choices=["spec_only", "mlx_qlora", "torch_trl"],
        default="spec_only",
        help="Training execution backend mode",
    )
    p.add_argument("--lora-rank", type=int, default=16, help="LoRA adapter rank")
    p.add_argument("--training-iters", type=int, default=200, help="QLoRA training iterations")


def _configure_workflow_parser(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--domain",
        choices=sorted(CustomModelPipeline.VALID_DOMAINS),
        default=None,
        help="Workflow execution domain (defaults to manifest domain or 'swe')",
    )
    p.add_argument(
        "--model-id",
        default=None,
        help="Optional registered or custom model ID to route the workflow to",
    )
    p.add_argument(
        "--manifest",
        default=None,
        help="Optional path to a custom model <model-id>.manifest.json to load and execute",
    )
    p.add_argument(
        "--payload-file",
        default=None,
        help="Optional JSON file containing custom objective, workspace_files, and task_payload",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="platform-cli",
        description="Proprietary Technical Intelligence Platform CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    eval_p = sub.add_parser("evaluate-blueprint", help="Evaluate deep research architecture & ROI")
    eval_p.add_argument("--budget", type=int, default=1_800_000)

    train_p = sub.add_parser(
        "train-model",
        help="Run the 5-stage model creation & RLVR post-training pipeline",
    )
    _configure_train_parser(train_p)

    custom_train_p = sub.add_parser(
        "create-custom-model",
        help="Create, validate, and export a custom specialist model (.safetensors + .manifest.json)",
    )
    _configure_train_parser(custom_train_p)

    wf_p = sub.add_parser("run-workflow", help="Run the 10-step checkpointed agent workflow")
    _configure_workflow_parser(wf_p)

    custom_wf_p = sub.add_parser(
        "run-custom-model",
        help="Load a custom model manifest and execute a 10-step verified agent workflow",
    )
    _configure_workflow_parser(custom_wf_p)

    data_p = sub.add_parser("inspect-data", help="Classify transformation & synthesize Kaitai .ksy")
    data_p.add_argument("--hex", required=True, help="Hex-encoded payload bytes")

    sub.add_parser("hardware-check", help="Detect host CPU/GPU/Unified Memory & recommended model lineup")

    dl_p = sub.add_parser("download-model", help="Download a license-approved open-weight model from HuggingFace")
    dl_p.add_argument("--model-id", required=True, help="HuggingFace repo ID (e.g., Qwen/Qwen3.5-35B-A3B)")
    dl_p.add_argument("--license", default="Apache-2.0", help="Expected SPDX license identifier")
    dl_p.add_argument("--local-dir", default="models/custom_download", help="Local directory target")

    sync_p = sub.add_parser("sync-vuln-db", help="Sync public CISA KEV / FIRST EPSS / OSV feeds into SQLite mirror")
    sync_p.add_argument("--db-path", default="vuln_intel_mirror.db", help="Path to SQLite vulnerability mirror")
    sync_p.add_argument("--feeds", nargs="+", default=["kev", "epss"], help="Feeds to sync (kev epss osv)")

    for_p = sub.add_parser("scan-forensics", help="Triage iOS/Android/Host artifacts for spyware IOCs")
    for_p.add_argument("--target-dir", required=True, help="Directory containing backup or triage artifacts")
    for_p.add_argument("--platform", choices=["auto", "ios", "android", "host"], default="auto")
    for_p.add_argument("--stix-file", default=None, help="Optional STIX 2.x bundle JSON file to load")
    for_p.add_argument("--use-mvt-cli", action="store_true", help="Probe optional mvt-ios / mvt-android CLI")

    vuln_p = sub.add_parser("audit-vulns", help="Audit project dependencies & source code against vuln mirror")
    vuln_p.add_argument("--project-dir", required=True, help="Root directory of project to audit")
    vuln_p.add_argument("--db-path", default=":memory:", help="Path to SQLite vulnerability mirror")

    img_p = sub.add_parser("analyze-image", help="Inspect image or PDF visual artifact metadata & text")
    img_p.add_argument("--path", required=True, help="Path to image (.png/.jpg) or document (.pdf/.md/.txt)")
    img_p.add_argument("--prompt", default=None, help="Optional VLM analysis prompt")
    img_p.add_argument("--endpoint", default=None, help="Optional OpenAI-compatible VLM endpoint URL")

    bench_p = sub.add_parser("run-benchmarks", help="Execute live coding, reasoning, cyber, forensics, & epistemic benchmarks")
    bench_p.add_argument(
        "--suites",
        nargs="+",
        default=None,
        help="Optional subset of suites (coding reasoning cyber_vuln forensics hallucination_resistance)",
    )

    harvest_p = sub.add_parser(
        "harvest-corpus",
        help="Harvest PDFs/books and firewall-approved URLs into RAG and optional distilled JSONL",
    )
    harvest_p.add_argument("--pdf", action="extend", nargs="+", default=[], help="PDF/MD/TXT/RST book file(s)")
    harvest_p.add_argument("--book-dir", action="extend", nargs="+", default=[], help="Directory tree of books")
    harvest_p.add_argument("--url", action="extend", nargs="+", default=[], help="Approved HTTP/HTTPS URL(s)")
    harvest_p.add_argument("--domain", default="swe", help="Target domain label (default: swe)")
    harvest_p.add_argument("--license", default="Apache-2.0", help="SPDX license identifier")
    harvest_p.add_argument(
        "--limit",
        type=_positive_int_arg,
        default=50,
        help="Maximum number of sources/files to harvest (positive integer, default: 50)",
    )
    harvest_p.add_argument(
        "--allowed-domain",
        action="extend",
        nargs="+",
        default=None,
        help="Optional additional allowlisted hostname(s) for web harvesting",
    )
    harvest_p.add_argument(
        "--requests-per-second",
        type=_positive_float_arg,
        default=1.0,
        help="Rate limit for HTTP requests per second (default: 1.0)",
    )
    harvest_p.add_argument("--distill-output", default=None, help="Optional JSONL path for distilled trajectories")
    harvest_p.add_argument(
        "--teacher-model",
        default="Qwen/Qwen3.5-35B-A3B",
        help="Teacher model ID for trajectory distillation",
    )
    harvest_p.add_argument(
        "--teacher-license",
        default="Apache-2.0",
        help="Teacher model SPDX license ID",
    )
    harvest_p.add_argument(
        "--max-samples-per-doc",
        type=_positive_int_arg,
        default=3,
        help="Maximum distilled samples synthesized per document",
    )
    harvest_p.add_argument(
        "--no-ingest-rag",
        action="store_true",
        help="Skip ingesting harvested chunks into HybridKnowledgeStore",
    )
    harvest_p.add_argument("--rag-db-path", default=":memory:", help="SQLite path for HybridKnowledgeStore")
    harvest_p.add_argument("--output", default=None, help="Optional JSON output file path")
    _add_taint_flags(harvest_p, default_tainted=False)

    rec_p = sub.add_parser(
        "recommend-strategy",
        help="Recommend pre-trained RAG/QLoRA vs. compact from-scratch SLM vs. multi-GPU",
    )
    rec_p.add_argument(
        "--corpus-tokens",
        type=_non_negative_int_arg,
        required=True,
        help="Estimated corpus size in tokens",
    )
    rec_p.add_argument("--domain", default="swe", help="Target domain (e.g., swe, cyber, binrev, visual_ocr)")
    rec_p.add_argument(
        "--custom-vocab",
        action="store_true",
        help="Signal that a domain-owned custom tokenizer vocabulary is required",
    )
    rec_p.add_argument(
        "--target-params-m",
        type=_positive_float_arg,
        default=None,
        help="Optional explicit target parameter count in millions (e.g., 10, 50, 125, 350)",
    )
    rec_p.add_argument("--output", default=None, help="Optional JSON output file path")

    slm_p = sub.add_parser(
        "train-scratch-slm",
        help="Train a byte-level BPE tokenizer and compact causal Transformer SLM to .safetensors",
    )
    slm_p.add_argument("--model-id", default="custom-scratch-slm", help="Safe identifier for the scratch SLM")
    slm_p.add_argument(
        "--corpus-file",
        action="extend",
        nargs="+",
        default=[],
        help="Corpus file path(s) (.txt, .md, .rst, .pdf, .jsonl)",
    )
    slm_p.add_argument(
        "--corpus-dir",
        action="extend",
        nargs="+",
        default=[],
        help="Directory tree(s) containing corpus files",
    )
    slm_p.add_argument("--text", action="extend", nargs="+", default=[], help="Inline corpus text string(s)")
    slm_p.add_argument("--output-dir", default="models/scratch_slm", help="Directory for exported artifacts")
    slm_p.add_argument(
        "--tier",
        choices=["10M", "50M", "125M", "350M"],
        default=None,
        help="Optional architecture preset tier (omit for fast micro defaults)",
    )
    slm_p.add_argument("--steps", type=_positive_int_arg, default=None, help="SGD training steps override")
    slm_p.add_argument("--d-model", type=_positive_int_arg, default=None, help="Hidden width override")
    slm_p.add_argument("--n-layers", type=_positive_int_arg, default=None, help="Transformer layer count override")
    slm_p.add_argument("--n-heads", type=_positive_int_arg, default=None, help="Attention head count override")
    slm_p.add_argument("--d-ff", type=_positive_int_arg, default=None, help="MLP hidden width override")
    slm_p.add_argument("--vocab-size", type=_positive_int_arg, default=None, help="BPE vocabulary size (>= 260)")
    slm_p.add_argument("--max-seq-len", type=_positive_int_arg, default=None, help="Maximum sequence length override")
    slm_p.add_argument("--batch-size", type=_positive_int_arg, default=None, help="Batch size override")
    slm_p.add_argument("--learning-rate", type=_positive_float_arg, default=None, help="Learning rate override")
    slm_p.add_argument("--seed", type=_non_negative_int_arg, default=None, help="Deterministic RNG seed override")
    slm_p.add_argument(
        "--backend",
        choices=["auto", "stdlib", "mlx", "torch"],
        default="auto",
        help="Execution backend (default: auto)",
    )
    slm_p.add_argument("--license", default="Apache-2.0", help="SPDX license identifier")
    slm_p.add_argument("--domain", default="swe", help="Target domain label")
    slm_p.add_argument("--sample-prompt", default=None, help="Optional prompt to sample after export")
    slm_p.add_argument(
        "--max-new-tokens",
        type=_positive_int_arg,
        default=16,
        help="Maximum generated tokens when --sample-prompt is provided",
    )
    slm_p.add_argument("--output", default=None, help="Optional JSON output file path")

    agy_p = sub.add_parser(
        "run-agy-local",
        help="Execute a local Google Antigravity SDK agent (or stdlib fallback) with SecVerifier gating",
    )
    agy_p.add_argument("--agent-name", default="local-sec-swe-agent", help="Agent identifier")
    agy_p.add_argument("--prompt", required=True, help="Task prompt for the local agent")
    agy_p.add_argument(
        "--runtime",
        choices=["local_openai", "litert"],
        default="local_openai",
        help="Local AGY runtime kind (default: local_openai)",
    )
    agy_p.add_argument("--model", default="Qwen/Qwen3.5-35B-A3B", help="Model ID or LiteRT model path")
    agy_p.add_argument(
        "--base-url",
        default="http://127.0.0.1:8080/v1",
        help="OpenAI-compatible base URL when --runtime=local_openai",
    )
    agy_p.add_argument(
        "--litert-backend",
        choices=["gpu", "npu"],
        default="gpu",
        help="LiteRT accelerator backend when --runtime=litert",
    )
    agy_p.add_argument(
        "--skills-dir",
        action="extend",
        nargs="+",
        default=None,
        help="Skill directory path(s) to discover (default: .agents/skills)",
    )
    agy_p.add_argument(
        "--mcp-server",
        action="extend",
        nargs="+",
        default=None,
        help="Restrict bound MCP servers (data_visual, vuln_intel, forensics, code_graph, binrev, defensive_cyber)",
    )
    agy_p.add_argument(
        "--max-subagent-depth",
        type=_non_negative_int_arg,
        default=2,
        help="Maximum subagent delegation depth (default: 2)",
    )
    agy_p.add_argument(
        "--force-fallback",
        action="store_true",
        help="Force deterministic stdlib fallback even if google-antigravity is installed",
    )
    agy_p.add_argument("--output", default=None, help="Optional JSON output file path")
    _add_taint_flags(agy_p, default_tainted=True)

    mcp_p = sub.add_parser(
        "mcp-stdio-bridge",
        help="Serve platform_core MCP servers over newline-delimited JSON-RPC 2.0 stdin/stdout",
    )
    mcp_p.add_argument(
        "--server",
        action="extend",
        nargs="+",
        dest="servers_single",
        default=None,
        help="MCP server(s) to expose (data_visual, vuln_intel, forensics, code_graph, binrev, defensive_cyber)",
    )
    mcp_p.add_argument(
        "--servers",
        action="extend",
        nargs="+",
        dest="servers_multi",
        default=None,
        help="Alias for --server accepting one or more server names",
    )
    mcp_p.add_argument("--vuln-db-path", default=":memory:", help="Path to SQLite vulnerability mirror")
    _add_taint_flags(mcp_p, default_tainted=True)

    args = parser.parse_args(argv)

    if args.command == "evaluate-blueprint":
        result = run_evaluate_blueprint(budget_usd=args.budget)
    elif args.command in {"train-model", "create-custom-model"}:
        result = run_model_creation_pipeline(
            model_id=args.model_id,
            base_checkpoint=args.base_checkpoint,
            domain=args.domain,
            pool=args.pool,
            total_params_b=args.params_b,
            active_params_b=args.active_params_b,
            context_window=args.context_window,
            license_id=args.license,
            output_dir=args.output_dir,
            dataset_file=args.dataset_file,
            execution_mode=args.execution_mode,
            lora_rank=args.lora_rank,
            training_iters=args.training_iters,
        )
    elif args.command in {"run-workflow", "run-custom-model"}:
        result = run_demo_workflow(
            domain=args.domain,
            model_id=args.model_id,
            manifest_path=args.manifest,
            payload_file=args.payload_file,
        )
    elif args.command == "inspect-data":
        raw_bytes = bytes.fromhex(args.hex)
        cls_res = DataAndVisualMCPServer.classify_transformation(raw_bytes)
        magic = raw_bytes[:2] if cls_res["has_magic_header"] and len(raw_bytes) >= 2 else b""
        rem_len = max(0, len(raw_bytes) - len(magic))
        fields = [{"id": "payload_body", "type": "bytes", "size_bytes": rem_len}] if rem_len > 0 else []
        ksy_res = DataAndVisualMCPServer.synthesize_kaitai_struct_ksy(
            format_id="inspected_binary_stream",
            magic_bytes=magic,
            fields=fields,
            sample_payload=raw_bytes,
        )
        result = {
            "transformation_class": cls_res["transformation_class"].value,
            "subtype": cls_res["subtype"],
            "shannon_entropy": cls_res["shannon_entropy"],
            "has_magic_header": cls_res["has_magic_header"],
            "kaitai_schema": {
                "format_id": ksy_res["format_id"],
                "full_byte_coverage": ksy_res["full_byte_coverage"],
                "expected_byte_length": ksy_res["expected_byte_length"],
            },
        }
    elif args.command == "hardware-check":
        hw = LocalHardwareDetector.detect()
        reg = ModelRegistry.for_profile(hw.recommended_profile)
        result = {
            "hardware": {
                "os_name": hw.os_name,
                "arch": hw.arch,
                "cpu_brand": hw.cpu_brand,
                "total_memory_gb": hw.total_memory_gb,
                "accelerator": hw.accelerator,
                "recommended_profile": hw.recommended_profile.value,
                "safe_model_budget_gb": hw.safe_model_budget_gb,
            },
            "recommended_models": [
                {
                    "model_id": m.model_id,
                    "pool": m.pool.value,
                    "vram_4bit_gb": m.vram_4bit_gb,
                    "vram_fp8_gb": m.vram_fp8_gb,
                    "license": m.license_id,
                }
                for m in reg.all_models()
            ],
        }
    elif args.command == "download-model":
        mgr = ModelDownloadManager()
        result = mgr.download_from_huggingface(
            repo_id=args.model_id,
            license_id=args.license,
            local_dir=args.local_dir,
        )
    elif args.command == "sync-vuln-db":
        vserver = VulnIntelMCPServer(db_path=args.db_path)
        try:
            sync_res = vserver.sync_live_feeds(feeds=args.feeds, session_tainted=False)
            result = {**sync_res, "mirror_stats": vserver.mirror_stats()}
        finally:
            vserver.close()
    elif args.command == "scan-forensics":
        fserver = ForensicsMCPServer()
        try:
            if args.stix_file:
                fserver.load_stix2_file(args.stix_file)
            assessment = fserver.analyze_forensic_target(
                target_dir=args.target_dir,
                platform=args.platform,
                use_mvt_cli=args.use_mvt_cli,
            )
            result = assessment.to_dict()
        finally:
            fserver.ioc_engine.close()
    elif args.command == "audit-vulns":
        vserver = VulnIntelMCPServer(db_path=args.db_path)
        cyber = DefensiveCyberMCPServer()
        try:
            proj = Path(args.project_dir).resolve()
            cpg_findings = []
            for p in proj.rglob("*"):
                if p.is_file() and not p.is_symlink() and p.suffix.lower() in {".py", ".c", ".cpp"}:
                    cpg_findings.extend(cyber.scan_cpg_taint(p.read_text(encoding="utf-8", errors="replace")))
            result = vserver.audit_project_dependencies(proj, cpg_findings=cpg_findings)
        finally:
            vserver.close()
    elif args.command == "analyze-image":
        target = Path(args.path)
        if target.suffix.lower() in {".pdf", ".md", ".txt", ".json", ".csv"}:
            result = DataAndVisualMCPServer.extract_document_text(target)
        elif args.prompt and args.endpoint:
            from platform_core.layer1_intelligence.inference import OpenAICompatibleClient

            client = OpenAICompatibleClient(base_url=args.endpoint)
            result = DataAndVisualMCPServer.analyze_visual_artifact(
                target, prompt=args.prompt, backend=client
            )
        else:
            result = DataAndVisualMCPServer.inspect_image_artifact(target)
    elif args.command == "run-benchmarks":
        result = BenchmarkSuiteRunner.run_all_suites(suites=args.suites)
    elif args.command == "harvest-corpus":
        if not args.pdf and not args.book_dir and not args.url:
            parser.error("harvest-corpus requires at least one --pdf, --book-dir, or --url.")
        result = run_harvest_corpus(
            pdf_paths=args.pdf,
            book_dirs=args.book_dir,
            urls=args.url,
            domain=args.domain,
            license_id=args.license,
            limit=args.limit,
            allowed_domains=args.allowed_domain,
            requests_per_second=args.requests_per_second,
            distill_output=args.distill_output,
            teacher_model_id=args.teacher_model,
            teacher_license_id=args.teacher_license,
            max_samples_per_doc=args.max_samples_per_doc,
            session_tainted=args.session_tainted,
            ingest_into_rag=not args.no_ingest_rag,
            rag_db_path=args.rag_db_path,
        )
        if args.output is not None:
            result["output_path"] = _write_json_output(args.output, result)
    elif args.command == "recommend-strategy":
        result = run_recommend_strategy(
            corpus_tokens=args.corpus_tokens,
            domain=args.domain,
            custom_vocab_required=args.custom_vocab,
            target_params_m=args.target_params_m,
        )
        if args.output is not None:
            result["output_path"] = _write_json_output(args.output, result)
    elif args.command == "train-scratch-slm":
        if not args.corpus_file and not args.corpus_dir and not args.text:
            parser.error("train-scratch-slm requires at least one --corpus-file, --corpus-dir, or --text.")
        result = run_train_scratch_slm(
            model_id=args.model_id,
            corpus_files=args.corpus_file,
            corpus_dirs=args.corpus_dir,
            inline_texts=args.text,
            output_dir=args.output_dir,
            tier=args.tier,
            steps=args.steps,
            d_model=args.d_model,
            n_layers=args.n_layers,
            n_heads=args.n_heads,
            d_ff=args.d_ff,
            vocab_size=args.vocab_size,
            max_seq_len=args.max_seq_len,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            seed=args.seed,
            execution_backend=args.backend,
            license_id=args.license,
            domain=args.domain,
            sample_prompt=args.sample_prompt,
            max_new_tokens=args.max_new_tokens,
        )
        if args.output is not None:
            result["output_path"] = _write_json_output(args.output, result)
    elif args.command == "run-agy-local":
        result = run_agy_local_command(
            agent_name=args.agent_name,
            prompt=args.prompt,
            runtime_kind=args.runtime,
            model_or_path=args.model,
            base_url=args.base_url,
            litert_backend=args.litert_backend,
            skills_dirs=args.skills_dir,
            mcp_servers=args.mcp_server,
            max_subagent_depth=args.max_subagent_depth,
            session_tainted=args.session_tainted,
            force_fallback=args.force_fallback,
        )
        if args.output is not None:
            result["output_path"] = _write_json_output(args.output, result)
    elif args.command == "mcp-stdio-bridge":
        combined_servers: list[str] = []
        if args.servers_single:
            combined_servers.extend(args.servers_single)
        if args.servers_multi:
            combined_servers.extend(args.servers_multi)
        return run_mcp_stdio_bridge(
            server_names=combined_servers or None,
            vuln_db_path=args.vuln_db_path,
            session_tainted=args.session_tainted,
        )
    else:
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
