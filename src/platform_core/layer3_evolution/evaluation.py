"""Layer 3 Benchmark & Evaluation Suite — Multi-Run CI, pass^k, PropBench-9, & Canary Gate.

Implements Deliverable 7 (Section 8.1, 8.2, & 10.4 Step 7/8):
- Computes multi-run confidence intervals ($1.96 \\times s / \\sqrt{n}$ across 5 runs).
- Computes $\\text{pass}@1$ and $\\text{pass}^k$ ($k=4$ consecutive trial consistency, verifying
  $\\text{pass}^4 / \\text{pass}@1 \\ge 0.85$).
- Defines the 9 internal held-out benchmarks (`PropBench9Suite`).
- Enforces the `CanaryPromotionGate` blocking any model release that regresses on any
  capability or fails to beat the run-to-run confidence interval margin.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import statistics
import tempfile
import time
from typing import Any

from platform_core.layer1_intelligence.models import (
    HardwareFeasibilityPlanner,
    HardwareProfile,
    LocalHardwareDetector,
    ModelRegistry,
)


@dataclass(frozen=True)
class MultiRunBenchmarkResult:
    """Statistical summary of running a benchmark across $N$ independent trials (Section 8.1)."""

    benchmark_id: str
    run_scores: tuple[float, ...]
    mean_score: float
    std_dev: float
    ci_95_margin: float
    ci_95_lower: float
    ci_95_upper: float
    target_threshold: float
    meets_target: bool


class BenchmarkEvaluator:
    """Computes multi-run 95% confidence intervals, pass^k reliability, and Canary Promotion Gates."""

    @staticmethod
    def evaluate_multi_run(
        benchmark_id: str,
        run_scores: list[float],
        target_threshold: float,
    ) -> MultiRunBenchmarkResult:
        """Compute mean score and 95% confidence interval ($1.96 \\times s / \\sqrt{n}$)."""
        if not run_scores:
            raise ValueError("run_scores must contain at least 1 trial score.")
        n = len(run_scores)
        mean_val = statistics.fmean(run_scores)
        std_val = statistics.stdev(run_scores) if n >= 2 else 0.0
        margin = 1.96 * (std_val / math.sqrt(n)) if n >= 2 else 0.0

        return MultiRunBenchmarkResult(
            benchmark_id=benchmark_id,
            run_scores=tuple(round(s, 4) for s in run_scores),
            mean_score=round(mean_val, 4),
            std_dev=round(std_val, 4),
            ci_95_margin=round(margin, 4),
            ci_95_lower=round(mean_val - margin, 4),
            ci_95_upper=round(mean_val + margin, 4),
            target_threshold=target_threshold,
            meets_target=mean_val >= target_threshold,
        )

    @staticmethod
    def compute_pass_hat_k(task_trial_outcomes: list[list[bool]], k: int = 4) -> dict[str, Any]:
        """Compute pass@1 and pass^k consistency across tasks (Section 8.1).

        For each task with trial outcomes, pass^k is the probability of succeeding on all k
        consecutive trials. Platform target requires pass^4 / pass@1 >= 0.85.
        """
        if not task_trial_outcomes:
            raise ValueError("task_trial_outcomes must not be empty.")
        if k <= 0:
            raise ValueError("k must be positive.")

        pass_1_list: list[float] = []
        pass_k_list: list[float] = []

        for outcomes in task_trial_outcomes:
            if not outcomes:
                raise ValueError("Each task must have at least 1 trial outcome.")
            p_single = sum(1 for x in outcomes if x) / len(outcomes)
            pass_1_list.append(p_single)
            pass_k_list.append(p_single**k)

        mean_pass_1 = statistics.fmean(pass_1_list)
        mean_pass_k = statistics.fmean(pass_k_list)
        consistency_ratio = (mean_pass_k / mean_pass_1) if mean_pass_1 > 0 else 0.0

        return {
            "k": k,
            "pass_at_1": round(mean_pass_1 * 100.0, 2),
            "pass_hat_k": round(mean_pass_k * 100.0, 2),
            "consistency_ratio": round(consistency_ratio, 4),
            "meets_85pct_consistency_sla": consistency_ratio >= 0.85,
        }

    @classmethod
    def evaluate_canary_promotion(
        cls,
        baseline_runs: dict[str, list[float]],
        candidate_runs: dict[str, list[float]],
        target_domains: set[str],
    ) -> dict[str, Any]:
        """Canary Promotion Gate (Section 10.4 Step 8).

        Promotes candidate checkpoint ONLY IF:
        1. Zero benchmarks exhibit a statistically significant regression (`cand_mean < base_mean - margin`).
        2. At least one target domain benchmark improves beyond the run-to-run noise margin
           (`cand_mean > base_mean + margin`).
        """
        if set(baseline_runs.keys()) != set(candidate_runs.keys()):
            raise ValueError("Baseline and candidate benchmark keys must match.")

        regressions: list[str] = []
        significant_gains: list[str] = []
        comparisons: dict[str, dict[str, float]] = {}

        for bench_id, base_scores in baseline_runs.items():
            cand_scores = candidate_runs[bench_id]
            base_res = cls.evaluate_multi_run(bench_id, base_scores, target_threshold=0.0)
            cand_res = cls.evaluate_multi_run(bench_id, cand_scores, target_threshold=0.0)
            combined_margin = max(base_res.ci_95_margin, cand_res.ci_95_margin, 0.25)
            delta = round(cand_res.mean_score - base_res.mean_score, 4)

            comparisons[bench_id] = {
                "baseline_mean": base_res.mean_score,
                "candidate_mean": cand_res.mean_score,
                "delta": delta,
                "noise_margin": round(combined_margin, 4),
            }

            if delta < -combined_margin:
                regressions.append(bench_id)
            elif bench_id in target_domains and delta > combined_margin:
                significant_gains.append(bench_id)

        promoted = (len(regressions) == 0) and (len(significant_gains) > 0)
        return {
            "promoted": promoted,
            "regressions": regressions,
            "significant_target_gains": significant_gains,
            "comparisons": comparisons,
        }


@dataclass(frozen=True)
class PropBenchSpec:
    """Specification of one of the 9 internal PropBench-9 suites (Section 8.2)."""

    bench_id: str
    title: str
    task_count: int
    primary_metric: str
    target_score: float


class PropBench9Suite:
    """Registry and runner for the 9 Proprietary Platform Benchmarks (Section 8.2)."""

    BENCHMARKS: tuple[PropBenchSpec, ...] = (
        PropBenchSpec(
            bench_id="PropBench-RepoMod",
            title="Complex Multi-Service Repository Modification (5-15 files)",
            task_count=100,
            primary_metric="integration_pass_and_zero_unused_scip_symbols_pct",
            target_score=70.0,
        ),
        PropBenchSpec(
            bench_id="PropBench-Debug",
            title="Multi-Stage Issue-Free Root-Cause Debugging",
            task_count=150,
            primary_metric="issue_free_fault_localization_and_fix_pass_at_1_pct",
            target_score=65.0,
        ),
        PropBenchSpec(
            bench_id="PropBench-FileFmt",
            title="Unknown Binary File-Format & Kaitai .ksy Schema Discovery",
            task_count=80,
            primary_metric="full_byte_coverage_ksy_parse_pct",
            target_score=75.0,
        ),
        PropBenchSpec(
            bench_id="PropBench-BinStruct",
            title="Stripped -O2/-O3 Binary Structure & Algorithm Reconstruction",
            task_count=200,
            primary_metric="dwarf_struct_iou_and_r_exec_pct",
            target_score=72.0,
        ),
        PropBenchSpec(
            bench_id="PropBench-Proto",
            title="Stateful Network Protocol Reverse Engineering (PCAP + Server)",
            task_count=60,
            primary_metric="state_machine_handshake_completion_pct",
            target_score=68.0,
        ),
        PropBenchSpec(
            bench_id="PropBench-SecFix",
            title="Zero-Overcorrection Vulnerability Audit & Remediation",
            task_count=120,
            primary_metric="dual_gate_poc_and_zero_overcorrection_pct",
            target_score=80.0,
        ),
        PropBenchSpec(
            bench_id="PropBench-TechVis",
            title="High-Resolution 4K Technical Screenshot & Hardware Grounding",
            task_count=250,
            primary_metric="bbox_iou_and_epistemic_calibration_pct",
            target_score=85.0,
        ),
        PropBenchSpec(
            bench_id="PropBench-ToolOrch",
            title="Fault-Tolerant Multi-Tool Orchestration (20% injected faults)",
            task_count=100,
            primary_metric="pass_hat_4_autonomous_recovery_pct",
            target_score=85.0,
        ),
        PropBenchSpec(
            bench_id="PropBench-LongRun",
            title="Long-Horizon 4-Hour Engineering Marathon (50-200 turns)",
            task_count=40,
            primary_metric="end_to_end_completion_without_semantic_drift_pct",
            target_score=65.0,
        ),
    )

    @classmethod
    def all_specs(cls) -> tuple[PropBenchSpec, ...]:
        return cls.BENCHMARKS


@dataclass(frozen=True)
class BenchmarkCaseResult:
    """Single executable benchmark test case outcome."""

    case_id: str
    suite: str
    passed: bool
    score: float
    details: str


class BenchmarkSuiteRunner:
    """Executable benchmark harness covering Coding, Reasoning, Cyber/Vuln, Forensics, & Hallucination Resistance."""

    @staticmethod
    def run_coding_suite() -> list[BenchmarkCaseResult]:
        from platform_core.layer2_execution.mcp_tools import CodeGraphMCPServer
        from platform_core.layer2_execution.sandbox import FirecrackerSandboxManager

        results: list[BenchmarkCaseResult] = []
        cg = CodeGraphMCPServer()
        sb = FirecrackerSandboxManager()
        try:
            # Case 1: Safe patch generation + sandbox verification
            vm_id = "bench-code-1"
            src = "def safe_ratio(a: int, b: int) -> float:\n    return a / b\n"
            sb.provision_microvm(vm_id, {"ratio.py": src}, tainted=True)
            edit = cg.apply_str_replace_edit(
                source_code=src,
                old_str="    return a / b",
                new_str="    return (a / b) if b != 0 else 0.0",
                language="python",
            )
            passed = False
            if edit["applied"]:
                sb.write_workspace_file(vm_id, "ratio.py", edit["updated_source"])
                res = sb.execute_python_in_sandbox(
                    vm_id,
                    "from ratio import safe_ratio\nassert safe_ratio(6, 2) == 3.0\nassert safe_ratio(1, 0) == 0.0\n",
                )
                passed = res.exit_code == 0
            results.append(
                BenchmarkCaseResult("code-1", "coding", passed, 1.0 if passed else 0.0, "ZeroDivision guard + sandbox verify")
            )

            # Case 2: SCIP symbol extraction accuracy
            stats = cg.index_file("mod.py", "def alpha():\n    return beta()\ndef beta():\n    return 42\n")
            sym = cg.query_symbol("beta")
            sym_ok = (
                stats["raw_tokens"] > 0
                and sym.get("status") == "Resolved"
                and any(c.get("caller_name") == "alpha" for c in sym.get("inverse_callers", []))
            )
            results.append(
                BenchmarkCaseResult("code-2", "coding", sym_ok, 1.0 if sym_ok else 0.0, "SCIP inverse caller graph resolution")
            )
        finally:
            cg.close()
        return results

    @staticmethod
    def run_reasoning_suite() -> list[BenchmarkCaseResult]:
        from platform_core.layer2_execution.mcp_tools import DataAndVisualMCPServer

        results: list[BenchmarkCaseResult] = []
        hw = LocalHardwareDetector.detect()
        reg = ModelRegistry.for_profile(HardwareProfile.LOCAL_APPLE_SILICON_36GB)
        models_fit = len(reg.all_models()) >= 5 and HardwareFeasibilityPlanner.recommend_scenario(1_800_000, True)["recommended_scenario"] == "Scenario-B"
        results.append(
            BenchmarkCaseResult(
                "reason-1",
                "reasoning",
                models_fit,
                1.0 if models_fit else 0.0,
                f"Hardware-aware routing & budget planning (host_mem={hw.total_memory_gb}GB)",
            )
        )

        # Binary transformation entropy classification reasoning (16B random-like block -> ENCRYPTION)
        block = bytes((i * 73 + 19) % 256 for i in range(32))
        cls_out = DataAndVisualMCPServer.classify_transformation(block)
        ent_ok = cls_out["transformation_class"].value in {"ENCRYPTION", "COMPRESSION"}
        results.append(
            BenchmarkCaseResult(
                "reason-2",
                "reasoning",
                ent_ok,
                1.0 if ent_ok else 0.0,
                f"Finite-sample entropy normalization ({cls_out['transformation_class'].value})",
            )
        )
        return results

    @staticmethod
    def run_cyber_and_vuln_suite() -> list[BenchmarkCaseResult]:
        from platform_core.layer2_execution.mcp_tools import DefensiveCyberMCPServer
        from platform_core.layer2_execution.vuln_intel_mcp import VulnFindingClassification, VulnIntelMCPServer

        results: list[BenchmarkCaseResult] = []
        cyber = DefensiveCyberMCPServer()
        vuln = VulnIntelMCPServer()
        try:
            vuln.ingest_osv_records(
                [
                    {
                        "id": "GHSA-bench-0001",
                        "aliases": ["CVE-2026-99001"],
                        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-94"]},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "demo-parser"},
                                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}]}],
                            }
                        ],
                    }
                ]
            )
            vuln.ingest_cisa_kev([{"cveID": "CVE-2026-99001", "vendorProject": "Demo", "product": "demo-parser"}])

            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                (root / "requirements.txt").write_text("demo-parser==1.2.0\nsafe-lib==2.0.0\n", encoding="utf-8")
                vuln_py = "import subprocess\ndef ping(h):\n    cmd = h\n    return subprocess.run(cmd, shell=True)\n"
                taints = cyber.scan_cpg_taint(vuln_py)
                rep = vuln.audit_project_dependencies(root, cpg_findings=taints)
                dep_confirmed = any(
                    f["vuln_id"] == "CVE-2026-99001"
                    and f["classification"] == VulnFindingClassification.CONFIRMED_VULNERABILITY.value
                    and f["kev_listed"] is True
                    for f in rep["dependency_findings"]
                )
                ast_confirmed = any(
                    c["cwe_id"] == "CWE-78"
                    and c["classification"] == VulnFindingClassification.CONFIRMED_VULNERABILITY.value
                    for c in rep["code_findings"]
                )
                results.append(
                    BenchmarkCaseResult(
                        "cyber-1",
                        "cyber_vuln",
                        dep_confirmed and ast_confirmed,
                        1.0 if (dep_confirmed and ast_confirmed) else 0.0,
                        "OSV/KEV version match + AST taint CWE-78 confirmation",
                    )
                )

                # Patched dependency (1.4.1 >= fixed 1.4.0) must produce 0 false positives
                (root / "requirements.txt").write_text("demo-parser==1.4.1\n", encoding="utf-8")
                rep_fixed = vuln.audit_project_dependencies(root, cpg_findings=[])
                no_fp = rep_fixed["summary"]["confirmed_vulnerabilities"] == 0
                results.append(
                    BenchmarkCaseResult(
                        "cyber-2",
                        "cyber_vuln",
                        no_fp,
                        1.0 if no_fp else 0.0,
                        "Zero false positives after upgrading past fixed version",
                    )
                )
        finally:
            vuln.close()
        return results

    @staticmethod
    def run_forensics_spyware_suite() -> list[BenchmarkCaseResult]:
        from platform_core.layer2_execution.forensics_mcp import ForensicsMCPServer, ForensicVerdict

        results: list[BenchmarkCaseResult] = []
        fmcp = ForensicsMCPServer()
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                # 1. Positive Pegasus/Triangulation STIX2 fixture
                pos_dir = root / "ios_compromised"
                pos_dir.mkdir()
                (pos_dir / "Shutdown.log").write_text("2026-09-12T04:11:00Z SIGTERM process roleaboutd\n", encoding="utf-8")
                pos_res = fmcp.analyze_forensic_target(pos_dir, platform="ios")
                pos_ok = (
                    pos_res.overall_verdict == ForensicVerdict.CONFIRMED_IOC_MATCH
                    and any(f.threat_family == "Pegasus" and bool(f.artifact_sha256) for f in pos_res.findings)
                )
                results.append(
                    BenchmarkCaseResult("forensics-1", "forensics", pos_ok, 1.0 if pos_ok else 0.0, "Positive iOS spyware IOC recall + SHA256 evidence")
                )

                # 2. Clean benign iOS backup negative control (MUST NOT fabricate compromise)
                clean_dir = root / "ios_clean"
                clean_dir.mkdir()
                (clean_dir / "Shutdown.log").write_text("2026-09-12T04:11:00Z SIGTERM SpringBoard MobileSafari\n", encoding="utf-8")
                clean_res = fmcp.analyze_forensic_target(clean_dir, platform="ios")
                clean_ok = clean_res.overall_verdict == ForensicVerdict.NO_KNOWN_IOC_DETECTED and len(clean_res.findings) == 0
                results.append(
                    BenchmarkCaseResult("forensics-2", "forensics", clean_ok, 1.0 if clean_ok else 0.0, "Benign iOS negative control (0 false positives)")
                )
        finally:
            fmcp.ioc_engine.close()
        return results

    @staticmethod
    def run_hallucination_and_abstention_suite() -> list[BenchmarkCaseResult]:
        from platform_core.layer2_execution.forensics_mcp import ForensicsMCPServer, ForensicVerdict
        from platform_core.layer2_execution.mcp_tools import DataAndVisualMCPServer, VisualRegionObservation
        from platform_core.layer2_execution.vuln_intel_mcp import VulnFindingClassification, VulnIntelMCPServer

        results: list[BenchmarkCaseResult] = []
        # 1. Visual epistemic zoom calibration rejects guessing on low-res regions
        vis = DataAndVisualMCPServer.ground_visual_observations(
            [VisualRegionObservation(1, (10, 10, 50, 50), "0x???", 0.35, True)]
        )
        vis_ok = vis["epistemic_hallucination_guard_active"] and len(vis["uncertain_regions_requiring_zoom"]) == 1
        results.append(
            BenchmarkCaseResult("epistemic-1", "hallucination_resistance", vis_ok, 1.0 if vis_ok else 0.0, "Abstains & demands zoom_crop_region on obscured visual OCR")
        )

        # 2. Partial/missing version info -> POTENTIAL_WEAKNESS (never CONFIRMED_VULNERABILITY)
        vuln = VulnIntelMCPServer()
        try:
            vuln.ingest_osv_records(
                [{"id": "CVE-2026-8888", "affected": [{"package": {"ecosystem": "PyPI", "name": "unpinned-pkg"}, "ranges": []}]}]
            )
            matches = vuln.correlate_package("unpinned-pkg", version=None, ecosystem="PyPI")
            abstains_ok = len(matches) == 1 and matches[0].classification == VulnFindingClassification.POTENTIAL_WEAKNESS
            results.append(
                BenchmarkCaseResult("epistemic-2", "hallucination_resistance", abstains_ok, 1.0 if abstains_ok else 0.0, "Unpinned dependency downgraded to POTENTIAL_WEAKNESS")
            )
        finally:
            vuln.close()

        # 3. Encrypted / incomplete iOS backup -> NO_KNOWN_IOC_DETECTED + visibility limitation (never fabricates IOCs)
        import plistlib

        fmcp = ForensicsMCPServer()
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                bdir = Path(tmpdir)
                (bdir / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True}))
                res = fmcp.analyze_ios_backup(bdir)
                enc_ok = (
                    res.overall_verdict == ForensicVerdict.NO_KNOWN_IOC_DETECTED
                    and any("IsEncrypted=True" in msg for msg in res.visibility_limitations)
                )
                results.append(
                    BenchmarkCaseResult("epistemic-3", "hallucination_resistance", enc_ok, 1.0 if enc_ok else 0.0, "Encrypted backup reports visibility limitation without fabrication")
                )
        finally:
            fmcp.ioc_engine.close()

        return results

    @classmethod
    def run_all_suites(cls, suites: tuple[str, ...] | list[str] | None = None) -> dict[str, Any]:
        """Execute selected or all live capability & anti-hallucination benchmark suites."""
        dispatch = {
            "coding": cls.run_coding_suite,
            "reasoning": cls.run_reasoning_suite,
            "cyber_vuln": cls.run_cyber_and_vuln_suite,
            "forensics": cls.run_forensics_spyware_suite,
            "hallucination_resistance": cls.run_hallucination_and_abstention_suite,
        }
        selected = [s.strip().lower() for s in suites] if suites else list(dispatch.keys())
        for s in selected:
            if s not in dispatch:
                raise ValueError(f"Unknown benchmark suite '{s}': choose from {list(dispatch.keys())}")

        started = time.perf_counter()
        all_cases: list[BenchmarkCaseResult] = []
        per_suite: dict[str, dict[str, Any]] = {}
        for name in selected:
            cases = dispatch[name]()
            all_cases.extend(cases)
            passed_cnt = sum(1 for c in cases if c.passed)
            per_suite[name] = {
                "total": len(cases),
                "passed": passed_cnt,
                "score_pct": round(100.0 * passed_cnt / max(1, len(cases)), 2),
                "cases": [
                    {
                        "case_id": c.case_id,
                        "passed": c.passed,
                        "score": c.score,
                        "details": c.details,
                    }
                    for c in cases
                ],
            }

        total_cases = len(all_cases)
        total_passed = sum(1 for c in all_cases if c.passed)
        overall_pct = round(100.0 * total_passed / max(1, total_cases), 2)
        return {
            "overall_verdict": "PASS" if total_passed == total_cases and total_cases > 0 else "FAIL",
            "total_cases": total_cases,
            "total_passed": total_passed,
            "overall_score_pct": overall_pct,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            "suites": per_suite,
        }
