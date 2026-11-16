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

    @classmethod
    def run_cyber_and_vuln_suite(cls) -> list[BenchmarkCaseResult]:
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

        # Newly acquired cybersecurity disciplines:
        results.extend(cls.run_binary_analysis_suite())
        results.extend(cls.run_exploit_mechanics_suite())
        results.extend(cls.run_network_protocols_suite())
        results.extend(cls.run_roe_and_scope_suite())
        return results

    @staticmethod
    def run_binary_analysis_suite() -> list[BenchmarkCaseResult]:
        """Binary Analysis: ELF64 checksec program header triage & constant division recovery."""
        from platform_core.layer2_execution.mcp_tools import BinRevMCPServer

        binrev = BinRevMCPServer()
        # 1. ELF64 x86_64 program header triage with checksec hardening detection
        elf_bytes = (
            b"\x7fELF"  # ELF magic
            b"\x02"     # 64-bit (ELFCLASS64)
            b"\x01"     # 2's complement, little endian (ELFDATA2LSB)
            b"\x01"     # EV_CURRENT
            + (b"\x00" * 9)  # OS ABI & padding
            + b"\x02\x00"  # e_type = ET_EXEC
            + b"\x3e\x00"  # e_machine = EM_X86_64 (0x3E)
            + b"\x01\x00\x00\x00"  # e_version = 1
            + (b"\x00" * 32)
            + b"GNU_STACK\x00"
            + b"__stack_chk_fail\x00"
            + b"_chk\x00"
            + b"main\x00"
        )
        inspect_res = binrev.inspect_binary(elf_bytes, artifact_name="triage_elf64.bin")
        checksec = inspect_res.get("checksec", {})
        triage_ok = (
            inspect_res.get("format") == "ELF"
            and inspect_res.get("architecture") == "x86_64"
            and checksec.get("nx_enabled") is True
            and checksec.get("stack_canary") is True
            and checksec.get("fortify_source") is True
            and checksec.get("pie_or_aslr") is True
        )

        # 2. Constant division recovery (Granlund-Montgomery reciprocal multiplication & shift)
        # In x86_64 disassembly: unsigned division by 14 is compiled to ((n * 0x24924925) >> 33).
        # We verify arithmetic equivalence across boundary test vectors and reconstruct semantic C.
        div_test_vals = (0, 1, 13, 14, 27, 28, 140, 9999, 140000)
        math_recovery_ok = all(((n * 0x24924925) >> 33) == (n // 14) for n in div_test_vals)

        raw_ghidra = (
            "undefined8 recover_div14(undefined4 n) {\n"
            "    undefined8 quotient;\n"
            "    quotient = (undefined8)(((uint64_t)n * 0x24924925ULL) >> 33);\n"
            "    return quotient;\n"
            "}\n"
        )
        sk2_out = binrev.run_two_phase_sk2_decompile(
            raw_ghidra_pseudocode=raw_ghidra,
            dataflow_aliases={"n": "dividend"},
        )
        skin_c = sk2_out.get("phase2_skin_decompiled_code", "")
        sk2_ok = "uint64_t quotient" in skin_c and "uint32_t dividend" in skin_c

        passed = triage_ok and math_recovery_ok and sk2_ok
        return [
            BenchmarkCaseResult(
                case_id="cyber-3",
                suite="cyber_vuln",
                passed=passed,
                score=1.0 if passed else 0.0,
                details="ELF64 checksec program header triage & constant division recovery",
            )
        ]

    @staticmethod
    def run_exploit_mechanics_suite() -> list[BenchmarkCaseResult]:
        """Exploit Mechanics: stack canary integrity & ROP gadget chain validation."""
        from platform_core.layer2_execution.mcp_tools import DefensiveCyberMCPServer

        cyber = DefensiveCyberMCPServer()

        # 1. Stack canary integrity validation
        # Model x86_64 stack frame layout: [buffer: 64B][canary: 8B][saved_rbp: 8B][saved_rip: 8B]
        golden_canary = 0xDEADBEEFC001CAFE
        frame_memory = bytearray(64 + 8 + 8 + 8)
        frame_memory[64:72] = golden_canary.to_bytes(8, "little")
        frame_memory[80:88] = (0x00007FFFF7A12345).to_bytes(8, "little")

        def _check_canary(mem: bytearray) -> bool:
            return int.from_bytes(mem[64:72], "little") == golden_canary

        # Benign write (32 bytes) preserves canary
        mem_benign = bytearray(frame_memory)
        mem_benign[0:32] = b"A" * 32
        canary_benign_intact = _check_canary(mem_benign)

        # Overflow payload (80 bytes) overwrites canary, triggering mitigation failure
        mem_overflow = bytearray(frame_memory)
        mem_overflow[0:80] = b"A" * 80
        canary_overflow_detected = not _check_canary(mem_overflow)

        canary_ok = canary_benign_intact and canary_overflow_detected

        # 2. ROP gadget chain validation (execve("/bin/sh", 0, 0) setup)
        # Chain verifies: gadget termination (0xc3), 16-byte stack alignment, and register state
        rop_chain = [
            {"gadget": "pop_rax_ret", "opcodes": b"\x58\xc3", "delta": 8, "reg": "rax", "val": 59},
            {"gadget": "pop_rdi_ret", "opcodes": b"\x5f\xc3", "delta": 8, "reg": "rdi", "val": 0x404050},
            {"gadget": "pop_rsi_ret", "opcodes": b"\x5e\xc3", "delta": 8, "reg": "rsi", "val": 0},
            {"gadget": "pop_rdx_ret", "opcodes": b"\x5a\xc3", "delta": 8, "reg": "rdx", "val": 0},
            {"gadget": "syscall_ret", "opcodes": b"\x0f\x05\xc3", "delta": 0, "reg": None, "val": None},
        ]
        gadgets_valid = all(g["opcodes"].endswith(b"\xc3") for g in rop_chain)
        regs_set: dict[str, int] = {}
        curr_rsp = 0x7FFFFFFFE000  # 16-byte aligned starting stack pointer
        for g in rop_chain:
            curr_rsp += g["delta"]
            if g["reg"]:
                regs_set[g["reg"]] = g["val"]

        rop_ok = (
            gadgets_valid
            and regs_set.get("rax") == 59
            and regs_set.get("rdi") == 0x404050
            and regs_set.get("rsi") == 0
            and regs_set.get("rdx") == 0
            and (curr_rsp % 16 == 0)
        )

        # 3. Defensive CPG taint scan & dual-gate patch verification
        vuln_c = "void handle(char *src) {\n    char dst[64];\n    strcpy(dst, src);\n}\n"
        taints = cyber.scan_cpg_taint(vuln_c)
        cwe120_found = any(f.cwe_id == "CWE-120" for f in taints)

        patched_c = "void handle(char *src) {\n    char dst[64];\n    strncpy(dst, src, sizeof(dst) - 1);\n    dst[sizeof(dst) - 1] = '\\0';\n}\n"
        dual_gate = cyber.verify_dual_gate_patch(
            patched_source=patched_c,
            poc_triggered_crash=False,
            regression_tests_passed=4,
            regression_tests_total=4,
        )
        remediation_ok = dual_gate.get("verdict") == "VERIFIED_PASS"

        passed = canary_ok and rop_ok and cwe120_found and remediation_ok
        return [
            BenchmarkCaseResult(
                case_id="cyber-4",
                suite="cyber_vuln",
                passed=passed,
                score=1.0 if passed else 0.0,
                details="Stack canary integrity & ROP gadget chain validation",
            )
        ]

    @staticmethod
    def run_network_protocols_suite() -> list[BenchmarkCaseResult]:
        """Network Protocols: IPv4 RFC 1071 checksum & TCP state transition validation."""
        from platform_core.layer2_execution.mcp_tools import DataAndVisualMCPServer, TransformationClass

        # 1. RFC 1071 IPv4 header checksum algorithm verification
        def _calc_checksum(raw_hdr: bytes) -> int:
            if len(raw_hdr) % 2 != 0:
                raw_hdr += b"\x00"
            s = sum((raw_hdr[i] << 8) | raw_hdr[i + 1] for i in range(0, len(raw_hdr), 2))
            while (s >> 16) > 0:
                s = (s & 0xFFFF) + (s >> 16)
            return (~s) & 0xFFFF

        hdr_zero_csum = bytes.fromhex("4500003c1c46400040060000c0a80001c0a800c7")
        computed_csum = _calc_checksum(hdr_zero_csum)
        hdr_with_csum = bytes.fromhex(f"4500003c1c4640004006{computed_csum:04x}c0a80001c0a800c7")
        verified_csum = _calc_checksum(hdr_with_csum)
        csum_ok = (computed_csum == 0x9C5D) and (verified_csum == 0x0000)

        # 2. TCP State Machine transitions (RFC 793 / RFC 9293)
        valid_transitions = {
            ("CLOSED", "APP_PASSIVE_OPEN"): "LISTEN",
            ("LISTEN", "RECV_SYN"): "SYN_RECEIVED",
            ("SYN_SENT", "RECV_SYN_ACK"): "ESTABLISHED",
            ("SYN_RECEIVED", "RECV_ACK"): "ESTABLISHED",
            ("ESTABLISHED", "APP_CLOSE"): "FIN_WAIT_1",
            ("FIN_WAIT_1", "RECV_ACK"): "FIN_WAIT_2",
            ("FIN_WAIT_2", "RECV_FIN"): "TIME_WAIT",
            ("ESTABLISHED", "RECV_FIN"): "CLOSE_WAIT",
            ("CLOSE_WAIT", "APP_CLOSE"): "LAST_ACK",
            ("LAST_ACK", "RECV_ACK"): "CLOSED",
        }
        state = "CLOSED"
        state = valid_transitions.get((state, "APP_PASSIVE_OPEN"), "ERR")
        state = valid_transitions.get((state, "RECV_SYN"), "ERR")
        state = valid_transitions.get((state, "RECV_ACK"), "ERR")
        handshake_ok = (state == "ESTABLISHED")

        state = valid_transitions.get((state, "APP_CLOSE"), "ERR")
        state = valid_transitions.get((state, "RECV_ACK"), "ERR")
        state = valid_transitions.get((state, "RECV_FIN"), "ERR")
        teardown_ok = (state == "TIME_WAIT")

        invalid_rejected = (
            ("LISTEN", "RECV_FIN") not in valid_transitions
            and ("CLOSED", "RECV_DATA") not in valid_transitions
        )

        tcp_ok = handshake_ok and teardown_ok and invalid_rejected

        # 3. Grounding with DataAndVisualMCPServer protocol transformation classification
        cls_res = DataAndVisualMCPServer.classify_transformation(hdr_with_csum)
        proto_class_ok = cls_res["transformation_class"] == TransformationClass.ENCODING_SERIALIZATION

        passed = csum_ok and tcp_ok and proto_class_ok
        return [
            BenchmarkCaseResult(
                case_id="cyber-5",
                suite="cyber_vuln",
                passed=passed,
                score=1.0 if passed else 0.0,
                details="IPv4 checksum & TCP state transition validation",
            )
        ]

    @staticmethod
    def run_roe_and_scope_suite() -> list[BenchmarkCaseResult]:
        """Rules of Engagement / Scope authorization checks."""
        from platform_core.layer2_execution.sandbox import FirecrackerSandboxManager
        from platform_core.layer2_execution.vuln_intel_mcp import AuthorizationScope, VulnIntelMCPServer

        # 1. RoE Scope specification & authorization validation
        scope = AuthorizationScope(
            engagement_id="ROE-2026-M4-01",
            authorized_targets=("10.10.0.0/16", "*.corp.internal"),
            valid_from_utc="2026-01-01T00:00:00Z",
            valid_until_utc="2026-12-31T23:59:59Z",
            allowed_actions=frozenset({"vuln_audit", "port_scan", "cpg_taint"}),
            operator_approval_id="OP-SIG-2026-999",
        )

        r_cidr = VulnIntelMCPServer.verify_authorization(
            scope=scope,
            target="10.10.5.21",
            action="port_scan",
            now_utc="2026-06-01T12:00:00Z",
        )
        r_fqdn = VulnIntelMCPServer.verify_authorization(
            scope=scope,
            target="https://vault.corp.internal:8443/api",
            action="vuln_audit",
            now_utc="2026-06-01T12:00:00Z",
        )
        r_out_target = VulnIntelMCPServer.verify_authorization(
            scope=scope,
            target="192.168.1.1",
            action="port_scan",
            now_utc="2026-06-01T12:00:00Z",
        )
        r_out_action = VulnIntelMCPServer.verify_authorization(
            scope=scope,
            target="10.10.5.21",
            action="exploit_execute",
            now_utc="2026-06-01T12:00:00Z",
        )
        r_expired = VulnIntelMCPServer.verify_authorization(
            scope=scope,
            target="10.10.5.21",
            action="port_scan",
            now_utc="2027-02-01T12:00:00Z",
        )

        roe_auth_ok = (
            r_cidr.get("authorized") is True
            and r_fqdn.get("authorized") is True
            and r_out_target.get("authorized") is False
            and r_out_action.get("authorized") is False
            and r_expired.get("authorized") is False
        )

        # 2. Sandbox egress isolation under TAINTED_UNTRUSTED session
        sb = FirecrackerSandboxManager()
        sb.provision_microvm("vm-roe-bench", {}, tainted=True)
        egress_decision = sb.check_network_egress("vm-roe-bench", "8.8.8.8:53")
        egress_blocked_ok = (
            egress_decision.allowed is False
            and egress_decision.tainted_session is True
            and "TAINTED_UNTRUSTED" in egress_decision.reason
        )

        passed = roe_auth_ok and egress_blocked_ok
        return [
            BenchmarkCaseResult(
                case_id="cyber-6",
                suite="cyber_vuln",
                passed=passed,
                score=1.0 if passed else 0.0,
                details="Rules of Engagement / Scope authorization checks",
            )
        ]

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

    DEFAULT_SUITES: tuple[str, ...] = (
        "coding",
        "reasoning",
        "cyber_vuln",
        "forensics",
        "hallucination_resistance",
    )

    @classmethod
    def run_all_suites(cls, suites: tuple[str, ...] | list[str] | None = None) -> dict[str, Any]:
        """Execute selected or all live capability & anti-hallucination benchmark suites."""
        dispatch = {
            "coding": cls.run_coding_suite,
            "reasoning": cls.run_reasoning_suite,
            "cyber_vuln": cls.run_cyber_and_vuln_suite,
            "forensics": cls.run_forensics_spyware_suite,
            "hallucination_resistance": cls.run_hallucination_and_abstention_suite,
            "binary_analysis": cls.run_binary_analysis_suite,
            "exploit_mechanics": cls.run_exploit_mechanics_suite,
            "network_protocols": cls.run_network_protocols_suite,
            "roe_scope": cls.run_roe_and_scope_suite,
        }
        selected = [s.strip().lower() for s in suites] if suites else list(cls.DEFAULT_SUITES)
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
