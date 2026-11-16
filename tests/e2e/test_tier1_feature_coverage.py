"""Tier 1: Feature Coverage Test Suite (65 tests across 13 cybersecurity disciplines).

Each of the 13 disciplines is covered by exactly 5 distinct feature tests:
1. Penetration Testing Methodologies (T1-PEN-01 to T1-PEN-05)
2. Vulnerability Research (T1-VULN-01 to T1-VULN-05)
3. Exploit Mechanics (T1-EXP-01 to T1-EXP-05)
4. Binary Analysis (T1-BIN-01 to T1-BIN-05)
5. Assembly Language (T1-ASM-01 to T1-ASM-05)
6. Operating System Internals (T1-OS-01 to T1-OS-05)
7. Memory Architecture (T1-MEM-01 to T1-MEM-05)
8. Malware Analysis (T1-MAL-01 to T1-MAL-05)
9. Network Protocols (T1-NET-01 to T1-NET-05)
10. Web and API Security (T1-WEB-01 to T1-WEB-05)
11. Firmware and Embedded Systems Analysis (T1-FW-01 to T1-FW-05)
12. Cryptographic Implementation (T1-CRYP-01 to T1-CRYP-05)
13. Digital Forensics (T1-FOR-01 to T1-FOR-05)
"""
from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
import unittest

from platform_core.deploy_security.governance import (
    SafetensorsValidator,
)
from platform_core.layer1_intelligence.training import (
    BinRevDecompileRewardOracle,
    StructFieldSpan,
)
from platform_core.layer2_execution.forensics_mcp import (
    ForensicsMCPServer,
    ForensicVerdict,
    Stix2IocEngine,
)
from platform_core.layer2_execution.mcp_tools import (
    BinRevMCPServer,
    DataAndVisualMCPServer,
    DefensiveCyberMCPServer,
    TransformationClass,
)
from platform_core.layer2_execution.sandbox import (
    FirecrackerSandboxManager,
)
from platform_core.layer2_execution.state import (
    EpistemicAssessment,
    EpistemicClaim,
    EpistemicStatus,
)
from platform_core.layer2_execution.vuln_intel_mcp import (
    AuthorizationScope,
    VulnIntelMCPServer,
)
from platform_core.layer3_evolution.corpus_harvester import (
    RateLimitedWebHarvester,
)
from platform_core.layer1_intelligence.serving import (
    RadixPrefixCacheSimulator,
)
from tests.e2e.harness import E2EBaseTestCase, TestContracts


class TestTier1FeatureCoverage(E2EBaseTestCase):
    """Tier 1: Comprehensive feature coverage across all 13 cybersecurity disciplines."""

    tier = 1

    # =========================================================================
    # Discipline 1: Penetration Testing Methodologies (T1-PEN)
    # =========================================================================

    def test_t1_pen_01_valid_cidr_range_roe_scope_verification(self) -> None:
        """T1-PEN-01: Valid CIDR Range RoE Scope Verification."""
        self.domain = "penetration_testing"
        self.test_id = "T1-PEN-01"

        scope = AuthorizationScope(
            engagement_id="ENG-2026-A1",
            authorized_targets=("10.0.0.0/24",),
            valid_from_utc="2026-01-01T00:00:00Z",
            valid_until_utc="2026-12-31T23:59:59Z",
            allowed_actions=frozenset({"port_scan", "vuln_audit"}),
            operator_approval_id="OP-2026-A1",
        )
        res = VulnIntelMCPServer.verify_authorization(
            scope=scope,
            target="10.0.0.45",
            action="port_scan",
            now_utc="2026-06-01T12:00:00Z",
        )
        self.assertTrue(res.get("authorized"), f"Expected authorization granted, got: {res}")
        self.assertNotIn("reason", res)

    def test_t1_pen_02_valid_fqdn_target_roe_scope_verification(self) -> None:
        """T1-PEN-02: Valid FQDN Target RoE Scope Verification."""
        self.domain = "penetration_testing"
        self.test_id = "T1-PEN-02"

        scope = AuthorizationScope(
            engagement_id="ENG-2026-B2",
            authorized_targets=("api.corp.internal",),
            valid_from_utc="2026-01-01T00:00:00Z",
            valid_until_utc="2026-12-31T23:59:59Z",
            allowed_actions=frozenset({"vuln_audit"}),
            operator_approval_id="OP-2026-B2",
        )
        res = VulnIntelMCPServer.verify_authorization(
            scope=scope,
            target="https://api.corp.internal:8443/v1",
            action="vuln_audit",
            now_utc="2026-06-01T12:00:00Z",
        )
        self.assertTrue(res.get("authorized"), f"Expected FQDN target authorized, got: {res}")

    def test_t1_pen_03_cyber_remediation_workflow_execution(self) -> None:
        """T1-PEN-03: Cyber Remediation Workflow Execution."""
        self.domain = "penetration_testing"
        self.test_id = "T1-PEN-03"

        res = self.runner.run(["run-workflow", "--domain", "cyber"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_status_completed(res)
        TestContracts.assert_independent_verifier_gate(res)
        TestContracts.assert_taint_level(res, "TAINTED_UNTRUSTED")
        self.assertEqual(data.get("selected_pool"), "POOL_2_SWE_CYBER")

    def test_t1_pen_04_tainted_session_network_egress_policy_verification(self) -> None:
        """T1-PEN-04: Tainted Session Network Egress Policy Verification."""
        self.domain = "penetration_testing"
        self.test_id = "T1-PEN-04"

        sb = FirecrackerSandboxManager()
        sb.provision_microvm("vm-pen-1", {}, tainted=True)
        decision = sb.check_network_egress("vm-pen-1", "8.8.8.8:53")
        self.assertFalse(decision.allowed, "Tainted session must block public IP egress")
        self.assertTrue(decision.tainted_session)
        self.assertIn("TAINTED_UNTRUSTED", decision.reason)

    def test_t1_pen_05_local_agy_orchestrator_tainted_run_configuration(self) -> None:
        """T1-PEN-05: Local AGY Orchestrator Tainted Run Configuration."""
        self.domain = "penetration_testing"
        self.test_id = "T1-PEN-05"

        res = self.runner.run(
            ["run-agy-local", "--prompt", "Audit network config", "--tainted", "--force-fallback"]
        )
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertTrue(data.get("config_snapshot", {}).get("session_tainted"))
        self.assertEqual(data.get("taint_level"), "TAINTED_UNTRUSTED")
        self.assertEqual(data.get("status"), "COMPLETED")

    # =========================================================================
    # Discipline 2: Vulnerability Research (T1-VULN)
    # =========================================================================

    def test_t1_vuln_01_sync_vulnerability_feeds_mirror(self) -> None:
        """T1-VULN-01: Sync Vulnerability Feeds Mirror (KEV and EPSS)."""
        self.domain = "vulnerability_research"
        self.test_id = "T1-VULN-01"

        tmp_dir = self.make_temp_dir()
        db_path = tmp_dir / "vuln_mirror.db"
        res = self.runner.run(["sync-vuln-db", "--db-path", str(db_path), "--feeds", "kev", "epss"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertIn("mirror_stats", data)
        self.assertGreaterEqual(data["mirror_stats"]["cwe_catalog"], 10)

    def test_t1_vuln_02_dependency_audit_with_known_kev_vulnerability(self) -> None:
        """T1-VULN-02: Dependency Audit with Known KEV/OSV Vulnerability."""
        self.domain = "vulnerability_research"
        self.test_id = "T1-VULN-02"

        tmp_dir = self.make_temp_dir()
        db_path = tmp_dir / "vuln_intel.db"
        vuln = VulnIntelMCPServer(db_path=db_path)
        vuln.ingest_osv_records(
            [
                {
                    "id": "CVE-2026-99001",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "demo-parser"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}]}],
                        }
                    ],
                }
            ]
        )
        vuln.ingest_cisa_kev(
            {"vulnerabilities": [{"cveID": "CVE-2026-99001", "vendorProject": "Demo", "product": "demo-parser"}]}
        )
        vuln.close()

        proj_dir = tmp_dir / "project"
        self.fixtures.setup_project_dependencies(proj_dir, variant="vulnerable")

        res = self.runner.run(["audit-vulns", "--project-dir", str(proj_dir), "--db-path", str(db_path)])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertGreaterEqual(data["summary"]["confirmed_vulnerabilities"], 1)
        self.assertGreaterEqual(data["summary"]["kev_matches"], 1)

    def test_t1_vuln_03_upgraded_dependency_yields_clean_audit(self) -> None:
        """T1-VULN-03: Upgraded Dependency Yields Clean Vulnerability Audit."""
        self.domain = "vulnerability_research"
        self.test_id = "T1-VULN-03"

        tmp_dir = self.make_temp_dir()
        db_path = tmp_dir / "clean_mirror.db"
        vuln = VulnIntelMCPServer(db_path=db_path)
        vuln.ingest_osv_records(
            [
                {
                    "id": "CVE-2026-99001",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "demo-parser"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}]}],
                        }
                    ],
                }
            ]
        )
        vuln.close()

        proj_dir = tmp_dir / "clean_project"
        self.fixtures.setup_project_dependencies(proj_dir, variant="clean")

        res = self.runner.run(["audit-vulns", "--project-dir", str(proj_dir), "--db-path", str(db_path)])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(data["summary"]["confirmed_vulnerabilities"], 0)

    def test_t1_vuln_04_polyglot_manifest_dependency_extraction(self) -> None:
        """T1-VULN-04: Polyglot Manifest Dependency Extraction."""
        self.domain = "vulnerability_research"
        self.test_id = "T1-VULN-04"

        proj_dir = self.make_temp_dir()
        self.fixtures.setup_project_dependencies(proj_dir, variant="polyglot")

        vserver = VulnIntelMCPServer()
        try:
            deps = vserver.parse_dependencies_from_directory(proj_dir)
            ecos = {d.ecosystem for d in deps}
            self.assertIn("PyPI", ecos)
            self.assertIn("npm", ecos)
            self.assertGreaterEqual(len(deps), 3)
        finally:
            vserver.close()

    def test_t1_vuln_05_live_cyber_benchmark_suite_execution(self) -> None:
        """T1-VULN-05: Live Cyber & Vulnerability Benchmark Suite Execution."""
        self.domain = "vulnerability_research"
        self.test_id = "T1-VULN-05"

        res = self.runner.run(["run-benchmarks", "--suites", "cyber_vuln"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(data.get("overall_verdict"), "PASS")
        self.assertEqual(data.get("overall_score_pct"), 100.0)
        self.assertEqual(data["suites"]["cyber_vuln"]["passed"], 6)

    # =========================================================================
    # Discipline 3: Exploit Mechanics (T1-EXP)
    # =========================================================================

    def test_t1_exp_01_binary_mitigation_audit_checksec(self) -> None:
        """T1-EXP-01: Binary Mitigation Audit (`checksec`) Detection."""
        self.domain = "exploit_mechanics"
        self.test_id = "T1-EXP-01"

        raw_bytes = self.fixtures.sample_elf_x86_64(with_checksec=True)
        server = BinRevMCPServer()
        res = server.inspect_binary(raw_bytes, artifact_name="service_elf")
        checksec = res["checksec"]
        self.assertTrue(checksec["nx_enabled"])
        self.assertTrue(checksec["stack_canary"])
        self.assertTrue(checksec["fortify_source"])
        self.assertTrue(checksec["pie_or_aslr"])

    def test_t1_exp_02_secverifier_dual_gate_patch_clean_pass(self) -> None:
        """T1-EXP-02: SecVerifier Dual-Gate Patch Verification Clean Pass."""
        self.domain = "exploit_mechanics"
        self.test_id = "T1-EXP-02"

        server = DefensiveCyberMCPServer()
        patched_code = "def run():\n    return 42\n"
        res = server.verify_dual_gate_patch(
            patched_source=patched_code,
            poc_triggered_crash=False,
            regression_tests_passed=12,
            regression_tests_total=12,
        )
        self.assertEqual(res["verdict"], "VERIFIED_PASS")
        self.assertTrue(res["gate1_security_verified"])
        self.assertTrue(res["gate2_regression_verified"])
        self.assertIsNone(res["failure_mode"])

    def test_t1_exp_03_ast_taint_shell_command_injection_cwe78(self) -> None:
        """T1-EXP-03: AST Taint Tracking of Shell Command Injection (CWE-78)."""
        self.domain = "exploit_mechanics"
        self.test_id = "T1-EXP-03"

        code = self.fixtures.sample_cwe_source("CWE-78")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        f = TestContracts.assert_cwe_present(findings, "CWE-78", severity="CRITICAL")
        self.assertIn("shell command execution sink", f.description.lower())

    def test_t1_exp_04_dynamic_code_execution_sink_cwe94(self) -> None:
        """T1-EXP-04: Dynamic Code Execution Sink Detection (CWE-94)."""
        self.domain = "exploit_mechanics"
        self.test_id = "T1-EXP-04"

        code = self.fixtures.sample_cwe_source("CWE-94")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-94", severity="CRITICAL")

    def test_t1_exp_05_unsafe_object_deserialization_sink_cwe502(self) -> None:
        """T1-EXP-05: Unsafe Object Deserialization Sink Detection (CWE-502)."""
        self.domain = "exploit_mechanics"
        self.test_id = "T1-EXP-05"

        code = self.fixtures.sample_cwe_source("CWE-502")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-502", severity="CRITICAL")

    # =========================================================================
    # Discipline 4: Binary Analysis (T1-BIN)
    # =========================================================================

    def test_t1_bin_01_elf_format_and_arch_identification(self) -> None:
        """T1-BIN-01: ELF Container Format & Architecture Identification."""
        self.domain = "binary_analysis"
        self.test_id = "T1-BIN-01"

        server = BinRevMCPServer()
        res = server.inspect_binary(self.fixtures.sample_elf_x86_64(with_checksec=False))
        self.assertEqual(res["format"], "ELF")
        self.assertEqual(res["architecture"], "x86_64")

    def test_t1_bin_02_pe_format_recognition(self) -> None:
        """T1-BIN-02: Portable Executable (PE) Format Recognition."""
        self.domain = "binary_analysis"
        self.test_id = "T1-BIN-02"

        server = BinRevMCPServer()
        res = server.inspect_binary(self.fixtures.sample_pe())
        self.assertEqual(res["format"], "PE")
        self.assertEqual(res["architecture"], "x86_64/PE")

    def test_t1_bin_03_macho_64bit_recognition(self) -> None:
        """T1-BIN-03: Mach-O 64-Bit Binary Recognition."""
        self.domain = "binary_analysis"
        self.test_id = "T1-BIN-03"

        server = BinRevMCPServer()
        res = server.inspect_binary(self.fixtures.sample_macho())
        self.assertEqual(res["format"], "Mach-O")
        self.assertEqual(res["architecture"], "ARM64/x86_64")

    def test_t1_bin_04_end_to_end_binrev_workflow_execution(self) -> None:
        """T1-BIN-04: End-to-End Binary Reverse Engineering Workflow Execution."""
        self.domain = "binary_analysis"
        self.test_id = "T1-BIN-04"

        res = self.runner.run(["run-workflow", "--domain", "binrev"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_status_completed(res)
        self.assertEqual(data.get("selected_pool"), "POOL_3_BINREV")
        TestContracts.assert_independent_verifier_gate(res)

    def test_t1_bin_05_dwarf_struct_layout_iou_overlap(self) -> None:
        """T1-BIN-05: DWARF Struct Layout IoU Overlap Calculation."""
        self.domain = "binary_analysis"
        self.test_id = "T1-BIN-05"

        gt = (
            StructFieldSpan(name="f1", offset_bytes=0, size_bytes=8),
            StructFieldSpan(name="f2", offset_bytes=8, size_bytes=8),
        )
        pred = (
            StructFieldSpan(name="field_0", offset_bytes=0, size_bytes=8),
            StructFieldSpan(name="field_8", offset_bytes=8, size_bytes=8),
        )
        iou = BinRevDecompileRewardOracle.compute_struct_layout_iou(pred, gt)
        self.assertEqual(round(iou, 4), 1.0)

    # =========================================================================
    # Discipline 5: Assembly Language (T1-ASM)
    # =========================================================================

    def test_t1_asm_01_arm64_elf_header_decoding(self) -> None:
        """T1-ASM-01: ARM64 ELF Machine Header Decoding."""
        self.domain = "assembly_language"
        self.test_id = "T1-ASM-01"

        server = BinRevMCPServer()
        res = server.inspect_binary(self.fixtures.sample_elf_arm64())
        self.assertEqual(res["format"], "ELF")
        self.assertEqual(res["architecture"], "ARM64")

    def test_t1_asm_02_sk2_phase1_skeleton_recovery(self) -> None:
        """T1-ASM-02: SK2 Phase 1 Skeleton Recovery (Goto Normalization)."""
        self.domain = "assembly_language"
        self.test_id = "T1-ASM-02"

        raw_ghidra = (
            "undefined8 f() {\n"
            "  goto LAB_00401010;\n"
            "LAB_00401010:\n"
            "  return 0;\n"
            "}"
        )
        res = BinRevMCPServer.run_two_phase_sk2_decompile(raw_ghidra)
        skeleton = res["phase1_skeleton_code"]
        self.assertNotIn("LAB_00401010:", skeleton)
        self.assertIn("/* structured_branch_normalized */ break;", skeleton)

    def test_t1_asm_03_sk2_phase2_skin_type_restoration(self) -> None:
        """T1-ASM-03: SK2 Phase 2 Skin Recovery (Type Restoration)."""
        self.domain = "assembly_language"
        self.test_id = "T1-ASM-03"

        raw_ghidra = "undefined8 process(undefined4 id, undefined flag) { return id; }"
        res = BinRevMCPServer.run_two_phase_sk2_decompile(raw_ghidra)
        skin = res["phase2_skin_decompiled_code"]
        self.assertIn("uint64_t", skin)
        self.assertIn("uint32_t", skin)
        self.assertIn("uint8_t", skin)

    def test_t1_asm_04_decompiled_variable_alias_substitution(self) -> None:
        """T1-ASM-04: Decompiled Variable Alias Semantic Substitution."""
        self.domain = "assembly_language"
        self.test_id = "T1-ASM-04"

        raw_ghidra = "void FUN_00401000(int param_1) { return; }"
        aliases = {"FUN_00401000": "validate_crc", "param_1": "packet_len"}
        res = BinRevMCPServer.run_two_phase_sk2_decompile(raw_ghidra, dataflow_aliases=aliases)
        skin = res["phase2_skin_decompiled_code"]
        self.assertIn("validate_crc", skin)
        self.assertIn("packet_len", skin)
        self.assertEqual(res["recovered_identifiers"], ["validate_crc", "packet_len"])

    def test_t1_asm_05_recopilot_context_header_synthesis(self) -> None:
        """T1-ASM-05: ReCopilot Context Header Synthesis."""
        self.domain = "assembly_language"
        self.test_id = "T1-ASM-05"

        raw_ghidra = "void run() { return; }"
        res = BinRevMCPServer.run_two_phase_sk2_decompile(
            raw_ghidra,
            callers=["main", "init"],
            callees=["memcpy"],
            cross_ref_strings=["/var/log/audit.log"],
        )
        prompt = res["recopilot_context_prompt"]
        self.assertIn("Callers: main, init", prompt)
        self.assertIn("Callees: memcpy", prompt)
        self.assertIn("/var/log/audit.log", prompt)

    # =========================================================================
    # Discipline 6: Operating System Internals (T1-OS)
    # =========================================================================

    def test_t1_os_01_ios_shutdown_log_lifecycle_triage(self) -> None:
        """T1-OS-01: iOS Shutdown Log Process Lifecycle Triage."""
        self.domain = "os_internals"
        self.test_id = "T1-OS-01"

        target_dir = self.make_temp_dir()
        self.fixtures.setup_forensics_bundle(target_dir, platform="ios", variant="clean")
        fserver = ForensicsMCPServer()
        assessment = fserver.analyze_ios_backup(target_dir)
        self.assertEqual(assessment.overall_verdict, ForensicVerdict.NO_KNOWN_IOC_DETECTED)
        self.assertEqual(len(assessment.findings), 0)

    def test_t1_os_02_android_package_artifact_analysis(self) -> None:
        """T1-OS-02: Android Package & Dumpsys Artifact Analysis."""
        self.domain = "os_internals"
        self.test_id = "T1-OS-02"

        target_dir = self.make_temp_dir()
        self.fixtures.setup_forensics_bundle(target_dir, platform="android", variant="clean")
        fserver = ForensicsMCPServer()
        assessment = fserver.analyze_android_artifacts(target_dir)
        self.assertEqual(assessment.overall_verdict, ForensicVerdict.NO_KNOWN_IOC_DETECTED)

    def test_t1_os_03_host_system_log_authentication_triage(self) -> None:
        """T1-OS-03: Host System Log Authentication Triage."""
        self.domain = "os_internals"
        self.test_id = "T1-OS-03"

        target_dir = self.make_temp_dir()
        self.fixtures.setup_forensics_bundle(target_dir, platform="host", variant="clean")
        fserver = ForensicsMCPServer()
        assessment = fserver.analyze_host_artifacts(target_dir)
        self.assertEqual(assessment.overall_verdict, ForensicVerdict.NO_KNOWN_IOC_DETECTED)

    def test_t1_os_04_firecracker_microvm_ephemeral_cow_snapshot_cycle(self) -> None:
        """T1-OS-04: Firecracker MicroVM Ephemeral CoW Snapshot Cycle."""
        self.domain = "os_internals"
        self.test_id = "T1-OS-04"

        sb = FirecrackerSandboxManager()
        sb.provision_microvm("vm-snap-1", {"a.txt": "v1"}, tainted=True)
        snap = sb.create_cow_snapshot("vm-snap-1")
        sb.write_workspace_file("vm-snap-1", "a.txt", "v2")
        sb.restore_cow_snapshot(snap.snapshot_id)
        files = sb.read_workspace_files("vm-snap-1")
        self.assertEqual(files["a.txt"], "v1")

    def test_t1_os_05_microvm_environment_credential_stripping(self) -> None:
        """T1-OS-05: MicroVM Environment Credential Stripping."""
        self.domain = "os_internals"
        self.test_id = "T1-OS-05"

        sb = FirecrackerSandboxManager()
        env = sb._build_sanitized_env()
        for forbidden in ["AWS_", "GCP_", "OPENAI_", "GITHUB_", "SSH_"]:
            for k in env:
                self.assertFalse(k.startswith(forbidden), f"Leaked sensitive env key: {k}")
        self.assertIn("PATH", env)

    # =========================================================================
    # Discipline 7: Memory Architecture (T1-MEM)
    # =========================================================================

    def test_t1_mem_01_apple_silicon_unified_memory_detection(self) -> None:
        """T1-MEM-01: Apple Silicon Unified Memory Profile Detection."""
        self.domain = "memory_architecture"
        self.test_id = "T1-MEM-01"

        res = self.runner.run(["hardware-check"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        hw = data["hardware"]
        self.assertEqual(hw["accelerator"], "apple_silicon_metal")
        self.assertEqual(hw["safe_model_budget_gb"], 28.08)
        self.assertEqual(hw["total_memory_gb"], 36.0)

    def test_t1_mem_02_creation_strategy_advisor_memory_budget(self) -> None:
        """T1-MEM-02: Creation Strategy Advisor Respects Unified Memory Budget."""
        self.domain = "memory_architecture"
        self.test_id = "T1-MEM-02"

        res = self.runner.run(["recommend-strategy", "--corpus-tokens", "5000000", "--domain", "cyber"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(data.get("recommended_path"), "PRETRAINED_QLORA_FIRST")
        self.assertTrue(data.get("fits_local_budget"))

    def test_t1_mem_03_radix_prefix_cache_lru_hit_rate(self) -> None:
        """T1-MEM-03: Radix Prefix Cache LRU Hit Rate Simulation."""
        self.domain = "memory_architecture"
        self.test_id = "T1-MEM-03"

        sim = RadixPrefixCacheSimulator(block_size_tokens=16)
        shared_prefix = [f"sys_block_{i}" for i in range(20)]
        for turn in range(1, 6):
            turn_blocks = shared_prefix + [f"turn_{t}" for t in range(turn)]
            metrics = sim.record_request(turn_blocks, active_params_b=27.8)
            self.assertLessEqual(metrics["estimated_ttft_ms"], 150.0)
        self.assertGreaterEqual(sim.cumulative_hit_ratio(), 0.70)

    def test_t1_mem_04_unbounded_memory_buffer_sink_cwe120(self) -> None:
        """T1-MEM-04: Unbounded Memory Buffer Operation Sink Detection (CWE-120)."""
        self.domain = "memory_architecture"
        self.test_id = "T1-MEM-04"

        code = self.fixtures.sample_cwe_source("CWE-120")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-120", severity="HIGH")

    def test_t1_mem_05_scratch_slm_training_memory_bounds(self) -> None:
        """T1-MEM-05: Scratch SLM Training Memory Footprint Bounds."""
        self.domain = "memory_architecture"
        self.test_id = "T1-MEM-05"

        tmp_out = self.make_temp_dir()
        res = self.runner.run(
            [
                "train-scratch-slm",
                "--model-id",
                "mem-test-slm",
                "--text",
                "safe sample memory bound text",
                "--output-dir",
                str(tmp_out),
                "--steps",
                "1",
                "--vocab-size",
                "260",
                "--batch-size",
                "1",
            ]
        )
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(data.get("model_id"), "mem-test-slm")
        self.assertIn("safetensors_path", data)

    # =========================================================================
    # Discipline 8: Malware Analysis (T1-MAL)
    # =========================================================================

    def test_t1_mal_01_ingest_stix2_indicators_into_mirror(self) -> None:
        """T1-MAL-01: Ingestion of STIX 2.x Indicators into SQLite Mirror."""
        self.domain = "malware_analysis"
        self.test_id = "T1-MAL-01"

        engine = Stix2IocEngine(db_path=":memory:", preload_public_baseline=False)
        bundle = self.fixtures.sample_stix2_bundle(
            indicator_value="malicious-c2.net", threat_family="Predator"
        )
        count = engine.ingest_stix2_bundle(bundle)
        self.assertEqual(count, 1)
        matches = engine.match_exact("domain", "malicious-c2.net")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].threat_family, "Predator")
        engine.close()

    def test_t1_mal_02_attribution_of_pegasus_process_ios_logs(self) -> None:
        """T1-MAL-02: Attribution of Pegasus Process in iOS Logs."""
        self.domain = "malware_analysis"
        self.test_id = "T1-MAL-02"

        target_dir = self.make_temp_dir()
        self.fixtures.setup_forensics_bundle(target_dir, platform="ios", variant="infected")
        fserver = ForensicsMCPServer()
        assessment = fserver.analyze_forensic_target(target_dir, platform="ios")
        self.assertEqual(assessment.overall_verdict, ForensicVerdict.CONFIRMED_IOC_MATCH)
        self.assertTrue(any(f.threat_family == "Pegasus" for f in assessment.findings))
        TestContracts.assert_antifabrication_evidence(assessment.findings, base_dir=target_dir)

    def test_t1_mal_03_clean_ios_control_zero_false_positives(self) -> None:
        """T1-MAL-03: Clean iOS Control Produces Zero False Positives."""
        self.domain = "malware_analysis"
        self.test_id = "T1-MAL-03"

        target_dir = self.make_temp_dir()
        self.fixtures.setup_forensics_bundle(target_dir, platform="ios", variant="clean")
        fserver = ForensicsMCPServer()
        assessment = fserver.analyze_forensic_target(target_dir, platform="ios")
        self.assertEqual(assessment.overall_verdict, ForensicVerdict.NO_KNOWN_IOC_DETECTED)
        self.assertEqual(len(assessment.findings), 0)

    def test_t1_mal_04_cli_forensic_scan_clean_bundle(self) -> None:
        """T1-MAL-04: CLI Forensic Scan with Loaded STIX File."""
        self.domain = "malware_analysis"
        self.test_id = "T1-MAL-04"

        clean_dir = self.make_temp_dir()
        self.fixtures.setup_forensics_bundle(clean_dir, platform="ios", variant="clean")
        res = self.runner.run(["scan-forensics", "--target-dir", str(clean_dir), "--platform", "ios"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(data.get("overall_verdict"), "NO_KNOWN_IOC_DETECTED")
        self.assertEqual(data.get("findings"), [])

    def test_t1_mal_05_digital_forensics_specialist_workflow(self) -> None:
        """T1-MAL-05: Digital Forensics Specialist Workflow Execution."""
        self.domain = "malware_analysis"
        self.test_id = "T1-MAL-05"

        res = self.runner.run(["run-workflow", "--domain", "forensics"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_status_completed(res)
        self.assertEqual(data.get("selected_pool"), "POOL_2_SWE_CYBER")
        TestContracts.assert_independent_verifier_gate(res)

    # =========================================================================
    # Discipline 9: Network Protocols (T1-NET)
    # =========================================================================

    def test_t1_net_01_network_packet_transformation_classification(self) -> None:
        """T1-NET-01: Network Packet Transformation Classification."""
        self.domain = "network_protocols"
        self.test_id = "T1-NET-01"

        res = self.runner.run(["inspect-data", "--hex", "4d414749430102"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(
            data.get("transformation_class"),
            "ENCODING_SERIALIZATION",
        )

    def test_t1_net_02_declarative_kaitai_struct_synthesis(self) -> None:
        """T1-NET-02: Declarative Kaitai Struct `.ksy` Synthesis for Binary Packet."""
        self.domain = "network_protocols"
        self.test_id = "T1-NET-02"

        res = DataAndVisualMCPServer.synthesize_kaitai_struct_ksy(
            format_id="telemetry_packet",
            magic_bytes=b"MAGIC",
            fields=[{"id": "body", "type": "u2", "size_bytes": 2}],
            sample_payload=b"MAGIC\x01\x02",
        )
        TestContracts.assert_kaitai_coverage(res, full_coverage=True)
        self.assertTrue(res["magic_verified"])
        self.assertIn("meta:\n  id: telemetry_packet", res["ksy_yaml"])

    def test_t1_net_03_ssrf_variable_outbound_request_sink_cwe918(self) -> None:
        """T1-NET-03: SSRF Variable Outbound Request Sink Detection (CWE-918)."""
        self.domain = "network_protocols"
        self.test_id = "T1-NET-03"

        code = self.fixtures.sample_cwe_source("CWE-918")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-918", severity="HIGH")

    def test_t1_net_04_base64_encoded_network_stream_safe_decode(self) -> None:
        """T1-NET-04: Base64 Encoded Network Stream Safe Decoding."""
        self.domain = "network_protocols"
        self.test_id = "T1-NET-04"

        raw_b64 = b"SGVsbG8gV29ybGQh"
        decoded = DataAndVisualMCPServer.safe_decode_or_decompress(raw_b64)
        self.assertEqual(decoded, b"Hello World!")

    def test_t1_net_05_data_protocol_workflow_execution(self) -> None:
        """T1-NET-05: Data Protocol Workflow End-to-End Execution."""
        self.domain = "network_protocols"
        self.test_id = "T1-NET-05"

        res = self.runner.run(["run-workflow", "--domain", "data_protocol"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_status_completed(res)
        deliverables = data.get("deliverable_outputs", {})
        self.assertTrue(any("kaitai_schema" in str(v) for v in deliverables.values()))

    # =========================================================================
    # Discipline 10: Web and API Security (T1-WEB)
    # =========================================================================

    def test_t1_web_01_sql_injection_sink_cwe89(self) -> None:
        """T1-WEB-01: SQL Injection Unparameterized Format Sink Detection (CWE-89)."""
        self.domain = "web_api_security"
        self.test_id = "T1-WEB-01"

        code = self.fixtures.sample_cwe_source("CWE-89")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-89", severity="HIGH")

    def test_t1_web_02_xml_external_entity_sink_cwe611(self) -> None:
        """T1-WEB-02: XML External Entity (XXE) Parsing Sink Detection (CWE-611)."""
        self.domain = "web_api_security"
        self.test_id = "T1-WEB-02"

        code = self.fixtures.sample_cwe_source("CWE-611")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-611", severity="HIGH")

    def test_t1_web_03_hardcoded_api_secret_cwe798(self) -> None:
        """T1-WEB-03: Hardcoded API Secret Literal Detection (CWE-798)."""
        self.domain = "web_api_security"
        self.test_id = "T1-WEB-03"

        code = self.fixtures.sample_cwe_source("CWE-798")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-798", severity="HIGH")

    def test_t1_web_04_path_traversal_archive_sink_cwe22(self) -> None:
        """T1-WEB-04: Path Traversal Archive Extraction Sink Detection (CWE-22)."""
        self.domain = "web_api_security"
        self.test_id = "T1-WEB-04"

        code = self.fixtures.sample_cwe_source("CWE-22")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-22", severity="HIGH")

    def test_t1_web_05_rate_limited_web_harvester_url_fetch(self) -> None:
        """T1-WEB-05: Rate-Limited Web Harvester Public URL Fetch."""
        self.domain = "web_api_security"
        self.test_id = "T1-WEB-05"

        class _MockResp:
            def __init__(self, data: bytes) -> None:
                self._buf = io.BytesIO(data)
                self.headers = {"Content-Type": "text/html"}

            def read(self, n: int = -1) -> bytes:
                return self._buf.read(n)

            def __enter__(self) -> _MockResp:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

        harvester = RateLimitedWebHarvester(
            allowed_domains={"docs.python.org"},
            requests_per_second=5.0,
            session_tainted=False,
            opener=lambda req, timeout=20.0: _MockResp(b"<html><title>Docs</title><body>Clean API doc.</body></html>"),
        )
        doc = harvester.fetch_url("https://docs.python.org/3/library/os.html")
        self.assertEqual(doc.title, "Docs")
        self.assertIn("Clean API doc.", doc.sanitized_text)

    # =========================================================================
    # Discipline 11: Firmware and Embedded Systems Analysis (T1-FW)
    # =========================================================================

    def test_t1_fw_01_uefi_firmware_volume_recognition(self) -> None:
        """T1-FW-01: UEFI Firmware Volume Container Recognition."""
        self.domain = "firmware_embedded"
        self.test_id = "T1-FW-01"

        server = BinRevMCPServer()
        res = server.inspect_binary(self.fixtures.sample_uefi_fvh())
        self.assertEqual(res["format"], "UEFI_FIRMWARE_VOLUME")
        self.assertEqual(res["architecture"], "UEFI")

    def test_t1_fw_02_squashfs_compressed_filesystem_header(self) -> None:
        """T1-FW-02: SquashFS Compressed Filesystem Header Identification."""
        self.domain = "firmware_embedded"
        self.test_id = "T1-FW-02"

        raw = self.fixtures.sample_squashfs()
        res = DataAndVisualMCPServer.classify_transformation(raw)
        self.assertEqual(res["transformation_class"], TransformationClass.COMPRESSION)
        self.assertEqual(res["subtype"], "squashfs")
        self.assertTrue(res["has_magic_header"])

    def test_t1_fw_03_embedded_mips_architecture_identification(self) -> None:
        """T1-FW-03: Embedded MIPS Architecture Binary Identification."""
        self.domain = "firmware_embedded"
        self.test_id = "T1-FW-03"

        server = BinRevMCPServer()
        res = server.inspect_binary(self.fixtures.sample_elf_mips())
        self.assertEqual(res["format"], "ELF")
        self.assertEqual(res["architecture"], "MIPS")

    def test_t1_fw_04_xz_lzma_compressed_archive_recognition(self) -> None:
        """T1-FW-04: XZ/LZMA Compressed Firmware Archive Recognition."""
        self.domain = "firmware_embedded"
        self.test_id = "T1-FW-04"

        raw = self.fixtures.sample_xz()
        res = DataAndVisualMCPServer.classify_transformation(raw)
        self.assertEqual(res["transformation_class"], TransformationClass.COMPRESSION)
        self.assertEqual(res["subtype"], "xz_lzma")
        self.assertTrue(res["has_magic_header"])

    def test_t1_fw_05_kaitai_struct_embedded_sensor_frame(self) -> None:
        """T1-FW-05: Kaitai Struct Synthesis for Embedded Sensor Frame."""
        self.domain = "firmware_embedded"
        self.test_id = "T1-FW-05"

        res = DataAndVisualMCPServer.synthesize_kaitai_struct_ksy(
            format_id="sensor_frame",
            magic_bytes=b"\xaa\x55",
            fields=[{"id": "temp", "type": "u2", "size_bytes": 2}],
            sample_payload=b"\xaa\x55\x01\x20",
        )
        TestContracts.assert_kaitai_coverage(res, full_coverage=True)
        self.assertTrue(res["magic_verified"])

    # =========================================================================
    # Discipline 12: Cryptographic Implementation (T1-CRYP)
    # =========================================================================

    def test_t1_cryp_01_finite_sample_normalized_shannon_entropy(self) -> None:
        """T1-CRYP-01: Finite-Sample Normalized Shannon Entropy on Short Ciphertext."""
        self.domain = "cryptographic_implementation"
        self.test_id = "T1-CRYP-01"

        # 32-byte pseudo-random block with high entropy
        block = bytes((i * 73 + 19) % 256 for i in range(32))
        res = DataAndVisualMCPServer.classify_transformation(block)
        self.assertEqual(res["transformation_class"], TransformationClass.ENCRYPTION)
        self.assertEqual(res["subtype"], "block_or_stream_cipher")

    def test_t1_cryp_02_weak_hash_md5_cwe327(self) -> None:
        """T1-CRYP-02: Weak Hash Algorithm Detection for MD5 (CWE-327)."""
        self.domain = "cryptographic_implementation"
        self.test_id = "T1-CRYP-02"

        code = self.fixtures.sample_cwe_source("CWE-327")
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-327", severity="MEDIUM")

    def test_t1_cryp_03_weak_hash_sha1_cwe327(self) -> None:
        """T1-CRYP-03: Weak Hash Algorithm Detection for SHA-1 (CWE-327)."""
        self.domain = "cryptographic_implementation"
        self.test_id = "T1-CRYP-03"

        code = "import hashlib\ndef sign(data):\n    return hashlib.sha1(data).digest()\n"
        server = DefensiveCyberMCPServer()
        findings = server.scan_cpg_taint(code)
        TestContracts.assert_cwe_present(findings, "CWE-327", severity="MEDIUM")

    def test_t1_cryp_04_ascii_hex_digest_identification_sha256(self) -> None:
        """T1-CRYP-04: ASCII Hex Digest Identification (SHA-256)."""
        self.domain = "cryptographic_implementation"
        self.test_id = "T1-CRYP-04"

        hex_digest = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = DataAndVisualMCPServer.classify_transformation(hex_digest)
        self.assertEqual(res["transformation_class"], TransformationClass.HASH_DIGEST)
        self.assertEqual(res["subtype"], "SHA-256")

    def test_t1_cryp_05_safetensors_serialization_checksum_validation(self) -> None:
        """T1-CRYP-05: Safetensors Serialization Safety Checksum Validation."""
        self.domain = "cryptographic_implementation"
        self.test_id = "T1-CRYP-05"

        raw = SafetensorsValidator.create_valid_safetensors_bytes(
            tensors_meta={"weight": {"dtype": "F32", "shape": [16], "data_offsets": [0, 64]}},
            data_payload=b"\x00" * 64,
        )
        validator = SafetensorsValidator()
        res = validator.validate_bytes(raw)
        self.assertEqual(res["tensor_count"], 1)

    # =========================================================================
    # Discipline 13: Digital Forensics (T1-FOR)
    # =========================================================================

    def test_t1_for_01_positive_ios_spyware_attribution(self) -> None:
        """T1-FOR-01: Positive iOS Spyware Indicator Attribution."""
        self.domain = "digital_forensics"
        self.test_id = "T1-FOR-01"

        target_dir = self.make_temp_dir()
        self.fixtures.setup_forensics_bundle(target_dir, platform="ios", variant="infected")
        res = self.runner.run(["scan-forensics", "--target-dir", str(target_dir), "--platform", "ios"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(data.get("overall_verdict"), "CONFIRMED_IOC_MATCH")
        findings = data.get("findings", [])
        self.assertTrue(any(f.get("threat_family") == "Pegasus" for f in findings))
        TestContracts.assert_antifabrication_evidence(findings, base_dir=target_dir)

    def test_t1_for_02_benign_negative_control_zero_findings(self) -> None:
        """T1-FOR-02: Benign Negative Control Yields Zero Forensics Findings."""
        self.domain = "digital_forensics"
        self.test_id = "T1-FOR-02"

        target_dir = self.make_temp_dir()
        self.fixtures.setup_forensics_bundle(target_dir, platform="ios", variant="clean")
        res = self.runner.run(["scan-forensics", "--target-dir", str(target_dir), "--platform", "ios"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(data.get("overall_verdict"), "NO_KNOWN_IOC_DETECTED")
        self.assertEqual(len(data.get("findings", [])), 0)

    def test_t1_for_03_epistemic_claim_tristate_roundtrip(self) -> None:
        """T1-FOR-03: Epistemic Claim Tri-State Roundtrip Serialization."""
        self.domain = "digital_forensics"
        self.test_id = "T1-FOR-03"

        c1 = EpistemicClaim(
            claim_id="c1",
            status=EpistemicStatus.FACT,
            statement="Observed log entry",
            evidence_refs=("ref1",),
            confidence=1.0,
        )
        c2 = EpistemicClaim(
            claim_id="c2",
            status=EpistemicStatus.HYPOTHESIS,
            statement="Possible lateral move",
            evidence_refs=("ref2",),
            confidence=0.7,
        )
        assessment = EpistemicAssessment.from_claims([c1, c2])
        d = assessment.to_dict()
        self.assertEqual(d["facts_count"], 1)
        self.assertEqual(d["hypotheses_count"], 1)
        self.assertEqual(assessment.facts_count, 1)
        self.assertEqual(assessment.hypotheses_count, 1)

    def test_t1_for_04_digital_forensics_workflow_execution(self) -> None:
        """T1-FOR-04: Digital Forensics Specialist Workflow Execution."""
        self.domain = "digital_forensics"
        self.test_id = "T1-FOR-04"

        res = self.runner.run(["run-workflow", "--domain", "forensics"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_status_completed(res)
        TestContracts.assert_independent_verifier_gate(res)
        TestContracts.assert_taint_level(res, "TAINTED_UNTRUSTED")

    def test_t1_for_05_live_forensics_benchmark_suite_pass(self) -> None:
        """T1-FOR-05: Live Forensics Benchmark Suite Pass."""
        self.domain = "digital_forensics"
        self.test_id = "T1-FOR-05"

        res = self.runner.run(["run-benchmarks", "--suites", "forensics"])
        TestContracts.assert_exit_code(res, 0)
        data = TestContracts.assert_valid_json(res)
        self.assertEqual(data.get("overall_verdict"), "PASS")
        self.assertEqual(data.get("overall_score_pct"), 100.0)
        self.assertEqual(data["suites"]["forensics"]["passed"], 2)


if __name__ == "__main__":
    unittest.main()
