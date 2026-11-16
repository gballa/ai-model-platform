"""Tests for executable BenchmarkSuiteRunner, EpistemicClaim serialization, Orchestrator, & new CLI commands."""

from __future__ import annotations

from pathlib import Path
import plistlib
import tempfile
import unittest

from platform_core.cli import main as cli_main
from platform_core.layer2_execution import (
    EpistemicAssessment,
    EpistemicClaim,
    EpistemicStatus,
    ExecutionLifecycleOrchestrator,
    PlatformState,
    SQLiteStateCheckpointer,
    TaskStatus,
)
from platform_core.layer3_evolution import BenchmarkSuiteRunner


class TestBenchmarksAndEpistemic(unittest.TestCase):
    def test_epistemic_assessment_and_state_roundtrip(self) -> None:
        claims = [
            EpistemicClaim("c1", EpistemicStatus.FACT, "Verified SBOM hit", ("requirements.txt",), 0.95, "vuln_intel", requires_human_verification=True),
            EpistemicClaim("c2", EpistemicStatus.HYPOTHESIS, "Possible anomalous tmp script", ("Shutdown.log",), 0.62, "forensics", ("Dev tool",)),
            EpistemicClaim("c3", EpistemicStatus.UNCERTAIN, "Encrypted keychain unreadable", ("Manifest.plist",), 0.50, "forensics"),
        ]
        assessment = EpistemicAssessment.from_claims(claims)
        self.assertEqual(assessment.facts_count, 1)
        self.assertEqual(assessment.hypotheses_count, 1)
        self.assertEqual(assessment.uncertain_count, 1)
        self.assertTrue(assessment.human_verification_required)

        state = PlatformState(
            session_id="ep-state-1",
            objective="Test serialization",
            task_domain="forensics",
            epistemic_assessment=assessment,
        )
        cp = SQLiteStateCheckpointer(":memory:")
        try:
            cp.save_checkpoint(state)
            loaded = cp.load_latest("ep-state-1")
            assert loaded is not None and loaded.epistemic_assessment is not None
            self.assertEqual(loaded.epistemic_assessment.facts_count, 1)
            self.assertEqual(loaded.epistemic_assessment.claims[1].status, EpistemicStatus.HYPOTHESIS)
        finally:
            cp.close()

    def test_orchestrator_end_to_end_vuln_intel_and_forensics(self) -> None:
        orch = ExecutionLifecycleOrchestrator()
        try:
            orch.vuln_intel_mcp.ingest_osv_records(
                [
                    {
                        "id": "CVE-2026-5555",
                        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-78"]},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "unsafe-runner"},
                                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.1.0"}, {"fixed": "1.2.0"}]}],
                            }
                        ],
                    }
                ]
            )
            st_vuln = orch.run_workflow(
                session_id="orch-vuln-1",
                objective="Audit microservice dependencies and Python handlers",
                task_domain="vuln_intel",
                workspace_files={
                    "requirements.txt": "unsafe-runner==1.0.0\n",
                    "worker.py": "import os\ndef run(arg):\n    return os.system(arg)\n",
                },
            )
            self.assertEqual(st_vuln.status, TaskStatus.COMPLETED)
            self.assertIsNotNone(st_vuln.epistemic_assessment)
            assert st_vuln.epistemic_assessment is not None
            self.assertGreaterEqual(st_vuln.epistemic_assessment.facts_count, 2)

            st_for = orch.run_workflow(
                session_id="orch-for-1",
                objective="Triage clean encrypted iOS backup extract",
                task_domain="forensics",
                workspace_files={
                    "Manifest.plist": plistlib.dumps({"IsEncrypted": True}),
                    "Shutdown.log": "2026-11-01T10:00:00Z SIGTERM SpringBoard\n",
                },
                task_payload={"platform": "ios"},
            )
            self.assertEqual(st_for.status, TaskStatus.COMPLETED)
            self.assertIn("epistemic_assessment", st_for.final_deliverable)
            self.assertEqual(st_for.final_deliverable["epistemic_assessment"]["uncertain_count"], 1)
        finally:
            orch.close()

    def test_executable_benchmarks_and_new_cli_subcommands(self) -> None:
        bench = BenchmarkSuiteRunner.run_all_suites()
        self.assertEqual(bench["overall_verdict"], "PASS")
        self.assertEqual(bench["overall_score_pct"], 100.0)
        self.assertEqual(bench["total_cases"], 15)
        self.assertEqual(bench["suites"]["cyber_vuln"]["total"], 6)
        self.assertEqual(bench["suites"]["cyber_vuln"]["passed"], 6)

        sub_bench = BenchmarkSuiteRunner.run_all_suites(
            suites=["binary_analysis", "exploit_mechanics", "network_protocols", "roe_scope"]
        )
        self.assertEqual(sub_bench["overall_verdict"], "PASS")
        self.assertEqual(sub_bench["total_cases"], 4)
        self.assertEqual(sub_bench["total_passed"], 4)

        self.assertEqual(cli_main(["hardware-check"]), 0)
        self.assertEqual(cli_main(["run-benchmarks"]), 0)
        self.assertEqual(cli_main(["run-workflow", "--domain", "forensics"]), 0)
        self.assertEqual(cli_main(["run-workflow", "--domain", "vuln_intel"]), 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
            (root / "Shutdown.log").write_text("2026-10-01T00:00:00Z SIGTERM SpringBoard\n", encoding="utf-8")
            self.assertEqual(cli_main(["audit-vulns", "--project-dir", str(root)]), 0)
            self.assertEqual(cli_main(["scan-forensics", "--target-dir", str(root), "--platform", "ios"]), 0)


if __name__ == "__main__":
    unittest.main()
