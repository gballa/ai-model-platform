"""Tests for Vulnerability Intelligence MCP, polyglot SBOM parsing, AST taint tracking, and RoE scope."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from platform_core.layer2_execution import (
    AuthorizationScope,
    DefensiveCyberMCPServer,
    IndependentVerifierAgent,
    SubTask,
    TaskStatus,
    VulnFindingClassification,
    VulnIntelMCPServer,
)
from platform_core.layer2_execution.sandbox import FirecrackerSandboxManager


class TestVulnIntelAndCyber(unittest.TestCase):
    def test_osv_nvd_kev_epss_correlation_and_polyglot_manifests(self) -> None:
        vuln = VulnIntelMCPServer()
        try:
            vuln.ingest_osv_records(
                [
                    {
                        "id": "GHSA-aaaa-1111",
                        "aliases": ["CVE-2026-12345"],
                        "summary": "Remote code execution in legacy-xml",
                        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-611"]},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "legacy-xml"},
                                "ranges": [
                                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.1.0"}]}
                                ],
                            }
                        ],
                    },
                    {
                        "id": "CVE-2026-22222",
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "mini-router"},
                                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}],
                            }
                        ],
                    },
                ]
            )
            vuln.ingest_nvd_records(
                [
                    {
                        "id": "CVE-2026-33333",
                        "package_name": "fast-serde",
                        "ecosystem": "crates.io",
                        "cvss_score": 8.4,
                        "cwe_ids": ["CWE-502"],
                        "affected_ranges": [{"introduced": "0.1.0", "fixed": "0.9.5"}],
                        "fixed_versions": ["0.9.5"],
                    }
                ]
            )
            vuln.ingest_cisa_kev(
                {"vulnerabilities": [{"cveID": "CVE-2026-12345", "vendorProject": "Acme", "product": "legacy-xml"}]}
            )
            vuln.ingest_epss_scores({"data": [{"cve": "CVE-2026-12345", "epss": "0.9412", "percentile": "0.99"}]})

            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                (root / "requirements.txt").write_text("legacy-xml==1.8.0\nunpinned-dep\n", encoding="utf-8")
                (root / "package-lock.json").write_text(
                    json.dumps({"packages": {"node_modules/mini-router": {"version": "2.4.0"}}}),
                    encoding="utf-8",
                )
                (root / "Cargo.lock").write_text(
                    '[[package]]\nname = "fast-serde"\nversion = "0.8.2"\n',
                    encoding="utf-8",
                )
                (root / "go.mod").write_text("module example.com/app\nrequire golang.org/x/net v0.25.0\n", encoding="utf-8")

                report = vuln.audit_project_dependencies(root)
                self.assertEqual(report["dependencies_scanned"], 5)
                self.assertEqual(report["summary"]["confirmed_vulnerabilities"], 3)
                self.assertEqual(report["summary"]["kev_matches"], 1)
                kev_hit = next(f for f in report["dependency_findings"] if f["vuln_id"] == "CVE-2026-12345")
                self.assertEqual(kev_hit["classification"], VulnFindingClassification.CONFIRMED_VULNERABILITY.value)
                self.assertAlmostEqual(kev_hit["epss_score"], 0.9412)

                # Upgraded version past fixed removes finding cleanly (no false positives)
                (root / "requirements.txt").write_text("legacy-xml==2.1.0\n", encoding="utf-8")
                (root / "package-lock.json").write_text(
                    json.dumps({"packages": {"node_modules/mini-router": {"version": "3.0.1"}}}),
                    encoding="utf-8",
                )
                (root / "Cargo.lock").write_text(
                    '[[package]]\nname = "fast-serde"\nversion = "0.9.5"\n',
                    encoding="utf-8",
                )
                clean_report = vuln.audit_project_dependencies(root)
                self.assertEqual(clean_report["summary"]["confirmed_vulnerabilities"], 0)
        finally:
            vuln.close()

    def test_taint_isolation_on_live_sync_and_roe_scope_guard(self) -> None:
        vuln = VulnIntelMCPServer()
        try:
            with self.assertRaises(PermissionError):
                vuln.sync_live_feeds(feeds=["kev"], session_tainted=True)

            # Clean-zone sync via mocked HTTP opener
            res = vuln.sync_live_feeds(
                feeds=["kev"],
                session_tainted=False,
                opener=lambda req, timeout: json.dumps(
                    {"vulnerabilities": [{"cveID": "CVE-2026-7777", "vendorProject": "V", "product": "P"}]}
                ).encode("utf-8"),
            )
            self.assertEqual(res["synced_counts"]["kev"], 1)

            scope = AuthorizationScope(
                engagement_id="eng-2026-01",
                authorized_targets=("10.20.0.0/24", "*.staging.internal.local"),
                valid_from_utc="2026-01-01T00:00:00Z",
                valid_until_utc="2026-12-31T23:59:59Z",
                allowed_actions=frozenset({"passive_scan", "static_audit"}),
                operator_approval_id="op-sig-alice",
            )
            ok = vuln.verify_authorization(scope, "10.20.0.15", "passive_scan", now_utc="2026-06-01T12:00:00Z")
            self.assertTrue(ok["authorized"])

            out_of_scope = vuln.verify_authorization(scope, "8.8.8.8", "passive_scan", now_utc="2026-06-01T12:00:00Z")
            self.assertFalse(out_of_scope["authorized"])

            expired = vuln.verify_authorization(scope, "app.staging.internal.local", "passive_scan", now_utc="2027-01-02T00:00:00Z")
            self.assertFalse(expired["authorized"])
        finally:
            vuln.close()

    def test_ast_taint_tracking_and_real_sandbox_poc_verification(self) -> None:
        cyber = DefensiveCyberMCPServer()
        vulnerable_code = (
            "import subprocess, urllib.request\n"
            "def handle(user_host, url):\n"
            "    cmd = f'ping -c 1 {user_host}'\n"
            "    subprocess.run(cmd, shell=True)\n"
            "    return urllib.request.urlopen(url)\n"
        )
        findings = cyber.scan_cpg_taint(vulnerable_code)
        cwes = {f.cwe_id for f in findings}
        self.assertIn("CWE-78", cwes)
        self.assertIn("CWE-918", cwes)
        self.assertTrue(any(f.source_expr.startswith("ast_taint:") for f in findings))

        # Safe shell=False call must NOT trigger CWE-78 false positive
        safe_code = (
            "import subprocess\n"
            "def handle(user_host: str) -> int:\n"
            "    return subprocess.run(['ping', '-c', '1', user_host], shell=False).returncode\n"
        )
        self.assertEqual(cyber.scan_cpg_taint(safe_code), [])

        # Real sandbox PoC execution fails in IndependentVerifierAgent when poc_script exits non-zero
        sb = FirecrackerSandboxManager()
        sb.provision_microvm("vm-poc", {"app.py": "def run():\n    return 1\n"}, tainted=True)
        verifier = IndependentVerifierAgent()
        st = SubTask(
            subtask_id="sub-poc-fail",
            title="Verify cyber fix",
            domain="cyber",
            assigned_agent="defensive_cyber",
            status=TaskStatus.AWAITING_VERIFICATION,
            candidate_output={
                "edit_applied": True,
                "patched_source": "def run():\n    return 1\n",
                "poc_script": "raise RuntimeError('PoC exploit still triggers!')\n",
                "regression_tests_passed": 5,
                "regression_tests_total": 5,
            },
        )
        verdict = verifier.verify_subtask(st, sb, "vm-poc", cyber)
        self.assertFalse(verdict["passed"])
        self.assertEqual(st.status, TaskStatus.VERIFIER_REJECTED)


if __name__ == "__main__":
    unittest.main()
