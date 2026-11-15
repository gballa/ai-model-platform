"""Tests for Digital Forensics & Mercenary Spyware Detection with strict anti-fabrication."""

from __future__ import annotations

import hashlib
from pathlib import Path
import plistlib
import sqlite3
import tempfile
import unittest

from platform_core.layer2_execution import (
    DefensiveCyberMCPServer,
    ForensicsMCPServer,
    ForensicVerdict,
    IndependentVerifierAgent,
    Stix2IocEngine,
    SubTask,
    TaskStatus,
)
from platform_core.layer2_execution.sandbox import FirecrackerSandboxManager


class TestForensicsSpywareDetection(unittest.TestCase):
    def test_stix2_ingestion_and_ios_backup_spyware_vs_clean_controls(self) -> None:
        engine = Stix2IocEngine()
        fmcp = ForensicsMCPServer(ioc_engine=engine)
        try:
            loaded = engine.ingest_stix2_bundle(
                {
                    "type": "bundle",
                    "id": "bundle--demo-001",
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--1",
                            "name": "Graphite",
                            "pattern": "[domain-name:value = 'telemetry-update-paragon.example']",
                            "confidence": 96,
                        },
                        {
                            "type": "indicator",
                            "id": "indicator--2",
                            "name": "Predator",
                            "pattern": "[ipv4-addr:value = '198.51.100.42']",
                            "confidence": 94,
                        },
                    ],
                }
            )
            self.assertEqual(loaded, 2)

            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)

                # 1. Compromised synthetic iOS backup with SMS.db C2 domain + DataUsage process IOC
                infected = root / "ios_infected"
                infected.mkdir()
                (infected / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
                (infected / "Shutdown.log").write_text("2026-10-10T02:14:00Z SIGTERM SpringBoard\n", encoding="utf-8")

                du = sqlite3.connect(infected / "DataUsage.sqlite")
                du.execute("CREATE TABLE ZPROCESS (ZPROCNAME TEXT, ZBUNDLENAME TEXT)")
                du.execute("INSERT INTO ZPROCESS VALUES ('roleaboutd', 'com.apple.mobile')")
                du.commit()
                du.close()

                sms = sqlite3.connect(infected / "SMS.db")
                sms.execute("CREATE TABLE message (text TEXT, handle_id INT, date INT)")
                sms.execute("INSERT INTO message VALUES ('https://telemetry-update-paragon.example/v1', 1, 750000000)")
                sms.commit()
                sms.close()

                res_inf = fmcp.analyze_ios_backup(infected)
                self.assertEqual(res_inf.overall_verdict, ForensicVerdict.CONFIRMED_IOC_MATCH)
                self.assertTrue(res_inf.requires_human_verification)
                families = {f.threat_family for f in res_inf.findings}
                self.assertIn("Pegasus", families)
                self.assertIn("Graphite", families)
                self.assertTrue(all(len(f.artifact_sha256) == 64 for f in res_inf.findings))

                # 2. Clean benign iOS backup -> MUST return NO_KNOWN_IOC_DETECTED (zero fabrication)
                clean = root / "ios_clean"
                clean.mkdir()
                (clean / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
                (clean / "Shutdown.log").write_text("2026-10-10T02:14:00Z SIGTERM SpringBoard MobileSafari\n", encoding="utf-8")
                du_c = sqlite3.connect(clean / "DataUsage.sqlite")
                du_c.execute("CREATE TABLE ZPROCESS (ZPROCNAME TEXT, ZBUNDLENAME TEXT)")
                du_c.execute("INSERT INTO ZPROCESS VALUES ('MobileSafari', 'com.apple.mobilesafari')")
                du_c.commit()
                du_c.close()

                res_clean = fmcp.analyze_ios_backup(clean)
                self.assertEqual(res_clean.overall_verdict, ForensicVerdict.NO_KNOWN_IOC_DETECTED)
                self.assertEqual(res_clean.findings, ())
                self.assertFalse(res_clean.requires_human_verification)
        finally:
            engine.close()

    def test_android_and_host_triage_plus_anti_fabrication_verifier_gate(self) -> None:
        fmcp = ForensicsMCPServer()
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)

                # Android fixture: Predator IOC package + stealth permission triad anomaly on non-IOC app
                and_dir = root / "android_dump"
                and_dir.mkdir()
                (and_dir / "packages.xml").write_text(
                    """<packages>
  <package name="com.cytrox.alien.agent" codePath="/data/app/alien" />
  <package name="org.custom.stealthnotes" codePath="/data/local/tmp/stealth.apk">
    <perms>
      <item name="android.permission.BIND_ACCESSIBILITY_SERVICE" granted="true" />
      <item name="android.permission.READ_SMS" granted="true" />
      <item name="android.permission.RECORD_AUDIO" granted="true" />
    </perms>
  </package>
</packages>""",
                    encoding="utf-8",
                )
                res_and = fmcp.analyze_forensic_target(and_dir)
                self.assertEqual(res_and.platform, "android")
                self.assertEqual(res_and.overall_verdict, ForensicVerdict.CONFIRMED_IOC_MATCH)
                self.assertTrue(any(f.threat_family == "Predator" for f in res_and.findings))
                self.assertTrue(any(f.indicator_type == "android_permission_triad" for f in res_and.findings))

                # Host fixture: LaunchDaemon executing from /tmp -> SUSPICIOUS_ANOMALY with alternative hypotheses
                host_dir = root / "host_triage"
                (host_dir / "LaunchDaemons").mkdir(parents=True)
                (host_dir / "LaunchDaemons" / "com.vendor.helper.plist").write_text(
                    "<plist><string>/tmp/.cache_daemon</string></plist>",
                    encoding="utf-8",
                )
                res_host = fmcp.analyze_forensic_target(host_dir)
                self.assertEqual(res_host.platform, "host")
                self.assertEqual(res_host.overall_verdict, ForensicVerdict.SUSPICIOUS_ANOMALY)
                self.assertGreater(len(res_host.findings[0].alternative_benign_explanations), 0)

                # SHA-256 hash IOC detection on raw binary artifact
                payload = b"\x7fELF-mock-spyware-payload"
                payload_sha = hashlib.sha256(payload).hexdigest()
                fmcp.ioc_engine.ingest_stix2_bundle(
                    {
                        "type": "bundle",
                        "objects": [
                            {
                                "type": "indicator",
                                "id": "ind-sha-1",
                                "name": "Candiru",
                                "pattern": f"[file:hashes.'SHA-256' = '{payload_sha}']",
                            }
                        ],
                    }
                )
                (host_dir / "unknown.bin").write_bytes(payload)
                res_hash = fmcp.analyze_host_artifacts(host_dir)
                self.assertEqual(res_hash.overall_verdict, ForensicVerdict.CONFIRMED_IOC_MATCH)
        finally:
            fmcp.ioc_engine.close()

        # IndependentVerifierAgent rejects fabricated forensic claims missing SHA-256 evidence
        verifier = IndependentVerifierAgent()
        sb = FirecrackerSandboxManager()
        sb.provision_microvm("vm-fab", {}, tainted=True)
        bad_sub = SubTask(
            subtask_id="sub-fab",
            title="Triage",
            domain="forensics",
            assigned_agent="defensive_cyber",
            status=TaskStatus.AWAITING_VERIFICATION,
            candidate_output={
                "forensic_assessment": {
                    "overall_verdict": ForensicVerdict.CONFIRMED_IOC_MATCH.value,
                    "findings": [
                        {
                            "verdict": ForensicVerdict.CONFIRMED_IOC_MATCH.value,
                            "artifact_path": "",
                            "artifact_sha256": "",
                        }
                    ],
                }
            },
        )
        gate_res = verifier.verify_subtask(bad_sub, sb, "vm-fab", DefensiveCyberMCPServer())
        self.assertFalse(gate_res["passed"])
        self.assertEqual(bad_sub.status, TaskStatus.VERIFIER_REJECTED)


if __name__ == "__main__":
    unittest.main()
