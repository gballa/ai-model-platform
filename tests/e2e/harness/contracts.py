"""Assertion helpers, base test case, and contract validators for opaque-box E2E testing."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import time
from typing import Any
import unittest

from tests.e2e.harness.cli_runner import CliResult, CliRunner
from tests.e2e.harness.fixtures import E2EFixtures
from tests.e2e.harness.report_collector import E2EReportCollector


class TestContracts:
    """Strict schema, exit code, and invariant assertion utilities."""

    @staticmethod
    def assert_exit_code(result: CliResult, expected: int = 0, msg: str = "") -> None:
        assert (
            result.exit_code == expected
        ), f"Expected exit code {expected}, got {result.exit_code}. Stderr: {result.stderr[:300]}. {msg}"

    @staticmethod
    def assert_valid_json(result: CliResult) -> dict[str, Any]:
        assert result.json_data is not None, f"Expected valid JSON in stdout, got:\n{result.stdout[:300]}"
        assert isinstance(result.json_data, dict), f"JSON stdout must be a dictionary, got {type(result.json_data)}"
        return result.json_data

    @staticmethod
    def assert_status_completed(result: CliResult) -> dict[str, Any]:
        data = TestContracts.assert_valid_json(result)
        assert data.get("status") == "COMPLETED", f"Expected status 'COMPLETED', got: {data.get('status')}"
        return data

    @staticmethod
    def assert_subtask_completed(subtask: Any) -> None:
        status = getattr(subtask, "status", None)
        if hasattr(status, "value"):
            status_val = status.value
        elif isinstance(subtask, dict):
            status_val = subtask.get("status")
        else:
            status_val = str(status)
        assert status_val == "COMPLETED", f"Expected subtask status 'COMPLETED', got: {status_val}"

    @staticmethod
    def assert_independent_verifier_gate(result: CliResult) -> None:
        data = TestContracts.assert_valid_json(result)
        verified_by = data.get("verified_by")
        assert (
            verified_by == "independent_verifier"
        ), f"SecVerifier gate invariant violated: expected 'independent_verifier', got '{verified_by}'"

    @staticmethod
    def assert_taint_level(result: Any, expected: str = "TAINTED_UNTRUSTED") -> None:
        if hasattr(result, "json_data"):
            data = TestContracts.assert_valid_json(result)
            taint = data.get("taint_level")
        elif hasattr(result, "taint_level"):
            t = result.taint_level
            taint = getattr(t, "value", str(t))
        elif isinstance(result, dict):
            taint = result.get("taint_level")
        else:
            taint = str(result)
        assert taint == expected, f"Expected taint_level '{expected}', got '{taint}'"

    @staticmethod
    def assert_cwe_present(
        findings: list[Any],
        cwe_id: str,
        severity: str | None = None,
    ) -> Any:
        matched = []
        for f in findings:
            fid = getattr(f, "cwe_id", None) or (f.get("cwe_id") if isinstance(f, dict) else None)
            if fid == cwe_id:
                if severity:
                    fsev = getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else None)
                    if fsev == severity:
                        matched.append(f)
                else:
                    matched.append(f)
        assert len(matched) > 0, f"Expected CWE finding for '{cwe_id}' (severity={severity}), found: {findings}"
        return matched[0]

    @staticmethod
    def assert_forensics_verdict(assessment: Any, expected_verdict: str) -> None:
        v = getattr(assessment, "overall_verdict", None)
        if hasattr(v, "value"):
            actual = v.value
        elif isinstance(v, str):
            actual = v
        elif isinstance(assessment, dict):
            actual = assessment.get("overall_verdict")
        else:
            actual = str(v)
        assert actual == expected_verdict, f"Expected forensic verdict '{expected_verdict}', got '{actual}'"

    @staticmethod
    def assert_antifabrication_evidence(findings: list[Any], base_dir: Path | str | None = None) -> None:
        for f in findings:
            path = getattr(f, "artifact_path", None) or (f.get("artifact_path") if isinstance(f, dict) else None)
            sha = getattr(f, "artifact_sha256", None) or (f.get("artifact_sha256") if isinstance(f, dict) else None)
            assert path, f"Anti-fabrication invariant violated: missing artifact_path in finding {f}"
            assert sha and len(sha) == 64, f"Anti-fabrication invariant violated: invalid 64-hex SHA-256 in finding {f}"
            p = Path(path)
            if not p.is_absolute() and base_dir is not None:
                p = Path(base_dir) / p
            assert p.is_file(), f"Anti-fabrication invariant violated: referenced file does not exist: {p}"
            actual_sha = hashlib.sha256(p.read_bytes()).hexdigest()
            assert actual_sha == sha, f"Anti-fabrication invariant violated: SHA-256 mismatch for {path}: expected {sha}, actual {actual_sha}"

    @staticmethod
    def assert_kaitai_coverage(result: dict[str, Any], full_coverage: bool = True) -> None:
        assert (
            result.get("full_byte_coverage") is full_coverage
        ), f"Expected full_byte_coverage={full_coverage}, got: {result.get('full_byte_coverage')}"
        if full_coverage:
            assert result.get("byte_coverage_ratio") == 1.0


class E2EBaseTestCase(unittest.TestCase):
    """Base class for all E2E test cases across Tiers 1-4."""

    tier: int = 1
    domain: str = "general"
    test_id: str = "T-GEN"

    def setUp(self) -> None:
        super().setUp()
        self._start_perf = time.perf_counter()
        mode = os.environ.get("E2E_CLI_MODE", "inprocess")
        self.runner = CliRunner(default_mode=mode)
        self.fixtures = E2EFixtures()
        self._temp_dirs: list[Path] = []
        self._recorded: bool = False

    def make_temp_dir(self, prefix: str = "e2e_") -> Path:
        p = self.fixtures.create_temp_dir(prefix=prefix)
        self._temp_dirs.append(p)
        return p

    def record_result(
        self,
        test_id: str | None = None,
        domain: str | None = None,
        tier: int | None = None,
        status: str = "PASS",
        error_message: str | None = None,
    ) -> None:
        elapsed = (time.perf_counter() - self._start_perf) * 1000.0
        tid = test_id or getattr(self, "test_id", self._testMethodName)
        dom = domain or getattr(self, "domain", "general")
        t_num = tier if tier is not None else getattr(self, "tier", 1)
        E2EReportCollector.instance().record(
            tier=t_num,
            domain=dom,
            test_id=tid,
            name=self._testMethodName,
            status=status,
            elapsed_ms=elapsed,
            error_message=error_message,
        )
        self._recorded = True

    def tearDown(self) -> None:
        for p in self._temp_dirs:
            self.fixtures.cleanup_dir(p)
        self._temp_dirs.clear()

        # If not manually recorded, record status from exception info
        if not self._recorded:
            exc_info = sys.exc_info()
            if exc_info[0] is None:
                status = "PASS"
                err_msg = None
            elif issubclass(exc_info[0], self.failureException):
                status = "FAIL"
                err_msg = str(exc_info[1])
            else:
                status = "ERROR"
                err_msg = str(exc_info[1])

            self.record_result(status=status, error_message=err_msg)

        super().tearDown()
