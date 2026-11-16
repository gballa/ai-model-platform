"""Unit tests verifying the resilience, thread-safety, and timeout handling of the E2E harness."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import io
import sys
import threading
import unittest
from unittest.mock import patch

from tests.e2e.harness.cli_runner import CliResult, CliRunner
from tests.e2e.test_runner import main as runner_main


class TestE2EHarnessHardening(unittest.TestCase):
    """Verifies hardening fixes for CliRunner and test_runner."""

    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_invoke_method_alias(self) -> None:
        """Verify that CliRunner.invoke is an alias to CliRunner.run and behaves identically."""
        self.assertTrue(hasattr(self.runner, "invoke"))
        self.assertEqual(CliRunner.invoke, CliRunner.run)
        res = self.runner.invoke(["hardware-check"], mode="inprocess")
        self.assertTrue(res.is_success)
        self.assertEqual(res.exit_code, 0)
        self.assertIsNotNone(res.json_data)

    def test_subprocess_timeout_expired_handled(self) -> None:
        """Verify that subprocess timeout is caught and returns structured CliResult with exit 124."""
        # Use an impossibly low timeout (1 microsecond) to force TimeoutExpired
        res = self.runner.run(["hardware-check"], mode="subprocess", timeout_sec=0.000001)
        self.assertEqual(res.exit_code, 124)
        self.assertFalse(res.is_success)
        self.assertIn("Command timed out after", res.stderr)
        self.assertIsNone(res.json_data)
        self.assertGreaterEqual(res.elapsed_ms, 0.0)

    def test_inprocess_lock_thread_safety(self) -> None:
        """Verify that CliRunner has reentrant lock and protects concurrent in-process calls."""
        self.assertTrue(hasattr(CliRunner, "_inprocess_lock"))
        self.assertIsInstance(CliRunner._inprocess_lock, type(threading.RLock()))

        def run_task() -> bool:
            result = self.runner.run(["inspect-data", "--hex", "deadbeef01"], mode="inprocess")
            return result.is_success and result.json_data is not None

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(run_task) for _ in range(12)]
            results = [f.result() for f in futures]

        self.assertEqual(len(results), 12)
        self.assertTrue(all(results))

    def test_test_runner_output_oserror_handled(self) -> None:
        """Verify that uncreatable/read-only output destination prints error and returns 1."""
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            code = runner_main(["--tier", "3", "--output", "/nonexistent/uncreatable/report.json"])
        self.assertEqual(code, 1)
        err_output = err_stream.getvalue()
        self.assertIn("[E2E] Error exporting report to /nonexistent/uncreatable/report.json", err_output)


if __name__ == "__main__":
    unittest.main()
