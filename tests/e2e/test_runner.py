"""Standalone E2E Test Suite Runner with 4-Tier filtering, domain selection, and reporting."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import unittest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.e2e.harness.report_collector import E2EReportCollector


def build_suite(tier: str = "all", domain: str = "all") -> unittest.TestSuite:
    """Build a TestSuite filtered by tier and domain."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    tier_modules = {
        "1": "tests.e2e.test_tier1_feature_coverage",
        "2": "tests.e2e.test_tier2_boundary_corner",
        "3": "tests.e2e.test_tier3_cross_feature",
        "4": "tests.e2e.test_tier4_real_world",
    }

    selected_modules = [tier_modules[tier]] if tier in tier_modules else list(tier_modules.values())

    for mod_name in selected_modules:
        mod_suite = loader.loadTestsFromName(mod_name)
        if domain == "all":
            suite.addTests(mod_suite)
        else:
            # Filter tests by domain attribute
            for test in _flatten_suite(mod_suite):
                test_domain = getattr(test, "domain", "")
                if test_domain == domain or domain.lower() in test.id().lower():
                    suite.addTest(test)

    return suite


def _flatten_suite(suite: unittest.TestSuite | unittest.TestCase) -> list[unittest.TestCase]:
    tests: list[unittest.TestCase] = []
    if isinstance(suite, unittest.TestCase):
        return [suite]
    for item in suite:
        tests.extend(_flatten_suite(item))
    return tests


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="e2e-runner",
        description="Run E2E Test Suite across 4 tiers for platform_core",
    )
    parser.add_argument(
        "--tier",
        choices=["1", "2", "3", "4", "all"],
        default="all",
        help="Target tier: 1 (features), 2 (boundaries), 3 (pairwise), 4 (scenarios), or all",
    )
    parser.add_argument(
        "--domain",
        default="all",
        help="Target cybersecurity discipline / domain filter, or 'all'",
    )
    parser.add_argument(
        "--mode",
        choices=["inprocess", "subprocess"],
        default="inprocess",
        help="CLI execution mode: inprocess (fast capture) or subprocess (isolated process)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to write structured JSON test report",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose test progress logging",
    )

    args = parser.parse_args(argv)

    # Set mode in environment for runner harness
    os.environ["E2E_CLI_MODE"] = args.mode

    # Reset collector before execution
    collector = E2EReportCollector.instance()
    collector.reset()

    suite = build_suite(tier=args.tier, domain=args.domain)
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)

    summary = collector.get_summary()

    if args.output:
        try:
            collector.export_json(args.output)
            print(f"\n[E2E] Report exported to: {args.output}")
        except OSError as exc:
            print(f"[E2E] Error exporting report to {args.output}: {exc}", file=sys.stderr)
            return 1

    print("\n" + "=" * 60)
    print("E2E TEST RUN SUMMARY")
    print("=" * 60)
    print(f"Overall Verdict : {summary['overall_verdict']}")
    print(f"Total Tests     : {summary['total_tests']}")
    print(f"Passed          : {summary['passed']}")
    print(f"Failed          : {summary['failed']}")
    print(f"Errors          : {summary['errors']}")
    print(f"Skipped         : {summary['skipped']}")
    print(f"Pass Rate       : {summary['pass_rate_pct']}%")
    print(f"Total Elapsed   : {summary['total_elapsed_ms']} ms")
    print("=" * 60)

    for t_num, t_data in sorted(summary["by_tier"].items()):
        print(f"  Tier {t_num}: {t_data['passed']}/{t_data['total']} passed ({t_data['elapsed_ms']} ms)")
    print("=" * 60)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
