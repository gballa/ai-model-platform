"""Thread-safe report collector tracking multi-tier E2E test results and metrics."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import threading
from typing import Any


@dataclass
class TestRecord:
    tier: int
    domain: str
    test_id: str
    name: str
    status: str
    elapsed_ms: float
    error_message: str | None = None


class E2EReportCollector:
    """Singleton metrics accumulator for the 4-tier E2E testing track."""

    _instance: E2EReportCollector | None = None
    _lock = threading.RLock()

    def __init__(self) -> None:
        self._records: list[TestRecord] = []
        self._record_lock = threading.RLock()

    @classmethod
    def instance(cls) -> E2EReportCollector:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._lock:
            if cls._instance is not None:
                cls._instance.reset()

    def reset(self) -> None:
        with self._record_lock:
            self._records.clear()

    def record(
        self,
        tier: int,
        domain: str,
        test_id: str,
        name: str,
        status: str,
        elapsed_ms: float,
        error_message: str | None = None,
    ) -> None:
        with self._record_lock:
            self._records.append(
                TestRecord(
                    tier=tier,
                    domain=domain,
                    test_id=test_id,
                    name=name,
                    status=status,
                    elapsed_ms=round(elapsed_ms, 2),
                    error_message=error_message,
                )
            )

    def get_records(self) -> list[TestRecord]:
        with self._record_lock:
            return list(self._records)

    def get_summary(self) -> dict[str, Any]:
        with self._record_lock:
            total = len(self._records)
            passed = sum(1 for r in self._records if r.status == "PASS")
            failed = sum(1 for r in self._records if r.status == "FAIL")
            errors = sum(1 for r in self._records if r.status == "ERROR")
            skipped = sum(1 for r in self._records if r.status == "SKIP")
            total_elapsed = sum(r.elapsed_ms for r in self._records)

            by_tier: dict[int, dict[str, Any]] = {}
            for r in self._records:
                if r.tier not in by_tier:
                    by_tier[r.tier] = {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0, "elapsed_ms": 0.0}
                t = by_tier[r.tier]
                t["total"] += 1
                t["elapsed_ms"] = round(t["elapsed_ms"] + r.elapsed_ms, 2)
                if r.status == "PASS":
                    t["passed"] += 1
                elif r.status == "FAIL":
                    t["failed"] += 1
                elif r.status == "ERROR":
                    t["errors"] += 1
                elif r.status == "SKIP":
                    t["skipped"] += 1

            by_domain: dict[str, dict[str, Any]] = {}
            for r in self._records:
                if r.domain not in by_domain:
                    by_domain[r.domain] = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
                d = by_domain[r.domain]
                d["total"] += 1
                if r.status == "PASS":
                    d["passed"] += 1
                elif r.status == "FAIL":
                    d["failed"] += 1
                elif r.status == "ERROR":
                    d["errors"] += 1

            pass_rate = (passed / total * 100.0) if total > 0 else 0.0

            return {
                "overall_verdict": "PASS" if (failed == 0 and errors == 0 and total > 0) else ("FAIL" if total > 0 else "EMPTY"),
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "skipped": skipped,
                "pass_rate_pct": round(pass_rate, 2),
                "total_elapsed_ms": round(total_elapsed, 2),
                "by_tier": by_tier,
                "by_domain": by_domain,
                "records": [asdict(r) for r in self._records],
            }

    def export_json(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        summary = self.get_summary()
        target.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
