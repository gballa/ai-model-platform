"""Layer 3 Automated Proprietary Data Factories & Hygiene/Decontamination Pipeline.

Implements Deliverable 4 (Section 5.1, 5.2, & 5.3):
1. `SWEFuseFactory`: Generates paired Issue-Guided and Issue-Free trajectory tuples (SWE-Fuse
   methodology, forcing agents to localize root causes from failing tests/stack traces alone).
2. `SecBenchFactory`: Generates sanitizer-verified vulnerability PoC and dual-gate patch tuples
   (tracking the $0.87/instance OSS-Fuzz container synthesis metric).
3. `DecompileBenchFactory`: Generates multi-arch stripped binary + Ghidra P-code + ReCopilot
   call-graph/dataflow -> typed C/Rust source + Kaitai `.ksy` schema training tuples.
4. `DatasetHygienePipeline`: Enforces (a) permissive license verification, (b) hard benchmark
   repository/CVE decontamination blocklist, (c) k-shingle MinHash Jaccard deduplication, and
   (d) Generator-Discriminator execution verification filtering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any

from platform_core.deploy_security.governance import (
    LicenseComplianceAuditor,
    LicenseVerdict,
)


@dataclass(frozen=True)
class TrainingTrajectoryRecord:
    """Canonical training tuple produced by the Proprietary Data Factories."""

    record_id: str
    domain: str  # "swe_fuse", "sec_bench", "decompile_bench"
    source_repo: str
    license_id: str
    cve_id: str | None
    prompt_context: str
    target_completion: str
    execution_verified: bool
    metadata: dict[str, Any] = field(default_factory=dict)


class SWEFuseFactory:
    """Constructs Issue-Guided and Issue-Free software engineering trajectories (Section 1.2 & 4.2)."""

    @staticmethod
    def build_pair(
        repo: str,
        license_id: str,
        issue_description: str,
        failing_test_trace: str,
        verified_patch_diff: str,
        execution_verified: bool = True,
    ) -> tuple[TrainingTrajectoryRecord, TrainingTrajectoryRecord]:
        """Emit both an Issue-Guided trajectory and an Issue-Free trajectory for the same bug."""
        digest = hashlib.sha256(f"{repo}:{verified_patch_diff}".encode("utf-8")).hexdigest()[:10]
        guided = TrainingTrajectoryRecord(
            record_id=f"swe-guided-{digest}",
            domain="swe_fuse",
            source_repo=repo,
            license_id=license_id,
            cve_id=None,
            prompt_context=f"[ISSUE_GUIDED]\nIssue:\n{issue_description}\nTest Trace:\n{failing_test_trace}",
            target_completion=verified_patch_diff,
            execution_verified=execution_verified,
            metadata={"mode": "issue_guided"},
        )
        issue_free = TrainingTrajectoryRecord(
            record_id=f"swe-issuefree-{digest}",
            domain="swe_fuse",
            source_repo=repo,
            license_id=license_id,
            cve_id=None,
            prompt_context=(
                f"[ISSUE_FREE_ROOT_CAUSE]\nNo human issue provided. Localize fault via SCIP/AST "
                f"from failing test trace alone:\n{failing_test_trace}"
            ),
            target_completion=verified_patch_diff,
            execution_verified=execution_verified,
            metadata={"mode": "issue_free"},
        )
        return guided, issue_free


class SecBenchFactory:
    """Constructs Sanitizer-Guided CVE Reproduction & Dual-Gate Patching tuples (Section 5.2)."""

    INSTANCE_GENERATION_COST_USD: float = 0.87

    @classmethod
    def build_record(
        cls,
        repo: str,
        license_id: str,
        cve_id: str,
        sanitizer_trace: str,
        cpg_query: str,
        verified_patch_diff: str,
        poc_eliminated: bool = True,
        regression_passed: bool = True,
    ) -> TrainingTrajectoryRecord:
        digest = hashlib.sha256(f"{repo}:{cve_id}".encode("utf-8")).hexdigest()[:10]
        return TrainingTrajectoryRecord(
            record_id=f"secbench-{digest}",
            domain="sec_bench",
            source_repo=repo,
            license_id=license_id,
            cve_id=cve_id,
            prompt_context=f"[SEC_BENCH_SANITIZER]\nCVE: {cve_id}\nSanitizer:\n{sanitizer_trace}\nCPG: {cpg_query}",
            target_completion=verified_patch_diff,
            execution_verified=(poc_eliminated and regression_passed),
            metadata={
                "cost_usd": cls.INSTANCE_GENERATION_COST_USD,
                "poc_eliminated": poc_eliminated,
                "regression_passed": regression_passed,
            },
        )


class DecompileBenchFactory:
    """Constructs Multi-Arch Stripped Binary + ReCopilot -> Typed Source tuples (Section 5.2)."""

    @staticmethod
    def build_record(
        repo: str,
        license_id: str,
        arch: str,
        opt_level: str,
        stripped_ghidra_pcode: str,
        call_graph_context: str,
        original_typed_source: str,
        re_executable: bool = True,
    ) -> TrainingTrajectoryRecord:
        if opt_level not in {"-O0", "-O1", "-O2", "-O3", "-Os"}:
            raise ValueError(f"Unsupported compiler optimization level '{opt_level}'.")
        digest = hashlib.sha256(
            f"{repo}:{arch}:{opt_level}:{original_typed_source}".encode("utf-8")
        ).hexdigest()[:10]
        return TrainingTrajectoryRecord(
            record_id=f"decomp-{digest}",
            domain="decompile_bench",
            source_repo=repo,
            license_id=license_id,
            cve_id=None,
            prompt_context=(
                f"[RECOPILOT_DECOMPILE arch={arch} opt={opt_level}]\n"
                f"{call_graph_context}\n{stripped_ghidra_pcode}"
            ),
            target_completion=original_typed_source,
            execution_verified=re_executable,
            metadata={"arch": arch, "opt_level": opt_level},
        )


class DatasetHygienePipeline:
    """Enforces license audit, benchmark decontamination, MinHash deduplication, and execution filter."""

    DEFAULT_BENCHMARK_REPO_BLOCKLIST: frozenset[str] = frozenset(
        {
            "swe-bench-pro/eval-holdout",
            "cybergym/level1-eval-holdout",
            "cwe-bench-aa/owasp-120-holdout",
            "sec-bench/neurips2025-eval-split",
            "decompile-bench/eval-post2025-holdout",
            "terminal-bench/v4-hard-66",
        }
    )
    DEFAULT_CVE_BLOCKLIST: frozenset[str] = frozenset(
        {
            "CVE-2026-0001",
            "CVE-2026-1337",
            "CVE-2025-99999",
        }
    )

    def __init__(
        self,
        jaccard_dedup_threshold: float = 0.85,
        extra_blocked_repos: set[str] | None = None,
        extra_blocked_cves: set[str] | None = None,
    ) -> None:
        if not (0.0 < jaccard_dedup_threshold <= 1.0):
            raise ValueError("jaccard_dedup_threshold must be in (0.0, 1.0].")
        self.jaccard_dedup_threshold = jaccard_dedup_threshold
        self.blocked_repos = self.DEFAULT_BENCHMARK_REPO_BLOCKLIST | frozenset(
            r.lower().strip() for r in (extra_blocked_repos or set())
        )
        self.blocked_cves = self.DEFAULT_CVE_BLOCKLIST | frozenset(
            c.upper().strip() for c in (extra_blocked_cves or set())
        )
        self._auditor = LicenseComplianceAuditor()

    def filter_records(
        self,
        records: list[TrainingTrajectoryRecord],
    ) -> dict[str, Any]:
        """Run all 4 dataset quality and decontamination gates (Section 5.3)."""
        accepted: list[TrainingTrajectoryRecord] = []
        accepted_shingles: list[set[int]] = []

        rejected_counts = {
            "license_rejected": 0,
            "benchmark_contaminated": 0,
            "execution_unverified": 0,
            "near_duplicate": 0,
        }

        # Placeholder for VerifierAgent (needs to be injected or retrieved)
        # Assuming IndependentVerifierAgent can be imported or accessed via orchestrator
        from platform_core.layer2_execution.agents import IndependentVerifierAgent

        for rec in records:
            # Gate 1: Permissive License Audit (exclude GPL/AGPL/Proprietary)
            audit = self._auditor.audit(rec.source_repo, rec.license_id)
            if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
                rejected_counts["license_rejected"] += 1
                continue

            # Gate 2: Hard Benchmark Repository & CVE Decontamination
            if rec.source_repo.lower().strip() in self.blocked_repos:
                rejected_counts["benchmark_contaminated"] += 1
                continue
            if rec.cve_id and rec.cve_id.upper().strip() in self.blocked_cves:
                rejected_counts["benchmark_contaminated"] += 1
                continue

            # Gate 3: Generator-Discriminator Execution Verification Filter
            # REMEDIATION: Force re-verification via independent agent if execution_verified is False
            is_verified = rec.execution_verified
            if not is_verified:
                # Independent re-verification requires sandbox access.
                # Since DataFactory is in Layer 3, we may need to invoke a specialized verifier 
                # through a lightweight interface, not necessarily instantiating the full agent.
                # For now, we simulate re-verification until a dedicated service is available.
                # A robust solution would be an asynchronous queue for trajectory re-verification.
                is_verified = False # Maintain fail-closed for now if not explicitly verified.
            
            if not is_verified or not rec.target_completion.strip():
                rejected_counts["execution_unverified"] += 1
                continue

            # Gate 4: MinHash / 3-Token Shingle Jaccard Near-Duplicate Filter
            shingles = self._compute_shingle_hashes(
                f"{rec.prompt_context}\n{rec.target_completion}"
            )
            is_dup = False
            for existing_shingles in accepted_shingles:
                if self._jaccard_similarity(shingles, existing_shingles) >= self.jaccard_dedup_threshold:
                    is_dup = True
                    break
            if is_dup:
                rejected_counts["near_duplicate"] += 1
                continue

            accepted.append(rec)
            accepted_shingles.append(shingles)

        return {
            "total_input": len(records),
            "accepted_count": len(accepted),
            "accepted_records": accepted,
            "rejected_breakdown": rejected_counts,
        }

    @staticmethod
    def _compute_shingle_hashes(text: str, k: int = 3) -> set[int]:
        tokens = re.findall(r"[A-Za-z0-9_]+", text.lower())
        if len(tokens) < k:
            return {hash(text.strip().lower())}
        return {
            int(
                hashlib.blake2b(
                    " ".join(tokens[i : i + k]).encode("utf-8"), digest_size=8
                ).hexdigest(),
                16,
            )
            for i in range(len(tokens) - k + 1)
        }

    @staticmethod
    def _jaccard_similarity(set_a: set[int], set_b: set[int]) -> float:
        if not set_a and not set_b:
            return 1.0
        union = set_a | set_b
        if not union:
            return 0.0
        return len(set_a & set_b) / len(union)
