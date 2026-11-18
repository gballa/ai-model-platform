"""Layer 3 Observability (OpenTelemetry / Langfuse) and 8-Step Controlled Improvement Cycle.

Implements Section 10.4:
1. Telemetry & Outcome Aggregation (`VERIFIED_PASS`, `RETRY_RECOVERED`, `VERIFIER_REJECTED`, `HUMAN_EDITED`)
2. Automated Failure Clustering
3. Root-Cause Attribution (`KNOWLEDGE_GAP_RAG_SCIP`, `TOOLING_PARSER_BUG`, `MODEL_WEIGHT_REASONING_GAP`)
4. Automated Sandbox Reproduction
5. Validated Trajectory Synthesis & Curation (never training on unverified LLM prose)
6. Offline Post-Training (SFT + GRPO/RLVR)
7. Full Regression & Contamination Audit
8. Canary Promotion Gate
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any

from .evaluation import BenchmarkEvaluator


class TraceOutcome(str, Enum):
    """Production trace outcome categories in Langfuse (Section 10.4 Step 1)."""

    VERIFIED_PASS = "VERIFIED_PASS"
    RETRY_RECOVERED = "RETRY_RECOVERED"
    VERIFIER_REJECTED = "VERIFIER_REJECTED"
    HUMAN_EDITED = "HUMAN_EDITED"


class FailureRootCauseBucket(str, Enum):
    """Root-Cause Attribution buckets (Section 10.4 Step 3)."""

    KNOWLEDGE_GAP_RAG_SCIP = "KNOWLEDGE_GAP_RAG_SCIP"
    TOOLING_PARSER_BUG = "TOOLING_PARSER_BUG"
    MODEL_WEIGHT_REASONING_GAP = "MODEL_WEIGHT_REASONING_GAP"


@dataclass(frozen=True)
class ProductionTraceRecord:
    """Telemetry record captured from a production or benchmark agent run."""

    trace_id: str
    domain: str
    outcome: TraceOutcome
    failure_signature: str | None = None
    missing_doc_or_symbol: bool = False
    mcp_tool_exception: bool = False
    candidate_trajectory: str = ""
    passed_compiler_and_tests: bool = False
    timestamp: float = field(default_factory=time.time)


class ControlledImprovementCycle:
    """Executes the 8-Step Controlled Improvement Cycle without online weight drift (Section 10.4)."""

    def __init__(self) -> None:
        self._traces: list[ProductionTraceRecord] = []
        self._monitoring_service = MonitoringService()

    def record_trace(self, trace: ProductionTraceRecord) -> None:
        """Step 1: Telemetry & Outcome Aggregation."""
        self._traces.append(trace)
        self._monitoring_service.check_thresholds(self._traces)

    def execute_cycle(
        self,
        baseline_benchmark_runs: dict[str, list[float]],
        candidate_benchmark_runs: dict[str, list[float]],
        target_domains: set[str],
    ) -> dict[str, Any]:
        """Run all 8 steps of the continuous improvement loop and return the audit report."""
        # Step 1: Outcome Aggregation
        outcome_counts = Counter(t.outcome.value for t in self._traces)

        # Step 2: Automated Failure Clustering
        failure_clusters: dict[str, list[ProductionTraceRecord]] = defaultdict(list)
        for t in self._traces:
            if t.outcome in {TraceOutcome.VERIFIER_REJECTED, TraceOutcome.HUMAN_EDITED}:
                sig = t.failure_signature or f"unclassified_{t.domain}"
                failure_clusters[sig].append(t)

        # Step 3: Root-Cause Attribution (Knowledge vs Tooling vs Weights)
        attributions: dict[str, FailureRootCauseBucket] = {}
        remediation_actions: dict[str, str] = {}
        for cluster_sig, items in failure_clusters.items():
            if any(i.mcp_tool_exception for i in items):
                attributions[cluster_sig] = FailureRootCauseBucket.TOOLING_PARSER_BUG
                remediation_actions[cluster_sig] = "Patch deterministic MCP parser/tool implementation."
            elif any(i.missing_doc_or_symbol for i in items):
                attributions[cluster_sig] = FailureRootCauseBucket.KNOWLEDGE_GAP_RAG_SCIP
                remediation_actions[cluster_sig] = "Re-index repository SCIP graph and update pgvectorscale RAG."
            else:
                attributions[cluster_sig] = FailureRootCauseBucket.MODEL_WEIGHT_REASONING_GAP
                remediation_actions[cluster_sig] = "Escalate cluster to offline SFT + GRPO/RLVR post-training."

        # Step 4: Automated Sandbox Reproduction Tasks
        sandbox_repro_tasks = [
            f"repro-sandbox-{sig}"
            for sig, bucket in attributions.items()
            if bucket == FailureRootCauseBucket.MODEL_WEIGHT_REASONING_GAP
        ]

        # Step 5: Validated Trajectory Synthesis & Curation (strictly filter out unverified prose!)
        curated_trajectories = [
            t.trace_id
            for t in self._traces
            if t.passed_compiler_and_tests
            and t.outcome in {TraceOutcome.VERIFIED_PASS, TraceOutcome.RETRY_RECOVERED, TraceOutcome.HUMAN_EDITED}
            and t.candidate_trajectory.strip()
        ]
        rejected_unverified_prose = sum(
            1 for t in self._traces if not t.passed_compiler_and_tests
        )

        # Step 6: Offline Post-Training Trigger
        offline_training_triggered = len(curated_trajectories) > 0

        # Step 7 & Step 8: Full Regression Audit & Canary Promotion Gate
        canary_decision = BenchmarkEvaluator.evaluate_canary_promotion(
            baseline_runs=baseline_benchmark_runs,
            candidate_runs=candidate_benchmark_runs,
            target_domains=target_domains,
        )

        return {
            "step1_outcome_counts": dict(outcome_counts),
            "step2_failure_cluster_count": len(failure_clusters),
            "step3_root_cause_attributions": {k: v.value for k, v in attributions.items()},
            "step3_remediation_actions": remediation_actions,
            "step4_sandbox_repro_tasks": sandbox_repro_tasks,
            "step5_curated_verified_trajectory_ids": curated_trajectories,
            "step5_rejected_unverified_count": rejected_unverified_prose,
            "step6_offline_training_triggered": offline_training_triggered,
            "step7_and_8_canary_gate": canary_decision,
            "monitoring_metrics": self._monitoring_service.get_report(),
        }


class MonitoringService:
    """Auto-scaling observability monitor for ControlledImprovementCycle."""

    def __init__(self, threshold: int = 100) -> None:
        self._threshold = threshold
        self._scaling_events = 0

    def check_thresholds(self, traces: list[ProductionTraceRecord]) -> None:
        if len(traces) >= self._threshold:
            self._scaling_events += 1
            # In a real scenario, this would trigger re-allocation.
            print(f"Observability Alert: Trace count {len(traces)} exceeded threshold {self._threshold}. Scaling event triggered.")

    def get_report(self) -> dict[str, Any]:
        return {
            "threshold": self._threshold,
            "scaling_events": self._scaling_events,
        }
