# ADR-0009: Asynchronous Model-Rollout Strategies for Evolution Layer

- **Identifier:** ADR-0009
- **Status:** Proposed
- **Date:** 2026-11-18
- **Source Modules:** [`observability.py`](../../../../src/platform_core/layer3_evolution/observability.py), [`evaluation.py`](../../../../src/platform_core/layer3_evolution/evaluation.py)

---

## 1. Context

The evolution layer (`Layer 3`) handles continuous model improvement and benchmark evaluation. Rolling out new model versions currently risks performance regressions or unexpected behavior if deployed immediately. A structured, asynchronous rollout strategy is required to ensure stability in production.

## 2. Decision

1. **Blue-Green Deployment Infrastructure**: Implement a blue-green rollout mechanism in `layer3_evolution` to allow concurrent hosting of the current ("green") and proposed ("blue") model versions.
2. **Canary-Based Automated Evaluation**: Use `BenchmarkSuiteRunner` (PropBench-9) to perform canary testing on the "blue" model, subjecting it to a subset of tasks before full traffic promotion.
3. **Observability-Driven Rollback**: Integrate `ObservabilityService` to monitor key performance indicators (TTFT, error rates, reward oracle outputs) and automate rollback to the "green" model if performance thresholds are breached during the canary rollout.

## 3. Consequences

- **Positive**: Enables safer model updates; facilitates quantitative performance comparisons via canary testing before full deployment.
- **Trade-offs**: Increased infrastructure complexity; requires dual-hosting of models during the rollout phase, consuming additional VRAM.

## 4. Alternatives Considered

1. **Immediate Rolling Deployment**: Rejected due to the high risk of catastrophic failure in production environments.
2. **Manual Rollout Verification**: Rejected due to the operational overhead and slow feedback cycle, inconsistent with the goals of `ControlledImprovementCycle`.
