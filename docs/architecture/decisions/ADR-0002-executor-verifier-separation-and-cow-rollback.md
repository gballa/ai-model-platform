# ADR-0002: 6-Agent Consolidation, `SecVerifier` Executor/Verifier Separation & `<15ms` CoW Snapshot Rollback

- **Identifier:** ADR-0002
- **Status:** Accepted
- **Date:** 2026-11-15
- **Source Modules:** [`agents.py`](../../../src/platform_core/layer2_execution/agents.py), [`sandbox.py`](../../../src/platform_core/layer2_execution/sandbox.py), [`orchestrator.py`](../../../src/platform_core/layer2_execution/orchestrator.py), [`mcp_tools.py`](../../../src/platform_core/layer2_execution/mcp_tools.py)

---

## 1. Context

Multi-agent software and security systems commonly suffer from three operational defects:
1. Excessive role fragmentation (e.g., 12+ conversational agents passing unstructured text back and forth, inflating token usage and latency).
2. Self-certifying executors that declare broken patches or incomplete security fixes `COMPLETED` without independent verification.
3. Dirty workspace state left behind when an attempted edit fails unit tests or breaks regression suites.

---

## 2. Decision

1. **Consolidate 12 Roles into 6 Stateful Agent Nodes**: Implement six specialist classes in `layer2_execution/agents.py` (`PrincipalOrchestratorAgent`, `SoftwareEngineeringAgent`, `ReverseEngineeringAgent`, `DefensiveCyberAgent`, `MultimodalDataAgent`, `IndependentVerifierAgent`) operating over a single typed `PlatformState` checkpointed in SQLite.
2. **Hard Structural Separation (`can_mark_completed`)**: Enforce in `BaseSpecialistAgent.set_subtask_status()` that all five executor/orchestrator agents have `can_mark_completed = False` and can only transition subtasks to `TaskStatus.AWAITING_VERIFICATION`. Only `IndependentVerifierAgent` (`can_mark_completed = True`) can set `TaskStatus.COMPLETED` at Step 8 (`STEP_8_INDEPENDENT_VERIFICATION`).
3. **`SecVerifier` Dual-Gate Security Verification**: Require `DefensiveCyberMCPServer.verify_dual_gate_patch()` and `SWECyberRewardOracle` to verify both:
   - **Gate 1 (Security)**: PoC crash eliminated AND zero remaining CPG taint findings (`remaining_cwe_count == 0`).
   - **Gate 2 (Regression)**: 100% of pass-to-pass functional regression tests pass (`regression_tests_passed == regression_tests_total`), penalizing over-correction with `-0.5` reward during RLVR and `REJECTED` (`OVER_CORRECTION_REGRESSION_BREAKAGE`) during execution.
4. **Pre-Execution CoW Snapshot & `<15ms` Rollback**: Before every specialist execution attempt at Step 6, `ExecutionLifecycleOrchestrator` captures a Copy-on-Write workspace snapshot via `FirecrackerSandboxManager.create_cow_snapshot()`. If Step 8 verification fails, Step 9 immediately restores the clean snapshot via `restore_cow_snapshot()` (`within_15ms_sla: True`), appends structured verifier feedback, and escalates to `TTS@4` rollouts on the final retry attempt (`retry_count == max_retries - 1`).

---

## 3. Consequences

- **Positive**: Eliminates self-certified hallucinations, guarantees clean workspace state before each retry attempt, and provides deterministic verifier feedback to guide retry recovery.
- **Trade-offs**: Every workflow requires an explicit verification pass at Step 8 before reaching Step 10 delivery.

---

## 4. Alternatives Considered

1. **12 Separate Conversational Agents**: Rejected because unstructured inter-agent chat multiplies context tokens and causes semantic drift over long trajectories.
2. **Allowing Executor Agents to Mark Tasks Completed After Self-Testing**: Rejected because executor agents frequently modify or weaken tests to pass their own edits.
3. **In-Place File Reversal via Reverse Diffs**: Rejected in favor of full CoW workspace snapshots (`CoWSnapshot`) because failed scripts may create or delete auxiliary files that reverse text diffs cannot reliably clean up.
