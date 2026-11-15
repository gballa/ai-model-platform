# Production Monitoring, Observability & Diagnostics Runbook

---

## 1. Purpose

Provide operational procedures for inspecting OpenTelemetry/Langfuse execution spans, auditing and replaying SQLite workflow checkpoints, monitoring Copy-on-Write (CoW) snapshot restoration latency SLAs (`<= 15ms`), and running the 8-Step Controlled Improvement Cycle and Canary Promotion Gate.

---

## 2. Prerequisites

- Python `>= 3.11` with `.venv` initialized (`PYTHONPATH=src .venv/bin/python`).

---

## 3. Required Configuration

- For persistent cross-process checkpoint inspection, pass a file path (e.g., `SQLiteStateCheckpointer("artifacts/checkpoints.db")`) instead of `":memory:"`. File-backed SQLite databases automatically enable `PRAGMA journal_mode = WAL` and `PRAGMA busy_timeout = 30000`.

---

## 4. Step-by-Step Instructions

1. **Inspect Execution Spans (`PlatformState.telemetry_spans`)**: Every step transition in `ExecutionLifecycleOrchestrator` emits a span with `span_name`, `step`, `timestamp`, and `attributes`.
2. **Audit Checkpoint History & Perform Time-Travel Replay**: Use `checkpointer.list_history(session_id)` to list all saved checkpoints, `load_latest(session_id)` for crash recovery, and `load_at_step(session_id, LifecycleStep.STEP_X)` to inspect state at a historical step.
3. **Verify CoW Snapshot Restoration SLA (`<= 15ms`)**: Check `restore_info["restore_latency_ms"]` and `restore_info["within_15ms_sla"]` returned by `FirecrackerSandboxManager.restore_cow_snapshot()` or recorded in span `"lifecycle.step9_snapshot_rollback"`.
4. **Execute the 8-Step Controlled Improvement Cycle & Canary Gate**: Record production trace outcomes in `ControlledImprovementCycle` and evaluate candidate model promotions via `execute_cycle()`.

---

## 5. Verified Commands and Examples

```python
from platform_core.layer2_execution import (
    ExecutionLifecycleOrchestrator,
    LifecycleStep,
    SQLiteStateCheckpointer,
)

checkpointer = SQLiteStateCheckpointer(":memory:")
orchestrator = ExecutionLifecycleOrchestrator(checkpointer=checkpointer)
try:
    state = orchestrator.run_workflow(
        session_id="ops-audit-01",
        objective="Audit telemetry spans and checkpoint replay",
        task_domain="cyber",
        workspace_files={
            "service.py": "import subprocess\ndef ping(h: str) -> int:\n    return subprocess.call(f'ping -c 1 {h}', shell=True)\n"
        },
        task_payload={
            "target_file": "service.py",
            "old_str": "    return subprocess.call(f'ping -c 1 {h}', shell=True)",
            "new_str": "    return subprocess.call(['ping', '-c', '1', h], shell=False)",
            "poc_still_crashes": False,
            "regression_tests_passed": 10,
            "regression_tests_total": 10,
        },
    )

    # 1. Inspect SQLite checkpoint history
    history = checkpointer.list_history("ops-audit-01")
    print("Checkpoint count:", len(history))
    for entry in history:
        print(f"  ckpt #{entry['checkpoint_id']}: step={entry['lifecycle_step']} status={entry['status']}")

    # 2. Time-travel replay to Step 4 (Scoped MCP Binding)
    step4 = checkpointer.load_at_step("ops-audit-01", LifecycleStep.STEP_4_SCOPED_MCP_BINDING)
    assert step4 is not None
    print("Replayed Step 4 Subtask Tools:", step4.subtasks[0].scoped_tools)
finally:
    orchestrator.close()
```

---

## 6. Expected Results

- Prints `Checkpoint count: 7` (Steps 1, 2, 3, 4, 6, 7, 8, and 10; note Step 6 and Step 7 both save checkpoints).
- Replays Step 4 state and prints `Replayed Step 4 Subtask Tools: ['cyber.scan_cpg_taint', 'code_graph.apply_str_replace_edit']`.

---

## 7. Common Errors and Troubleshooting

| Symptom / Alert | Cause | Operational Remediation |
| :--- | :--- | :--- |
| `step3_root_cause_attributions` reports `KNOWLEDGE_GAP_RAG_SCIP` | Agent failed because symbol definitions or docs were missing from context. | Re-index the target files with `CodeGraphMCPServer.index_file()` and ingest missing docs into `HybridKnowledgeStore`. Do not retrain model weights. |
| `step3_root_cause_attributions` reports `TOOLING_PARSER_BUG` | An MCP tool raised an exception (`mcp_tool_exception=True`). | Fix the deterministic tool in `mcp_tools.py` and add a unit test in `tests/test_platform_core.py`. |
| `canary_decision["promoted"] == False` | Candidate model regressed on a benchmark (`delta < -combined_margin`) or failed to beat noise margin on target domains. | Inspect `canary_decision["regressions"]` and `canary_decision["comparisons"]`; adjust general replay ratio (`0.15..0.30`) or GRPO KL penalty (`kl_beta`). |

---

## 8. Related Documentation

- [8-Step Controlled Improvement Cycle](../workflows/controlled-improvement-cycle.md)
- [10-Step Agent Execution Lifecycle](../workflows/agent-execution-lifecycle.md)
- [Troubleshooting Playbook](../development/troubleshooting.md)
