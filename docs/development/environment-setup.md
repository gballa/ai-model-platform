# Development Environment Setup & Debugging Guide

---

## 1. Purpose

Configure a reproducible local development and debugging environment for `platform-core` on macOS or Linux, verify Python standard-library modules, and understand how local execution maps to optional production cluster components.

---

## 2. Prerequisites

- **Python**: `>= 3.11` with standard library modules `sqlite3`, `zlib`, `gzip`, `hashlib`, `hmac`, `ast`, `struct`, `subprocess`, `tempfile`, and `unittest`.
- **Build Tooling**: `setuptools>=68.0` (pre-installed in `.venv`).

---

## 3. Required Configuration

- **Virtual Environment Path**: `.venv/` (in the repository root)
- **Editable Package Metadata**: [`pyproject.toml`](../../pyproject.toml) registers package discovery under `where = ["src"]` and the console script `platform-cli = "platform_core.cli:main"`.

---

## 4. Step-by-Step Instructions

1. **Verify Python & SQLite Versions**: Confirm Python 3.11+ and SQLite 3.35+ (supporting WAL mode) are available.
2. **Initialize `.venv` and Editable Install**: Create `.venv` and install the package in editable mode (`pip install -e .`).
3. **Run Local Debugging & Inspection**: Use `python -m pdb` or inspect SQLite checkpoint history and OpenTelemetry spans directly on the returned `PlatformState` object.

---

## 5. Verified Commands and Examples

### Environment Verification Commands

```bash
# 1. Check Python and SQLite versions in .venv
.venv/bin/python -c "import sys, sqlite3; print('Python:', sys.version.split()[0], '| SQLite:', sqlite3.sqlite_version)"

# 2. Verify CLI entrypoint is importable and functional
PYTHONPATH=src .venv/bin/python -m platform_core.cli --help
```

### Local Interactive Debugging Example (Inspecting Step-by-Step Checkpoints & Spans)

```python
from platform_core.layer2_execution import ExecutionLifecycleOrchestrator, LifecycleStep

orchestrator = ExecutionLifecycleOrchestrator()
try:
    state = orchestrator.run_workflow(
        session_id="debug-session-01",
        objective="Debug step-by-step state transitions",
        task_domain="swe",
        workspace_files={"app.py": "def add(a: int, b: int) -> int:\n    return a - b\n"},
        task_payload={
            "target_file": "app.py",
            "old_str": "    return a - b",
            "new_str": "    return a + b",
            "test_script": "from app import add\nassert add(2, 3) == 5\n",
        },
    )
    # 1. Inspect recorded telemetry spans across Steps 1-10
    for span in state.telemetry_spans:
        print(f"Step {span['step']}: {span['span_name']} -> {span['attributes']}")

    # 2. Time-travel replay: inspect the state snapshot saved right after Step 3 (Routing)
    step3_state = orchestrator.checkpointer.load_at_step(
        "debug-session-01", LifecycleStep.STEP_3_SPECIALIST_AND_THINKING_ROUTE
    )
    assert step3_state is not None
    print("Step 3 Routing Snapshot:", step3_state.routing_summary)
finally:
    orchestrator.close()
```

---

## 6. Expected Results

- The environment check prints Python `3.11+` and SQLite `3.x`.
- `platform_core.cli --help` lists all 6 subcommands (`evaluate-blueprint`, `train-model`, `create-custom-model`, `run-workflow`, `run-custom-model`, `inspect-data`).
- The debugging script prints 7 telemetry spans (`step1_ingest_and_taint`, `step2_pre_index_and_decompose`, `step3_routing`, `step4_scoped_mcp_binding`, `step7_observation`, `step8_independent_verification`, `step10_artifact_delivery`) and restores the exact Step 3 `PlatformState` snapshot.

---

## 7. Common Errors and Troubleshooting

| Symptom / Error | Cause | Resolution |
| :--- | :--- | :--- |
| `ResourceWarning: unclosed database in <sqlite3.Connection ...>` under `-W error` | Creating `ExecutionLifecycleOrchestrator`, `SQLiteStateCheckpointer`, or `CodeGraphMCPServer` without calling `.close()`. | Always wrap `orchestrator`, `checkpointer`, or `code_graph` in a `try...finally: obj.close()` block. |
| `PermissionError: Invalid session_id ...` | Passing spaces or slashes in `session_id`. | Ensure `session_id` matches `^[A-Za-z0-9._-]+$`. |

---

## 8. Related Documentation

- [Getting Started Guide](getting-started.md)
- [Configuration Reference](configuration.md)
- [Troubleshooting Playbook](troubleshooting.md)
- [Operations & Time-Travel Replay Guide](../operations/README.md)
