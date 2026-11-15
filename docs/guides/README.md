# Practical Engineering Playbooks & How-To Catalog

This directory indexes all task-oriented engineering playbooks across `platform-core` and provides dedicated operational guides for **Database & State Operations** and **AI Agent, Prompt & Pipeline Development**.

---

## Complete Catalog of Practical How-To Guides

Every required engineering activity is covered by a verified, step-by-step guide following the 8-part standard defined in [docs/DOCUMENTATION_STANDARDS.md](../DOCUMENTATION_STANDARDS.md#5-technical-writing-standards):

| Engineering Activity | Authoritative Guide |
| :--- | :--- |
| **1. Initial Development Environment Setup** | [docs/development/environment-setup.md](../development/environment-setup.md) & [docs/development/getting-started.md](../development/getting-started.md) |
| **2. Local Execution & Debugging** | [docs/development/environment-setup.md](../development/environment-setup.md) & [docs/HOW_TO_GUIDES.md](../HOW_TO_GUIDES.md) |
| **3. Configuration & Environment Variables** | [docs/development/configuration.md](../development/configuration.md) |
| **4. API Usage & Integration** | [docs/api/README.md](../api/README.md) & [docs/architecture/integrations.md](../architecture/integrations.md) |
| **5. Adding New Modules & Features** | [docs/development/development-workflow.md](../development/development-workflow.md) |
| **6. Database Operations, Checkpointing & Schema Management** | [Playbook A: SQLite State & Code-Graph Database Operations](#playbook-a-sqlite-state--code-graph-database-operations) (below) |
| **7. AI Model, Agent, Prompt & Pipeline Development** | [Playbook B: AI Agent, ReCopilot Prompt & Pipeline Development](#playbook-b-ai-agent-recopilot-prompt--pipeline-development) (below) & [docs/CUSTOM_MODEL_GUIDE.md](../CUSTOM_MODEL_GUIDE.md) |
| **8. Testing & Quality Assurance** | [docs/testing/README.md](../testing/README.md) |
| **9. Troubleshooting** | [docs/development/troubleshooting.md](../development/troubleshooting.md) |
| **10. Build & Deployment** | [docs/deployment/README.md](../deployment/README.md) |
| **11. Production Monitoring & Diagnostics** | [docs/operations/README.md](../operations/README.md) |
| **12. Domain-Specific Real-Life Recipes (SWE, Cyber, BinRev, Protocol, Memory)** | [docs/HOW_TO_GUIDES.md](../HOW_TO_GUIDES.md) |

---

## Playbook A: SQLite State & Code-Graph Database Operations

### 1. Purpose
Operate, persist, inspect, and migrate the two embedded SQLite stores in `platform-core`: `SQLiteStateCheckpointer` (`state_checkpoints`) and `CodeGraphMCPServer` (`indexed_files` and `code_symbols`).

### 2. Prerequisites
- Python `>= 3.11` with `sqlite3` support (`PYTHONPATH=src .venv/bin/python`).

### 3. Required Configuration
- By default, both stores use `db_path=":memory:"`.
- To persist across process restarts or share across worker threads, pass a filesystem path (e.g., `db_path="./artifacts/platform_state.db"`). Both classes automatically configure `check_same_thread=False`, `threading.RLock()`, `PRAGMA busy_timeout = 30000`, and `PRAGMA journal_mode = WAL`.

### 4. Step-by-Step Instructions
1. Instantiate `SQLiteStateCheckpointer(db_path)` and `CodeGraphMCPServer(db_path)` with a file path inside a temporary or artifacts directory.
2. Execute indexing or workflow checkpointing across one or more threads.
3. Query checkpoint history (`list_history`), latest state (`load_latest`), or point-in-time step snapshots (`load_at_step`).
4. Close both stores via `.close()` when shutting down to flush WAL frames cleanly.

### 5. Verified Commands and Examples

```python
from pathlib import Path
import tempfile
from platform_core.layer2_execution import (
    CodeGraphMCPServer,
    LifecycleStep,
    PlatformState,
    SQLiteStateCheckpointer,
    TaskStatus,
)

with tempfile.TemporaryDirectory() as tmp:
    state_db = Path(tmp) / "state.db"
    graph_db = Path(tmp) / "graph.db"

    checkpointer = SQLiteStateCheckpointer(state_db)
    code_graph = CodeGraphMCPServer(str(graph_db))
    try:
        # 1. Save and reload a durable state checkpoint
        st = PlatformState(
            session_id="db-ops-01",
            objective="Verify persistent WAL SQLite checkpointing",
            task_domain="swe",
            current_step=LifecycleStep.STEP_2_PRE_INDEX_AND_DECOMPOSE,
            status=TaskStatus.IN_PROGRESS,
        )
        ckpt_id = checkpointer.save_checkpoint(st)
        restored = checkpointer.load_latest("db-ops-01")
        assert restored is not None and restored.session_id == "db-ops-01"

        # 2. Index a file and verify incremental BLAKE2b cache hit on second call
        first_idx = code_graph.index_file("pkg/auth.py", "def verify_token(tok: str) -> bool:\n    return True\n")
        second_idx = code_graph.index_file("pkg/auth.py", "def verify_token(tok: str) -> bool:\n    return True\n")
        print("Checkpoint ID:", ckpt_id, "| First cache_hit:", first_idx["cache_hit"], "| Second cache_hit:", second_idx["cache_hit"])
    finally:
        checkpointer.close()
        code_graph.close()
```

### 6. Expected Results
Prints:
```text
Checkpoint ID: 1 | First cache_hit: False | Second cache_hit: True
```

### 7. Common Errors and Troubleshooting
- **`sqlite3.ProgrammingError: Cannot operate on a closed database`**: Calling methods after `close()` has been invoked. Keep the instance open until all worker threads complete.
- **`ResourceWarning: unclosed database`**: Always call `.close()` in a `finally` block.

### 8. Related Documentation
- [Data Flow & SQLite ER Schemas](../architecture/data-flow.md#3-sqlite-persistence-schemas-er-diagram)
- [Layer 2 Execution Module Reference](../modules/layer2-execution.md)

---

## Playbook B: AI Agent, ReCopilot Prompt & Pipeline Development

### 1. Purpose
Develop, customize, and evaluate specialist agent workflows, structured `ReCopilot` / `SWE-Fuse` / `Sec-Bench` prompt templates, and `BestOfNVerifierPruner` (`TTS@N`) candidate selection pipelines.

### 2. Prerequisites
- Python `>= 3.11` with `.venv` configured (`PYTHONPATH=src .venv/bin/python`).

### 3. Required Configuration
- `AdaptiveModelRouter` thinking budget constants (`NON_THINK_BUDGET=0`, `THINK_HIGH=512..1024`, `THINK_MAX_BUDGET=2048`).
- `BestOfNVerifierPruner` candidate rollout scoring (`CandidateRollout`).

### 4. Step-by-Step Instructions
1. Use `SWEFuseFactory`, `SecBenchFactory`, or `DecompileBenchFactory` to construct structured prompt contexts (`[ISSUE_GUIDED]`, `[ISSUE_FREE_ROOT_CAUSE]`, `[SEC_BENCH_SANITIZER]`, `[RECOPILOT_DECOMPILE]`).
2. Route the task through `AdaptiveModelRouter.route()` with `require_best_of_n=True` to obtain a `TTS@4` or `TTS@8` rollout allocation.
3. Evaluate parallel candidate rollouts with `BestOfNVerifierPruner.select_best_candidate()` so only candidates passing the dual gate (`compiled_cleanly and passed_primary_tests and passed_regression_tests`) with minimal steps and thinking tokens win.

### 5. Verified Commands and Examples

```python
from platform_core.layer1_intelligence import (
    AdaptiveModelRouter,
    BestOfNVerifierPruner,
    CandidateRollout,
    RoutingRequest,
)
from platform_core.layer3_evolution import SWEFuseFactory

# 1. Build paired Issue-Guided and Issue-Free prompts
guided, issue_free = SWEFuseFactory.build_pair(
    repo="acme/router",
    license_id="Apache-2.0",
    issue_description="Fix empty token list handling",
    failing_test_trace="IndexError: list index out of range",
    verified_patch_diff="@@ -1,1 +1,1 @@\n-return items[0]\n+return items[0] if items else None",
)

# 2. Route with Best-of-N (TTS@4) enabled
router = AdaptiveModelRouter()
decision = router.route(
    RoutingRequest(
        task_id="agent-dev-01",
        task_domain="swe",
        prompt_tokens=len(issue_free.prompt_context) // 4,
        uncertainty_entropy=0.55,
        require_best_of_n=True,
    )
)

# 3. Prune parallel candidate rollouts using deterministic verifier outcomes
winner = BestOfNVerifierPruner.select_best_candidate(
    [
        CandidateRollout("cand-overcorrect", "patch_a", 900, 6, True, True, False, 0.95),
        CandidateRollout("cand-verbose-valid", "patch_b", 850, 5, True, True, True, 1.0),
        CandidateRollout("cand-concise-valid", "patch_c", 520, 3, True, True, True, 1.0),
    ]
)
print("Routed:", decision.primary_model.model_id, "| Rollouts:", decision.best_of_n_rollouts)
print("Selected Winner:", winner.candidate_id, "| Thinking Tokens:", winner.thinking_tokens_used)
```

### 6. Expected Results
Prints:
```text
Routed: Qwen3.8-27B-SWE-Cyber | Rollouts: 4
Selected Winner: cand-concise-valid | Thinking Tokens: 520
```

### 7. Common Errors and Troubleshooting
- **`ValueError: Cannot select from an empty candidate rollout list`**: Ensure at least 1 `CandidateRollout` is passed to `BestOfNVerifierPruner.select_best_candidate()`.
- **`ValueError: uncertainty_entropy must be in [0.0, 1.0]`**: Normalize token entropy to `[0.0, 1.0]` before constructing `RoutingRequest`.

### 8. Related Documentation
- [Custom Model Creation & Execution Guide](../CUSTOM_MODEL_GUIDE.md)
- [Step-by-Step Real-Life How-To Guides](../HOW_TO_GUIDES.md)
- [Layer 1 Intelligence Module Reference](../modules/layer1-intelligence.md)
