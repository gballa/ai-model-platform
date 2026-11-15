# Troubleshooting & Diagnostics Playbook

---

## 1. Purpose

Provide a rapid diagnostic reference for resolving exceptions, verification rejections, sandbox timeouts, and supply-chain blocks encountered when operating or extending `platform-core`.

---

## 2. Prerequisites

- Access to the repository root and `.venv/bin/python`.

---

## 3. Required Configuration

No special configuration is needed. Diagnostic commands run directly against `platform_core`.

---

## 4. Step-by-Step Instructions

1. Identify the exception class or workflow rejection status (`VERIFIER_REJECTED`, `FAILED_ESCALATED`, `PickleSupplyChainError`, `SafetensorsValidationError`, `PermissionError`, `MemoryError`, `ValueError`).
2. Match the error message in the diagnostic table in Section 7 below.
3. Run the verification snippet in Section 5 to inspect checkpoint history, verifier feedback, or license/Safetensors audit details.

---

## 5. Verified Commands and Examples

### Inspecting `verifier_feedback` and SQLite History on a Rejected SubTask

```python
from platform_core.layer2_execution import ExecutionLifecycleOrchestrator

orchestrator = ExecutionLifecycleOrchestrator()
try:
    state = orchestrator.run_workflow(
        session_id="diag-failed-patch",
        objective="Diagnose why a candidate patch was rejected",
        task_domain="swe",
        workspace_files={"math_util.py": "def square(x: int) -> int:\n    return x + x\n"},
        task_payload={
            "target_file": "math_util.py",
            "old_str": "    return x + x",
            "new_str": "    return x * 3",  # Deliberately wrong for x=4
            "test_script": "from math_util import square\nassert square(4) == 16, 'Expected 16'\n",
        },
    )
    print("Workflow Status:", state.status.value)  # FAILED_ESCALATED
    print("Subtask Retries:", state.subtasks[0].retry_count)  # 3
    print("Verifier Feedback Log:")
    for idx, msg in enumerate(state.subtasks[0].verifier_feedback, 1):
        print(f"  Attempt {idx}: {msg}")
finally:
    orchestrator.close()
```

---

## 6. Expected Results

The diagnostic snippet prints:
- `Workflow Status: FAILED_ESCALATED`
- `Subtask Retries: 3`
- Three structured verifier feedback entries showing `Unit/regression test failure (exit=1): ... AssertionError: Expected 16`.

---

## 7. Common Errors and Troubleshooting

| Exception / Status | Exact Trigger Condition | Root Cause & Remediation |
| :--- | :--- | :--- |
| `PickleSupplyChainError: Rejected unsafe checkpoint ... with forbidden extension '.pt'` | Passing `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.ckpt`, or `.joblib` to `SafetensorsValidator.validate_file()`. | Convert model weights to `.safetensors` or generate them via `CustomModelPipeline.build_custom_model()`. |
| `PickleSupplyChainError: Disguised Python pickle header detected inside ...` | First 2 bytes of a `.safetensors` file match `\x80\x02`–`\x80\x05`. | File is a Python pickle renamed to `.safetensors`. Replace with a genuine Safetensors binary file. |
| `SafetensorsValidationError: Tensor '...' data_offsets [start, end] span ... bytes, but shape ... requires ... bytes` | Corrupted `.safetensors` header or mismatched `shape * dtype` byte span; or unindexed gap/overlap between tensors. | Ensure tensor `data_offsets` are contiguous from `0` to `data_buffer_len` and match `math.prod(shape) * DTYPE_BYTE_SIZES[dtype]`. |
| `PermissionError: Cannot register model '...' with license '...'` | Using `Llama-4-Community`, `GPL-3.0`, `AGPL-3.0`, `Proprietary-Closed-API`, `Research-Only`, or an unknown license string. | Use an approved commercial OSI license in `LicenseComplianceAuditor.APPROVED_LICENSES` (`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `PostgreSQL`, `CC0-1.0`). |
| `PermissionError: Agent '...' is forbidden from marking SubTask '...' as COMPLETED` | Calling `agent.set_subtask_status(subtask, TaskStatus.COMPLETED)` on an executor agent (`can_mark_completed=False`). | Executor agents must transition subtasks to `TaskStatus.AWAITING_VERIFICATION`; only `IndependentVerifierAgent` may set `TaskStatus.COMPLETED`. |
| `PermissionError: Symlinked ... rejected` | Passing a symlinked path to `SafetensorsValidator.validate_file()`, `CustomModelPipeline.load_trajectories_from_file()`, `load_custom_model_manifest()`, `build_custom_model(output_dir=...)`, or `_load_custom_workflow_payload()`. | Pass a regular file or directory path; symlinks are rejected to prevent arbitrary file read/overwrite attacks. |
| `PermissionError: Path traversal attempt blocked in sandbox file path` | Passing an absolute path (`/etc/passwd`) or `..` segment to `FirecrackerSandboxManager`. | Use relative workspace paths only (e.g., `"src/app.py"`). |
| `MemoryError: Decompression bomb quota exceeded: > 10485760 bytes` | `DataAndVisualMCPServer.safe_decode_or_decompress()` encountered a `gzip`, `zlib`, or `base64` payload expanding beyond `10 MiB`. | Inspect the stream header with `classify_transformation()` without decompressing, or split large archives before ingestion. |
| `ValueError: Zero training trajectories passed DatasetHygienePipeline` | All records in `--dataset-file` failed license checks, matched the benchmark blocklist, had `execution_verified=False`, or were empty. | Check the returned `rejected_breakdown` dictionary (`license_rejected`, `benchmark_contaminated`, `execution_unverified`, `near_duplicate`) and fix the input `.jsonl` records. |
| `SecVerifier Dual-Gate rejected patch: mode=OVER_CORRECTION_REGRESSION_BREAKAGE` | Security patch eliminated the CWE/PoC (`Gate 1`) but `regression_tests_passed < regression_tests_total` (`Gate 2`). | Refine the patch so 100% of pass-to-pass functional regression tests pass. |
| `SecVerifier Dual-Gate rejected patch: mode=PARTIAL_FIX_SECONDARY_ENTRYPOINT` | Primary PoC no longer crashes, but `DefensiveCyberMCPServer.scan_cpg_taint()` still detects remaining CWE sinks in `patched_source`. | Remediate all CWE sinks reported in `remaining_cwes`. |

---

## 8. Related Documentation

- [Environment Setup & Debugging](environment-setup.md)
- [Security Architecture & Governance](../security/README.md)
- [10-Step Agent Execution Lifecycle](../workflows/agent-execution-lifecycle.md)
