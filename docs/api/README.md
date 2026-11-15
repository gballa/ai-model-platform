# API, CLI & Schema Contract Reference

---

## 1. Purpose

Document the public Python API exports, CLI subcommand contracts, JSON/JSONL file schemas (`.manifest.json`, workflow `payload.json`, training `trajectories.jsonl`), and signed MCP tool schemas for integrating with `platform-core`.

---

## 2. Prerequisites

- Python `>= 3.11` with `platform-core` installed in `.venv` (`PYTHONPATH=src .venv/bin/python`).

---

## 3. Required Configuration

Import public symbols from the four package namespaces:
- `platform_core.layer1_intelligence` ([`__init__.py`](../../src/platform_core/layer1_intelligence/__init__.py))
- `platform_core.layer2_execution` ([`__init__.py`](../../src/platform_core/layer2_execution/__init__.py))
- `platform_core.layer3_evolution` ([`__init__.py`](../../src/platform_core/layer3_evolution/__init__.py))
- `platform_core.deploy_security` ([`__init__.py`](../../src/platform_core/deploy_security/__init__.py))

---

## 4. Step-by-Step Instructions

### 4.1 JSON Schema Contract 1: Custom Model Manifest (`<model-id>.manifest.json`)
Produced by `CustomModelPipeline.build_custom_model(output_dir=...)` and consumed by `CustomModelPipeline.load_custom_model_manifest()` and `platform-cli run-custom-model --manifest <path>`:

| JSON Key | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `schema_version` | `string` | Yes | Schema version (`"1.0"`). |
| `model_spec` | `object` | Yes | Serialized `ModelSpec` dictionary (`model_id`, `pool`, `architecture`, `total_params_b`, `active_params_b`, `context_window`, `license_id`, `vram_4bit_gb`, `vram_fp8_gb`, `supports_early_fusion_vision`, `attention_mechanism`, `is_proprietary_fine_tune`, `base_checkpoint`, `benchmark_highlights`). |
| `domain` | `string` | Yes | One of `{"swe", "cyber", "binrev", "data_protocol", "architecture", "visual_ocr", "forensics", "vuln_intel"}`. |
| `safetensors_file` | `string` | Yes | Single-segment filename (`<model-id>.safetensors`) in the same directory as the manifest. Path separators (`/`, `\`) and `..` are rejected. |
| `checkpoint_sha256` | `string` | Yes | 64-character hex SHA-256 digest of the `.safetensors` file verified on load. |
| `checkpoint_bytes` | `integer` | Yes | Byte length of the `.safetensors` file. |
| `training_metrics` | `object` | Yes | Metrics from Stages 1–6 (`accepted_training_trajectories`, `sharding_backend`, `mopd_kl_loss`, `grpo_step_metrics`, `dpo_step_metrics`, `binrev_reward_breakdown`, `checkpoint_verified`). |
| `canary_promoted` | `boolean` | Yes | Whether the model passed the 5-run Canary Promotion Gate. |
| `canary_gains` | `array[string]` | Yes | Benchmarks with statistically significant gains. |
| `serving_launch_args` | `array[string]` | Yes | SGLang or vLLM CLI launch command tokens. |

### 4.2 JSON Schema Contract 2: Workflow Task Payload (`payload.json`)
Consumed by `platform-cli run-workflow --payload-file <path>` and `run-custom-model --payload-file <path>` (see [`examples/sample_cyber_workflow.json`](../../examples/sample_cyber_workflow.json)):

```json
{
  "session_id": "acme-prod-cyber-remediation",
  "domain": "cyber",
  "objective": "Remediate CWE-78 shell command injection in diagnostics service using custom model",
  "workspace_files": {
    "service.py": "import subprocess\ndef run_check(host: str) -> int:\n    return subprocess.call(f'ping -c 1 {host}', shell=True)\n"
  },
  "task_payload": {
    "target_file": "service.py",
    "old_str": "    return subprocess.call(f'ping -c 1 {host}', shell=True)",
    "new_str": "    return subprocess.call(['ping', '-c', '1', host], shell=False)",
    "poc_still_crashes": false,
    "regression_tests_passed": 18,
    "regression_tests_total": 18
  }
}
```

**Domain-Specific `task_payload` Keys**:
- **`swe` / `architecture`**: `target_file`, `old_str`, `new_str`, `test_script`.
- **`cyber`**: `target_file`, `old_str`, `new_str`, `poc_still_crashes` (`bool`), `regression_tests_passed` (`int`), `regression_tests_total` (`int`), optional `poc_script` / `regression_test_script` (`str`) executed in Firecracker sandbox.
- **`binrev`**: `binary_payload` (`bytes`) or `binary_payload_hex` (`str`), `raw_pseudocode` (`str`), `callers` (`list[str]`), `callees` (`list[str]`), `dataflow_aliases` (`dict[str, str]`).
- **`data_protocol` / `visual_ocr`**: `sample_payload` (`bytes`/`str`) or `sample_payload_hex` (`str`), `format_id` (`lower_snake_case` `str`), `magic_bytes` (`bytes`/`str`) or `magic_bytes_hex` (`str`), `fields` (`list[{"id": str, "type": str, "size_bytes": int}]`), `visual_regions` (`list[VisualRegionObservation | dict]`).
- **`vuln_intel`**: `project_dir` (`str`), optional `db_path` (`str`), optional `authorization_scope` (`AuthorizationScope` or dict), optional `cpg_findings` (`list`). Distinguishes `CONFIRMED_VULNERABILITY`, `POTENTIAL_WEAKNESS`, and `INFORMATIONAL`.
- **`forensics`**: `target_dir` (`str`), `platform` (`"auto" | "ios" | "android" | "host"`), optional `stix_file` (`str`), optional `use_mvt_cli` (`bool`). Produces `ForensicAssessment` (`CONFIRMED_IOC_MATCH` | `SUSPICIOUS_ANOMALY` | `NO_KNOWN_IOC_DETECTED`) with `visibility_limitations` and anti-fabrication guards.

### 4.4 Epistemic Ledger & CLI Endpoints
- **`EpistemicAssessment`** (`state.py`): Attached to `PlatformState.epistemic_assessment` at Step 10 (`FACT`, `HYPOTHESIS`, `UNCERTAIN` claims via `EpistemicStatus`, `EpistemicClaim`, `requires_human_verification`).
- **Additional Local & Security CLI Subcommands**:
  - `hardware-check`: Host hardware detection (`LocalHardwareDetector.detect()`) and local model lineup.
  - `download-model --model-id <repo> --license <spdx> --local-dir <dir>`: License-gated download (`ModelDownloadManager`).
  - `sync-vuln-db --db-path <sqlite> --feeds kev epss osv`: Sync public vulnerability feeds (`VulnIntelMCPServer.sync_live_feeds()`).
  - `audit-vulns --project-dir <dir> --db-path <sqlite>`: Polyglot dependency + Python AST taint correlation.
  - `scan-forensics --target-dir <dir> --platform {auto,ios,android,host} [--stix-file <json>] [--use-mvt-cli]`: Digital forensics & spyware IOC triage (`ForensicsMCPServer`).
  - `analyze-image --path <file> [--prompt <text>] [--endpoint <url>]`: Image/PDF inspection (`DataAndVisualMCPServer`).
  - `run-benchmarks [--suites coding reasoning cyber_vuln forensics hallucination_resistance]`: Execute live `BenchmarkSuiteRunner` suites.

### 4.3 JSONL/JSON Schema Contract 3: Training Trajectories (`trajectories.jsonl`)
Consumed by `CustomModelPipeline.load_trajectories_from_file()` (see [`examples/sample_custom_trajectories.jsonl`](../../examples/sample_custom_trajectories.jsonl)):
- Required fields per object: `prompt_context` (non-empty `str`), `target_completion` (non-empty `str`).
- Optional fields with defaults: `record_id` (`"custom-rec-<idx>"`), `domain` (`"swe_fuse"`), `source_repo` (`"org/custom-repo"`), `license_id` (`"Apache-2.0"`), `cve_id` (`None`), `execution_verified` (`True`, must be `bool`), `metadata` (`{}`).

---

## 5. Verified Commands and Examples

```python
from platform_core.cli import run_demo_workflow, run_evaluate_blueprint

# 1. Programmatic blueprint evaluation
blueprint = run_evaluate_blueprint(budget_usd=1_800_000)
assert blueprint["recommended_scenario"] == "Scenario-B"

# 2. Programmatic workflow execution with payload file
res = run_demo_workflow(
    domain="cyber",
    payload_file="examples/sample_cyber_workflow.json",
)
assert res["status"] == "COMPLETED"
assert res["verified_by"] == "independent_verifier"
print("Completed session:", res["session_id"], "| Spans:", res["telemetry_span_count"])
```

---

## 6. Expected Results

Prints:
```text
Completed session: acme-prod-cyber-remediation | Spans: 7
```

---

## 7. Common Errors and Troubleshooting

| Error | Cause | Resolution |
| :--- | :--- | :--- |
| `ValueError: Dataset record at index ... is missing a non-empty string 'prompt_context'` | Null or empty `prompt_context` or `target_completion` in `.jsonl`. | Populate both fields with non-empty strings. |
| `ValueError: Kaitai Struct meta.id must be lower_snake_case.` | Passing uppercase or hyphenated `format_id` in `data_protocol` or `visual_ocr` payloads. | Use `lower_snake_case` (matching `^[a-z][a-z0-9_]*$`). |

---

## 8. Related Documentation

- [CLI Module Reference](../modules/cli.md)
- [Integrations & Boundaries](../architecture/integrations.md)
- [Custom Model Creation & Execution Guide](../CUSTOM_MODEL_GUIDE.md)
