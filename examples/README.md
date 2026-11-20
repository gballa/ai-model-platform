# `examples` — Runnable Scripts, Sample Trajectories & Workflow Payloads

---

## 1. Module Responsibilities and Boundaries

The `examples/` directory provides verified, self-contained sample files and executable scripts demonstrating how to create, persist, verify, load, and execute custom specialist models and 10-step domain workflows in `platform-core`.

---

## 2. Contents

| File | Format | Purpose |
| :--- | :--- | :--- |
| [`custom_model_end_to_end.py`](custom_model_end_to_end.py) | Python 3.11+ script | Runs the complete custom model lifecycle in a temporary directory: loads `sample_custom_trajectories.jsonl`, builds `Acme-SecCoder-27B-v1` (`cyber` domain), saves and validates `.safetensors` + `.manifest.json`, loads the manifest back from disk, and executes the CWE-78 remediation task in `sample_cyber_workflow.json`. |
| [`sample_custom_trajectories.jsonl`](sample_custom_trajectories.jsonl) | JSON Lines (`.jsonl`) | Three execution-verified training trajectories across `sec_bench` (`Apache-2.0`), `swe_fuse` (`MIT`), and `decompile_bench` (`BSD-3-Clause`) for testing `create-custom-model` and `CustomModelPipeline.load_trajectories_from_file()`. |
| [`sample_cyber_workflow.json`](sample_cyber_workflow.json) | JSON object (`.json`) | Sample `cyber` workflow payload defining `session_id`, `objective`, `workspace_files` (`service.py` with a `CWE-78` `shell=True` sink), and `task_payload` for `run-workflow` and `run-custom-model`. |

See also [`scripts/ingest_m1_corpus.py`](../scripts/ingest_m1_corpus.py) and [`scripts/synthesize_v4_trajectories.py`](../scripts/synthesize_v4_trajectories.py) for large-scale corpus RAG ingestion and Firecracker microVM trajectory verification scripts generating artifacts under `artifacts/` (gitignored).

---

## 3. Verified Execution Commands

Run from the repository root:

```bash
# 1. Run the self-contained end-to-end Python script
PYTHONPATH=src .venv/bin/python -W error examples/custom_model_end_to_end.py

# 2. Use the sample files directly with the CLI
PYTHONPATH=src .venv/bin/python -m platform_core.cli create-custom-model \
  --model-id Acme-SecCoder-27B-v1 \
  --domain cyber \
  --dataset-file examples/sample_custom_trajectories.jsonl \
  --output-dir ./artifacts/custom_models

PYTHONPATH=src .venv/bin/python -m platform_core.cli run-custom-model \
  --manifest ./artifacts/custom_models/Acme-SecCoder-27B-v1.manifest.json \
  --payload-file examples/sample_cyber_workflow.json
```

---

## 4. Related Documentation

- [Custom Model Creation & Execution Guide](../docs/CUSTOM_MODEL_GUIDE.md)
- [Step-by-Step Real-Life How-To Guides](../docs/HOW_TO_GUIDES.md)
- [API & Schema Contract Reference](../docs/api/README.md)
