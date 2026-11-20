# Getting Started with `platform-core`

---

## 1. Purpose

Provide a rapid, verified onboarding path from a fresh checkout of `platform-core` to running architecture evaluations, 5-stage custom model training, 10-step verified agent workflows, binary/stream inspections, and the full unit/security test suite.

---

## 2. Prerequisites

- **Operating System**: macOS or Linux.
- **Python**: Python `3.11` or newer (`requires-python = ">=3.11"` in [`pyproject.toml`](../../pyproject.toml)).
- **Third-Party Packages**: **None** (`dependencies = []`). All local workflows, parsers, SQLite stores, and cryptographic verifiers run using Python's standard library.

---

## 3. Required Configuration

No external environment variables, API keys, or background database daemons are required for local execution. Ensure your working directory is the repository root.

---

## 4. Step-by-Step Instructions

1. Create and activate (or invoke directly) the local `.venv` Python virtual environment and install `platform-core` in editable mode.
2. Run the unit, integration, and security test suite with `-W error`.
3. Run `evaluate-blueprint` to inspect the 4-Pool model lineup and hardware economics.
4. Run `run-workflow` on the software engineering (`swe`) and cybersecurity (`cyber`) domains.
5. Run the end-to-end custom model script (`examples/custom_model_end_to_end.py`).

---

## 5. Verified Commands and Examples

```bash
# Step 1: Create virtual environment and install package in editable mode
python3 -m venv .venv
.venv/bin/pip install -e .

# Step 2: Run all 211 unit, integration, security, and E2E tests under strict warning gate
PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v

# Step 3: Evaluate the architecture blueprint and hardware break-even
PYTHONPATH=src .venv/bin/python -m platform_core.cli evaluate-blueprint --budget 1800000

# Step 4: Execute a 10-step verified cybersecurity remediation workflow
PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain cyber

# Step 5: Create, verify, load, and run a custom model end-to-end
PYTHONPATH=src .venv/bin/python -W error examples/custom_model_end_to_end.py
```

---

## 6. Expected Results

- **Test Suite**: Outputs `Ran 211 tests ...` followed by `OK` with exit code `0`.
- **`evaluate-blueprint`**: Prints JSON with `"recommended_scenario": "Scenario-B"`, `"pretrain_from_scratch_justified": false`, `"gpu_ownership_break_even_months": 22.3`, and 5 registered models.
- **`run-workflow --domain cyber`**: Prints JSON with `"status": "COMPLETED"`, `"current_step": 10`, `"taint_level": "TAINTED_UNTRUSTED"`, and `"verified_by": "independent_verifier"`.
- **`examples/custom_model_end_to_end.py`**: Prints JSON confirming `"safetensors_verified": true`, `"license_verdict": "APPROVED_COMMERCIAL"`, and `"routed_model_id": "Acme-SecCoder-27B-v1"`.

---

## 7. Common Errors and Troubleshooting

| Symptom / Error | Cause | Resolution |
| :--- | :--- | :--- |
| `ModuleNotFoundError: No module named 'platform_core'` | Running Python without `PYTHONPATH=src` or without `.venv/bin/pip install -e .`. | Prefix commands with `PYTHONPATH=src` or run `.venv/bin/pip install -e .`. |
| `Unsupported workflow domain` | Passing an unrecognized `--domain` flag. | Use one of `{swe, cyber, vuln_intel, forensics, binrev, data_protocol, architecture, visual_ocr}`. |

---

## 8. Related Documentation

- [Environment Setup Guide](environment-setup.md)
- [Configuration Reference](configuration.md)
- [Custom Model Creation & Execution Guide](../CUSTOM_MODEL_GUIDE.md)
- [Step-by-Step Real-Life How-To Guides](../HOW_TO_GUIDES.md)
