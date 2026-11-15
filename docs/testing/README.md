# Testing & Quality Assurance Guide

---

## 1. Purpose

Describe the unit, integration, security, and statistical benchmark verification suites for `platform-core`, and provide step-by-step instructions for running tests and validating `PropBench-9` results.

---

## 2. Prerequisites

- Python `>= 3.11` with `.venv` configured (`PYTHONPATH=src .venv/bin/python`).
- Test suite file: [`tests/test_platform_core.py`](../../tests/test_platform_core.py) (local guide: [`tests/README.md`](../../tests/README.md)).

---

## 3. Required Configuration

All test executions must pass Python's `-W error` flag so that any runtime warning, deprecation warning, or unclosed SQLite `ResourceWarning` immediately fails the gate.

---

## 4. Step-by-Step Instructions

1. **Run the Unit, Integration & Adversarial Security Suite**: Execute `unittest discover` across `tests/`.
2. **Understand the 6 Test Classes in `tests/test_platform_core.py`**:
   - `TestDeployAndSupplyChainSecurity`: Tests `SafetensorsValidator` (valid checkpoints, `.pt` extension block, disguised pickle header `\x80\x02`–`\x80\x05`, overlapping offsets, `shape * dtype` mismatch), `LicenseComplianceAuditor` (`Apache-2.0`/`MIT` approval, `Llama-4-Community` EU rejection, `GPL-3.0`/`Proprietary-Closed-API` rejection), `SignedManifestVerifier` (HMAC-SHA256 verification, taint lockdown of `network_egress`/`admin_deploy`), `CyberGymFirewall` (taint block, SSRF/IP literal block, Squid config), and `K8sAgentSandboxGenerator`.
   - `TestLayer1IntelligenceAndTraining`: Tests `ModelRegistry` & `HardwareFeasibilityPlanner`, `AdaptiveModelRouter` & `BestOfNVerifierPruner`, `RadixPrefixCacheSimulator` & `ServingEndpointConfig`, `SWECyberRewardOracle`, `BinRevDecompileRewardOracle`, `GRPOTrainer`, `MOPDDistiller`, `DistributedTrainingSpecBuilder`, and `DPOTrainer`.
   - `TestLayer2MCPServersAndSandbox`: Tests `CodeGraphMCPServer` (Python AST + polyglot Rust/Go/C/C++/TS/Java CST + SCIP inverse callers + `NoConfidentMatch` fallback + Git co-change blast radius + `apply_str_replace_edit`), `BinRevMCPServer` (ELF/Mach-O/PE + `checksec` + prompt injection detection + `SK²Decompile`), `DefensiveCyberMCPServer` (CPG taint + `SecVerifier` Dual-Gate), `DataAndVisualMCPServer` (finite-sample entropy classification, streaming decompression-bomb defense, Kaitai `.ksy` synthesis, Epistemic Visual Grounder, `ActionGrouping`), and `FirecrackerSandboxManager` (CoW `<15ms` restore, env var stripping, path traversal block, symlink rejection, deleted-file pruning).
   - `TestLayer2OrchestratorAndAgents`: Tests executor vs. verifier separation (`PermissionError` when `SoftwareEngineeringAgent` attempts `COMPLETED`), 10-step workflows across `swe`/`cyber`/`binrev`/`data_protocol`, human `interrupt()` approval gate (`AWAITING_HUMAN_APPROVAL` -> `approve_and_resume`), and automatic CoW rollback + retry recovery.
   - `TestLayer3EvolutionMemoryAndEvaluation`: Tests `BitemporalEpisodicMemory` (fact supersession and `query_facts_as_of`), `HybridKnowledgeStore` (`<200K` `DIRECT_PREFIX_CACHE` vs `>=200K` `HYBRID_PGVECTORSCALE_SEARCH` + prompt injection redaction), `DatasetHygienePipeline` (4-gate filtering), `BenchmarkEvaluator` (95% CI, $\text{pass}^4$, Canary Promotion Gate), `PropBench9Suite`, and `ControlledImprovementCycle`.
   - `TestCustomModelPipelineAndCLI`: Tests CLI entrypoints (`evaluate-blueprint`, `train-model`, `create-custom-model`, `run-workflow`, `run-custom-model`, `inspect-data`), multi-threaded SQLite access (`ThreadPoolExecutor`), symlink rejection, and boolean-as-int rejection.
3. **Run the `PropBench-9` Statistical Evaluator**: Use `BenchmarkEvaluator` to compute 5-run 95% confidence intervals and $\text{pass}^4 / \text{pass}@1 \ge 0.85$ consistency.

---

## 5. Verified Commands and Examples

```bash
# 1. Run all 20 test methods under strict warning gate
PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v

# 2. Run a single test class
PYTHONPATH=src .venv/bin/python -W error -m unittest tests.test_platform_core.TestDeployAndSupplyChainSecurity -v

# 3. Run the end-to-end custom model integration script
PYTHONPATH=src .venv/bin/python -W error examples/custom_model_end_to_end.py
```

### Statistical Multi-Run & $\text{pass}^4$ Evaluation Example

```python
from platform_core.layer3_evolution import BenchmarkEvaluator, PropBench9Suite

specs = {s.bench_id: s for s in PropBench9Suite.all_specs()}
secfix_spec = specs["PropBench-SecFix"]

ci_result = BenchmarkEvaluator.evaluate_multi_run(
    benchmark_id=secfix_spec.bench_id,
    run_scores=[82.1, 82.5, 81.9, 82.3, 82.2],
    target_threshold=secfix_spec.target_score,
)
pass_k = BenchmarkEvaluator.compute_pass_hat_k(
    task_trial_outcomes=[[True, True, True, True], [True, True, True, True], [False, False, False, False]],
    k=4,
)
print("Mean:", ci_result.mean_score, "+/-", ci_result.ci_95_margin, "| Meets target:", ci_result.meets_target)
print("pass@1:", pass_k["pass_at_1"], "| pass^4:", pass_k["pass_hat_k"], "| SLA met:", pass_k["meets_85pct_consistency_sla"])
```

---

## 6. Expected Results

- `unittest discover` outputs `Ran 20 tests ... OK`.
- The statistical snippet outputs `Mean: 82.2 +/- 0.196 | Meets target: True` and `pass@1: 66.67 | pass^4: 66.67 | SLA met: True`.

---

## 7. Common Errors and Troubleshooting

| Error | Cause | Resolution |
| :--- | :--- | :--- |
| `ResourceWarning: unclosed database` | Test instantiated `ExecutionLifecycleOrchestrator`, `SQLiteStateCheckpointer`, or `CodeGraphMCPServer` without calling `.close()`. | Call `.close()` in `try...finally` or `addCleanup()`. |
| `ValueError: Baseline and candidate benchmark keys must match.` | Passing mismatched dictionary keys to `BenchmarkEvaluator.evaluate_canary_promotion()`. | Ensure `baseline_runs` and `candidate_runs` contain identical benchmark IDs. |

---

## 8. Related Documentation

- [Tests Directory README](../../tests/README.md)
- [Layer 3 Evolution Module Reference](../modules/layer3-evolution.md)
- [Development Workflow Guide](../development/development-workflow.md)
