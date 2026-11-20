# Testing & Quality Assurance Guide

---

## 1. Purpose

Describe the unit, integration, security, and statistical benchmark verification suites for `platform-core`, and provide step-by-step instructions for running tests and validating `PropBench-9` results.

---

## 2. Prerequisites

- Python `>= 3.11` with `.venv` configured (`PYTHONPATH=src .venv/bin/python`).
- Test suites: 10 unit/integration modules (`tests/test_*.py`, `59` tests) and the 4-tier E2E suite (`tests/e2e/`, `152` tests), totaling `211` automated tests (index: [`tests/README.md`](../../tests/README.md)).

---

## 3. Required Configuration

All test executions must pass Python's `-W error` flag so that any runtime warning, deprecation warning, or unclosed SQLite `ResourceWarning` immediately fails the gate.

---

## 4. Step-by-Step Instructions

1. **Run the Unit, Integration, Adversarial Security & 4-Tier E2E Suite (`211` Tests)**: Execute `unittest discover -s tests -v` (or run `tests/e2e/test_runner.py --tier {1,2,3,4,all}` for targeted E2E tiers).
2. **Understand the Core Test Classes in `tests/test_platform_core.py` (20 Tests)**:
   - `TestDeployAndSupplyChainSecurity`: Tests `SafetensorsValidator` (valid checkpoints, `.pt` extension block, disguised pickle header `\x80\x02`–`\x80\x05`, overlapping offsets, `shape * dtype` mismatch), `LicenseComplianceAuditor` (`Apache-2.0`/`MIT` approval, `Llama-4-Community` EU rejection, `GPL-3.0`/`Proprietary-Closed-API` rejection), `SignedManifestVerifier` (HMAC-SHA256 verification, taint lockdown of `network_egress`/`admin_deploy`), `CyberGymFirewall` (taint block, SSRF/IP literal block, Squid config), and `K8sAgentSandboxGenerator`.
   - `TestLayer1IntelligenceAndTraining`: Tests `ModelRegistry` & `HardwareFeasibilityPlanner`, `AdaptiveModelRouter` & `BestOfNVerifierPruner`, `RadixPrefixCacheSimulator` & `ServingEndpointConfig`, `SWECyberRewardOracle`, `BinRevDecompileRewardOracle`, `GRPOTrainer`, `MOPDDistiller`, `DistributedTrainingSpecBuilder`, and `DPOTrainer`.
   - `TestLayer2ExecutionAndMCPServers`: Tests `CodeGraphMCPServer` (Python AST + polyglot Rust/Go/C/C++/TS/Java CST + SCIP inverse callers + `NoConfidentMatch` fallback + Git co-change blast radius + `apply_str_replace_edit`), `BinRevMCPServer` (ELF/Mach-O/PE + `checksec` + prompt injection detection + `SK²Decompile`), `DefensiveCyberMCPServer` (CPG taint + `SecVerifier` Dual-Gate), `DataAndVisualMCPServer` (finite-sample entropy classification, streaming decompression-bomb defense, Kaitai `.ksy` synthesis, Epistemic Visual Grounder, `ActionGrouping`), and `FirecrackerSandboxManager` (CoW `<15ms` restore, env var stripping, path traversal block, symlink rejection, deleted-file pruning), plus executor/verifier separation, 10-step workflows, human `interrupt()` pause/resume, and CoW rollback retry recovery.
   - `TestLayer3EvolutionMemoryAndCLI`: Tests `BitemporalEpisodicMemory` (fact supersession and `query_facts_as_of`), `HybridKnowledgeStore` (`<200K` `DIRECT_PREFIX_CACHE` vs `>=200K` `HYBRID_PGVECTORSCALE_SEARCH` + prompt injection redaction), `DatasetHygienePipeline` (4-gate filtering), `BenchmarkEvaluator` (95% CI, $\text{pass}^4$, Canary Promotion Gate), `PropBench9Suite`, `ControlledImprovementCycle`, CLI entrypoints, multi-threaded SQLite access, symlink rejection, and boolean-as-int rejection.
   - **Specialized & E2E Modules (`191` additional tests)**: [`test_inference_and_training.py`](../../tests/test_inference_and_training.py) (5), [`test_memory_rag_and_vision.py`](../../tests/test_memory_rag_and_vision.py) (2), [`test_vuln_intel_and_cyber.py`](../../tests/test_vuln_intel_and_cyber.py) (3), [`test_forensics_spyware.py`](../../tests/test_forensics_spyware.py) (2), [`test_benchmarks_and_epistemic.py`](../../tests/test_benchmarks_and_epistemic.py) (3), [`test_corpus_and_scratch_trainer.py`](../../tests/test_corpus_and_scratch_trainer.py) (9), [`test_agy_sdk_and_skills.py`](../../tests/test_agy_sdk_and_skills.py) (5), [`test_e2e_harness.py`](../../tests/test_e2e_harness.py) (4), [`test_heretic_and_brain.py`](../../tests/test_heretic_and_brain.py) (6), and the 4-tier [`tests/e2e/`](../../tests/e2e/test_runner.py) suite (152 tests across Tiers 1–4).
3. **Run the `PropBench-9` Statistical Evaluator**: Use `BenchmarkEvaluator` to compute 5-run 95% confidence intervals and $\text{pass}^4 / \text{pass}@1 \ge 0.85$ consistency.

---

## 5. Verified Commands and Examples

```bash
# 1. Run all 211 test methods under strict warning gate
PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v

# 2. Run a single test class or E2E tier
PYTHONPATH=src .venv/bin/python -W error -m unittest tests.test_platform_core.TestDeployAndSupplyChainSecurity -v
PYTHONPATH=src .venv/bin/python -W error tests/e2e/test_runner.py --tier 4 --verbose

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

- `unittest discover` outputs `Ran 211 tests ... OK`.
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
