# Module Reference: Layer 3 — Evolution, Bitemporal Memory & PropBench-9 (`platform_core.layer3_evolution`)

**Source Directory:** [`src/platform_core/layer3_evolution/`](../../src/platform_core/layer3_evolution/)  
**Local Module README:** [`src/platform_core/layer3_evolution/README.md`](../../src/platform_core/layer3_evolution/README.md)

---

## Table of Contents

1. [Module Responsibilities & Boundaries](#1-module-responsibilities--boundaries)
2. [`memory.py` — `BitemporalEpisodicMemory` & `HybridKnowledgeStore`](#2-memorypy--bitemporalepisodicmemory--hybridknowledgestore)
3. [`data_factory.py` — Trajectory Factories & `DatasetHygienePipeline`](#3-data_factorypy--trajectory-factories--datasethygienepipeline)
4. [`corpus_harvester.py` — Book/Web Corpus Harvesting, Sanitization & Teacher Distillation](#4-corpus_harvesterpy--bookweb-corpus-harvesting-sanitization--teacher-distillation)
5. [`evaluation.py` — `PropBench9Suite` & `BenchmarkEvaluator`](#5-evaluationpy--propbench9suite--benchmarkevaluator)
6. [`observability.py` — `ControlledImprovementCycle`](#6-observabilitypy--controlledimprovementcycle)
7. [Testing & Verification](#7-testing--verification)
8. [Related Documentation](#8-related-documentation)

---

## 1. Module Responsibilities & Boundaries

`platform_core.layer3_evolution` provides long-term bitemporal memory, hybrid knowledge retrieval, automated trajectory generation and decontamination, statistical benchmark evaluation, and the 8-step continuous improvement loop.

---

## 2. `memory.py` — `BitemporalEpisodicMemory` & `HybridKnowledgeStore`

- **`BitemporalEpisodicMemory`**:
  - `append_event(session_id, event_type, summary, commit_sha=None, timestamp=None) -> ProgressionEvent`: Appends an immutable event to the GAM Event Progression Graph.
  - `upsert_architectural_fact(subject, predicate, object_val, commit_sha, valid_from=None) -> BitemporalFactEdge`: Closes any superseded active fact (`valid_to = v_from`, `invalid_at = now`) and inserts a new active `BitemporalFactEdge`.
  - `query_active_facts(subject=None) -> list[BitemporalFactEdge]`: Returns facts with `valid_to is None and invalid_at is None`.
  - `query_facts_as_of(point_in_time, subject=None) -> list[BitemporalFactEdge]`: Returns facts where `valid_from <= point_in_time` and `(valid_to is None or point_in_time < valid_to)`.
- **`HybridKnowledgeStore`**:
  - `DIRECT_PREFIX_CACHE_TOKEN_LIMIT = 200_000`.
  - `ingest_document(chunk_id, source_uri, content, embedding=None) -> KnowledgeDocumentChunk`: Redacts prompt injection patterns (`INJECTION_REGEX`), computes SHA-256 provenance, estimates token count (`max(1, len(sanitized) // 4)`), and computes a 16-dim deterministic embedding if none is supplied.
  - `retrieve(query, top_k=5) -> dict[str, Any]`: Returns `"retrieval_mode": "DIRECT_PREFIX_CACHE"` when `0 < total_tokens < 200_000`, and `"HYBRID_PGVECTORSCALE_SEARCH"` ($0.65 \times \text{cosine} + 0.35 \times \text{lexical}$) when `total_tokens >= 200_000` (or `0`).

---

## 3. `data_factory.py` — Trajectory Factories & `DatasetHygienePipeline`

- **`SWEFuseFactory.build_pair(...)`**: Produces paired `(guided, issue_free)` `TrainingTrajectoryRecord` instances for the same bug fix.
- **`SecBenchFactory.build_record(...)`**: Produces sanitizer-verified CVE remediation records (tracking `INSTANCE_GENERATION_COST_USD = 0.87`).
- **`DecompileBenchFactory.build_record(...)`**: Validates compiler optimization level (`{-O0, -O1, -O2, -O3, -Os}`) and builds ReCopilot decompilation training tuples.
- **`DatasetHygienePipeline.filter_records(records)`**: Enforces Gate 1 (Commercial License Audit), Gate 2 (Benchmark Repo & CVE Blocklist), Gate 3 (`execution_verified=True`), and Gate 4 (3-shingle BLAKE2b Jaccard deduplication `< 0.85`).

---

## 4. `corpus_harvester.py` — Book/Web Corpus Harvesting, Sanitization & Teacher Distillation

- **`PromptInjectionSanitizer.sanitize(text)`**: Strips zero-width and bidirectional control characters (`\u200b`, `\u202e`, `\ufeff`) and redacts prompt-injection payloads (`ignore previous instructions`, `<|im_start|>`, `<|im_end|>`, `<|endoftext|>`, `### System:`, `system: override`, and shell pipe/exfiltration strings) while preserving legitimate source code.
- **`DomainChunker.chunk_text(text, chunk_chars=2400, overlap_chars=300, preserve_code_blocks=True)`**: Chunks technical documents with overlap while preserving fenced code blocks without unbalanced fence leakage.
- **`PDFBookExtractor`**: Extracts `.pdf` (delegating to `DataAndVisualMCPServer.extract_document_text`), `.md`, `.txt`, and `.rst` via `extract_book()` and `extract_directory()`, rejecting `..` traversal, symlinked targets, and symlinked ancestor directories.
- **`RateLimitedWebHarvester`**: Enforces `CyberGymFirewall.evaluate_egress(url, session_tainted)` fail-closed before every request, paces fetches via `time.monotonic()`, caps responses at `MAX_RESPONSE_BYTES` (`5 MiB`) and 4xx error bodies at `1024` bytes, retries 5xx/429 with exponential backoff without double-sleeping, and raises `RateLimitError` on 429 exhaustion.
- **`TeacherDistiller`**: Synthesizes `TrainingTrajectoryRecord` items after auditing teacher and source licenses (`LicenseComplianceAuditor`), initializes `execution_verified=False` unless verified by a deterministic `verifier` callable (or opted into `allow_unexecuted_text_synthesis=True`), passes records through `DatasetHygienePipeline`, and exports JSONL atomically (`export_distilled_jsonl()`).
- **`CorpusHarvesterPipeline`**: Orchestrates `PDFBookExtractor` and `RateLimitedWebHarvester`, ingesting sanitized chunks into `HybridKnowledgeStore` (preserving `< 200,000` token `DIRECT_PREFIX_CACHE` routing).

---

## 5. `evaluation.py` — `PropBench9Suite` & `BenchmarkEvaluator`

- **`BenchmarkEvaluator`**:
  - `evaluate_multi_run(benchmark_id, run_scores, target_threshold) -> MultiRunBenchmarkResult`: Computes sample mean, sample standard deviation, and 95% confidence interval margin $1.96 \times s / \sqrt{n}$.
  - `compute_pass_hat_k(task_trial_outcomes, k=4) -> dict[str, Any]`: Computes $\text{pass}@1$, $\text{pass}^k$, and `consistency_ratio` (`meets_85pct_consistency_sla = consistency_ratio >= 0.85`).
  - `evaluate_canary_promotion(baseline_runs, candidate_runs, target_domains) -> dict[str, Any]`: Promotes iff `len(regressions) == 0` and `len(significant_gains) > 0` beyond `combined_margin = max(base_ci, cand_ci, 0.25)`.
- **`PropBench9Suite`**: Defines the 9 internal benchmarks (`PropBench-RepoMod`, `PropBench-Debug`, `PropBench-FileFmt`, `PropBench-BinStruct`, `PropBench-Proto`, `PropBench-SecFix`, `PropBench-TechVis`, `PropBench-ToolOrch`, `PropBench-LongRun`).

---

## 6. `observability.py` — `ControlledImprovementCycle`

- **`TraceOutcome`**: `VERIFIED_PASS`, `RETRY_RECOVERED`, `VERIFIER_REJECTED`, `HUMAN_EDITED`.
- **`FailureRootCauseBucket`**: `KNOWLEDGE_GAP_RAG_SCIP`, `TOOLING_PARSER_BUG`, `MODEL_WEIGHT_REASONING_GAP`.
- **`ControlledImprovementCycle.execute_cycle(...)`**: Executes all 8 steps of the offline continuous improvement loop.

---

## 7. Testing & Verification

Covered by `TestLayer3EvolutionMemoryAndEvaluation` in [`tests/test_platform_core.py`](../../tests/test_platform_core.py), `TestMemoryRagAndVision` in [`tests/test_memory_rag_and_vision.py`](../../tests/test_memory_rag_and_vision.py), `TestBenchmarksAndEpistemic` in [`tests/test_benchmarks_and_epistemic.py`](../../tests/test_benchmarks_and_epistemic.py), and `TestCorpusHarvester` in [`tests/test_corpus_and_scratch_trainer.py`](../../tests/test_corpus_and_scratch_trainer.py).

---

## 8. Related Documentation

- [8-Step Controlled Improvement Cycle](../workflows/controlled-improvement-cycle.md)
- [ADR-0004: Bitemporal Memory & 200K Knowledge Store](../architecture/decisions/ADR-0004-bitemporal-memory-and-200k-hybrid-knowledge-store.md)
- [ADR-0006: Local AI Creator & Google Antigravity SDK Bridge](../architecture/decisions/ADR-0006-local-ai-creator-and-antigravity-sdk.md)
- [Layer 3 Local README](../../src/platform_core/layer3_evolution/README.md)
