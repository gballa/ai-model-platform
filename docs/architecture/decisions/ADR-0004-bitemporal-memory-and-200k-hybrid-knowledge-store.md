# ADR-0004: Bitemporal Graphiti/GAM Episodic Memory, 200K-Token Prefix-Cache Threshold & 3-Tier SQLite Code Graph

- **Identifier:** ADR-0004
- **Status:** Accepted
- **Date:** 2026-11-15
- **Source Modules:** [`memory.py`](../../../src/platform_core/layer3_evolution/memory.py), [`mcp_tools.py`](../../../src/platform_core/layer2_execution/mcp_tools.py)

---

## 1. Context

Long-horizon engineering agents require three distinct forms of memory and retrieval:
1. **Structural Codebase Memory**: Navigating polyglot repositories (`.py`, `.ts`, `.js`, `.go`, `.rs`, `.c`, `.cpp`, `.h`, `.java`) without reading entire raw files into the LLM prompt on every turn.
2. **Episodic Architectural Memory**: Tracking how system facts evolve across commits without overwriting historical state needed for regression debugging or time-travel audit.
3. **External Knowledge Retrieval**: Avoiding noisy top-$k$ RAG chunk fragmentation when the documentation corpus fits directly inside modern 262K–1M context windows with prefix caching.

---

## 2. Decision

1. **Three-Tier Structural Code Graph (`CodeGraphMCPServer`)**:
   - **Tier 1 (Incremental AST/CST + BLAKE2b Cache)**: Hash file contents with 16-byte BLAKE2b in SQLite (`indexed_files`). Re-parse only modified files using Python `ast` (for `.py`) or fault-tolerant balanced-brace CST extraction (`_parse_polyglot_cst`), reducing raw file tokens to compact signature skeletons.
   - **Tier 2 (SCIP Symbol & Inverse Call-Graph Index)**: Store canonical SCIP IDs and outgoing callee lists (`calls_json`) in `code_symbols`. Resolve definitions and inverse callers via `query_symbol()`, returning an explicit `NoConfidentMatch` status with line-level fallback hits when a symbol is absent.
   - **Tier 3 (Temporal Git Co-Change Graph)**: Track historical commit file co-occurrence via `ingest_git_commits()` and combine with structural dependents in `analyze_blast_radius()`.
2. **Bitemporal Episodic Memory (`BitemporalEpisodicMemory`)**:
   - Separate append-only `ProgressionEvent` nodes from `BitemporalFactEdge` records (`valid_from`, `valid_to`, `invalid_at`).
   - When `upsert_architectural_fact()` records a new value for `(subject, predicate)`, close the prior active edge (`valid_to = v_from`, `invalid_at = now`) and insert a new active edge, enabling exact point-in-time queries via `query_facts_as_of(point_in_time)`.
3. **200K-Token Hybrid Knowledge Threshold (`HybridKnowledgeStore`)**:
   - Sanitize ingested documents against indirect prompt injection (`INJECTION_REGEX`) and record SHA-256 digests.
   - Enforce `DIRECT_PREFIX_CACHE_TOKEN_LIMIT = 200_000`: whenever `0 < total_corpus_tokens < 200_000`, `retrieve()` returns `DIRECT_PREFIX_CACHE` (all chunks, score `1.0`) regardless of `top_k`. Only when `total_corpus_tokens >= 200_000` does `retrieve()` switch to `HYBRID_PGVECTORSCALE_SEARCH` ($0.65 \times \text{cosine} + 0.35 \times \text{lexical}$).

---

## 3. Consequences

- **Positive**: Eliminates RAG chunking loss on corpora under 200K tokens, achieves `O(changed files)` incremental indexing via BLAKE2b caching, supports multi-threaded SQLite access via `RLock` + `WAL`, and preserves full historical auditability of architectural facts.
- **Trade-offs**: Very large repositories (`>= 200,000` knowledge tokens) transition from full-context prefix caching to top-$k$ hybrid vector/lexical ranking.

---

## 4. Alternatives Considered

1. **Always Using Top-$k$ Vector RAG**: Rejected because chunking small-to-medium technical corpora (`< 200K` tokens) degrades cross-reference reasoning and prevents SGLang RadixAttention prefix cache reuse.
2. **Destructive Key-Value Fact Overwrites**: Rejected because overwriting `(subject, predicate)` facts destroys the ability to answer "what authentication format was active at commit X / timestamp T?".
