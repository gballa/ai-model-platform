---
name: corpus-harvester
description: >-
  Use this skill when the user wants to harvest technical PDF books, Markdown/reST
  documentation, or allowlisted web pages into a sanitized RAG knowledge store
  and teacher-distilled training trajectories for local model creation.
---

# Corpus Harvester & Teacher Distiller

## Overview

Extracts and chunks technical PDFs, Markdown, reStructuredText, and plain-text books alongside rate-limited, firewall-gated public web pages. Every document passes through indirect prompt-injection sanitization before indexing into `HybridKnowledgeStore` (enforcing the `< 200,000`-token `DIRECT_PREFIX_CACHE` rule) or distilling into `TrainingTrajectoryRecord` JSONL via `TeacherDistiller` and `DatasetHygienePipeline`.

## Dependencies

- **Runtime**: `.venv/bin/python` works out of the box with `PYTHONPATH=src` and zero extra pip installs for core/fallback paths (pure Python stdlib PDF stream decompression via `DataAndVisualMCPServer.extract_document_text`, SQLite FTS5 RAG, and offline deterministic teacher synthesis).
- **Optional extras**:
  - `pip install -e ".[vision]"` (`pypdf`) for complex/compressed PDF object streams.
  - Local OpenAI-compatible teacher server (e.g., `mlx_lm.server`, `llama-server`, `Ollama`) when distilling with a live teacher endpoint instead of offline mock synthesis.
- **Downstream skills**:
  - `local-model-advisor`: Inspects harvested corpus token counts and hardware memory to pick RAG, QLoRA, or from-scratch SLM creation.
  - `scratch-slm-trainer`: Trains a custom BPE tokenizer and compact `.safetensors` SLM on harvested/sanitized text.
  - `pretrained-qlora-finetuner`: Fine-tunes an 8B–35B open-weight model on the distilled `TrainingTrajectoryRecord` JSONL.

## Quick Start

1. Harvest local PDF/Markdown books into a persistent SQLite RAG store and JSON report:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/corpus-harvester/scripts/harvest_corpus.py \
     harvest-pdfs --dirs docs/ --domain swe --license Apache-2.0 \
     --rag-db artifacts/rag_corpus.db --limit 25 --output artifacts/pdf_harvest.json
   ```
2. Query the RAG store (uses `DIRECT_PREFIX_CACHE` below `200,000` tokens, `HYBRID_PGVECTORSCALE_SEARCH` at `>= 200,000` tokens):
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/corpus-harvester/scripts/harvest_corpus.py \
     query-rag --rag-db artifacts/rag_corpus.db --query "CWE-78 command injection" \
     --limit 5 --output artifacts/rag_query.json
   ```
3. Distill harvested documents into hygiene-filtered `TrainingTrajectoryRecord` JSONL:
   ```bash
   PYTHONPATH=src .venv/bin/python .agents/skills/corpus-harvester/scripts/harvest_corpus.py \
     distill --input artifacts/pdf_harvest.json --target-domain swe_fuse \
     --jsonl-out artifacts/distilled_train.jsonl --limit 25 --output artifacts/distill_report.json
   ```

## Utility Scripts

All commands reside in [scripts/harvest_corpus.py](scripts/harvest_corpus.py), write structured JSON via `--output`, and require an explicit positive `--limit` (no silent default caps). Both `PYTHONPATH=src .venv/bin/python` and `.venv/bin/python` (auto-resolving `src/`) are supported.

- **`harvest-pdfs`**: Extracts `.pdf`, `.md`, `.txt`, and `.rst` files via `PDFBookExtractor` (which delegates PDF parsing to `DataAndVisualMCPServer.extract_document_text`), sanitizes prompt injections, and optionally indexes into `HybridKnowledgeStore`.
  - Required: `--limit <int>`, `--output <path>`, and at least one of `--paths <file...>` or `--dirs <dir...>`.
  - Optional: `--domain <str>`, `--license <spdx>`, `--max-chars <int>`, `--rag-db <sqlite_path>`, `--no-rag`.
- **`harvest-web`**: Fetches public URLs via `RateLimitedWebHarvester` with explicit domain allowlisting and `CyberGymFirewall` SSRF/taint checks.
  - Required: `--urls <url...>`, `--allowed-domains <host...>`, `--limit <int>`, `--output <path>`.
  - Optional: `--domain <str>`, `--license <spdx>`, `--requests-per-second <float>`, `--max-retries <int>`, `--session-tainted`, `--rag-db <sqlite_path>`, `--no-rag`.
- **`distill`**: Synthesizes `TrainingTrajectoryRecord` pairs from a harvested JSON report via `TeacherDistiller` (auditing teacher license via `LicenseComplianceAuditor` and filtering output via `DatasetHygienePipeline`).
  - Required: `--input <harvest_json>`, `--limit <int>`, `--output <path>`.
  - Optional: `--target-domain <str>`, `--teacher-model <id>`, `--teacher-license <spdx>`, `--endpoint <url>`, `--jsonl-out <path>`.
- **`query-rag`**: Queries a persisted `HybridKnowledgeStore` SQLite database and reports `retrieval_mode` and ranked chunks.
  - Required: `--rag-db <sqlite_path>`, `--query <str>`, `--limit <int>`, `--output <path>`.

## Rate Limiting

- Web harvesting enforces spacing between HTTP requests using `time.monotonic()` (default: `1.0` request/second via `--requests-per-second`).
- Transient HTTP `5xx` and `429` responses use exponential backoff (`2**attempt` seconds) logged to `stderr`.
- Persistent HTTP `429` responses after `--max-retries` raise `RateLimitError` with the target URL and configured rate limit, exiting with status code `1`.

## Prompt Injection & Security

- **Fail-Closed Egress & SSRF Guard**: `RateLimitedWebHarvester` passes every URL through `CyberGymFirewall.evaluate_egress(url, session_tainted)` before opening a socket. `--session-tainted`, `localhost`, `169.254.169.254`, RFC1918 private IPs, and non-allowlisted domains fail closed with `PermissionError`.
- **Bounded Downloads**: HTTP responses are streamed in chunks and aborted above `MAX_RESPONSE_BYTES` (5 MiB).
- **Indirect Prompt Injection Sanitization**: `PromptInjectionSanitizer.sanitize()` strips zero-width control characters and redacts markers (`ignore previous instructions`, `<|im_start|>`, `<|im_end|>`, `<|endoftext|>`, `### System:`, `system: override`) prior to RAG ingestion or distillation, recording `injection_alerts` per document.
- **Symlink & Path-Traversal Rejection**: Symlinked inputs, symlinked `--output` / `--jsonl-out` paths, and `..` path-traversal segments are rejected.
- **Provenance & Commercial Licensing**: `TeacherDistiller` enforces `APPROVED_COMMERCIAL` licenses (e.g., `Apache-2.0`, `MIT`, `BSD-3-Clause`) via `LicenseComplianceAuditor`.

## Common Mistakes

1. **Omitting `--allowed-domains` or using `harvest-web` in a tainted session**: Web egress fails closed when `--session-tainted` is set or when the host is not explicitly allowlisted.
2. **Omitting `--limit` or passing `--limit 0`**: All bounded subcommands reject missing or non-positive `--limit` values so results are never silently truncated.
3. **Writing `--output` or `--rag-db` to a symlinked path**: Symlinked targets and `..` path escapes are blocked; pass a concrete directory/file path.
