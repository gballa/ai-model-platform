# Test Verification Report (`04-test-report.md`)

**Feature Slug:** `ultimate-local-model-creator`  
**Owner:** `test-verifier` (Wave 3 Test Engineer)  
**Verdict:** `PASS` (`49` / `49` tests passing, `0` failures, `0` errors, `0` skipped, `0` warnings under `-W error`)

---

## 1. Execution Summary

| Suite / Scope | Command | Tests | Result | Runtime |
| :--- | :--- | :---: | :---: | :---: |
| **Full Repository Suite (strict `-W error`)** | `PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v` | 49 | `OK` | 4.674s |
| **New Wave 3 Modules & CLI/Skills** | `PYTHONPATH=src .venv/bin/python -W error -m unittest tests/test_corpus_and_scratch_trainer.py tests/test_agy_sdk_and_skills.py -v` | 14 | `OK` | 3.963s |

- **New test files created:**
  - [`tests/test_corpus_and_scratch_trainer.py`](../../../tests/test_corpus_and_scratch_trainer.py) (`9` test methods across `TestCorpusHarvester` and `TestScratchTrainerAndStrategyAdvisor`)
  - [`tests/test_agy_sdk_and_skills.py`](../../../tests/test_agy_sdk_and_skills.py) (`5` test methods across `TestAgySdkBridge` and `TestCliAndWorkspaceSkillSubprocesses`)
- **Static hygiene check:** AST inspection confirmed `0` unused imports and `0` `TODO`/`FIXME` markers in both new test files.

---

## 2. Coverage Matrix & Defect Remediation Verified

### 2.1 Corpus Harvester & Teacher Distillation ([`tests/test_corpus_and_scratch_trainer.py`](../../../tests/test_corpus_and_scratch_trainer.py))
- `PromptInjectionSanitizer`: verified removal of zero-width/control characters (`\u200b`, `\u202e`, `\ufeff`), redaction of `<|im_start|>`, `ignore all previous instructions`, `### System:`, `system: override`, shell pipe/exfiltration payloads, and preservation of legitimate code and security notes.
- `DomainChunker`: verified sliding-window overlap and fenced code block preservation (` ```python ... ``` `) without unbalanced fence leakage across chunks.
- `PDFBookExtractor`: verified extraction of `.md`, `.txt`, `.rst`, and zlib-compressed `.pdf` fixtures, `max_chars` truncation metadata, rejection of symlinks, `..` traversal, and unsupported extensions.
- `RateLimitedWebHarvester`: verified offline mocked opener for SSRF IP/metadata blocking (`127.0.0.1`, `169.254.169.254`, `localhost`, private DNS resolution), `session_tainted=True` egress blocking, `time.monotonic()` rate pacing, HTTP 429 `RateLimitError` + exponential backoff without double-sleeping, HTTP 5xx retry recovery, bounded 4xx error body truncation, HTML `<script>`/`<style>` stripping, and `MAX_RESPONSE_BYTES` overflow rejection.
- `TeacherDistiller` & `CorpusHarvesterPipeline`: verified `HybridKnowledgeStore` `< 200,000` token `DIRECT_PREFIX_CACHE` enforcement, `LicenseComplianceAuditor` rejection of disallowed teacher/source licenses, `DatasetHygienePipeline` Gate 3 fail-closed behavior (`execution_verified=False` by default unless oracle-verified, opt-in `allow_unexecuted_text_synthesis=True`), duplicate/contaminated filtering, atomic JSONL export, and symlink rejection.

### 2.2 Strategy Advisor, BPE Tokenizer & Compact Scratch SLM ([`tests/test_corpus_and_scratch_trainer.py`](../../../tests/test_corpus_and_scratch_trainer.py))
- `CreationStrategyAdvisor`: verified `PRETRAINED_RAG_ONLY` (`< 50K` tokens), `PRETRAINED_QLORA_FIRST` on 36 GB Apple Silicon M3 Pro (`safe_model_budget_gb=28.08`), `FROM_SCRATCH_COMPACT_SLM` (custom vocab / `10M–350M` target), and `MULTI_GPU_FULL_POST_TRAIN` (`CLUSTER_DEFAULT`).
- `BytePairTokenizer`: verified UTF-8 multi-byte round-trip (`λ`, `café`, `🚀`), special tokens `<pad>`, `<bos>`, `<eos>`, `<unk>`, JSON `save`/`load` round-trip, symlink rejection, and `bool`-as-`int` rejection.
- `ScratchSLMConfig`: verified `10M`/`50M`/`125M`/`350M` `preset_tier` parameter estimates, `bool`-as-`int` rejection, disallowed license rejection, and unsafe `model_id` slug rejection.
- `CompactTransformerSLMTrainer`: verified deterministic CPU training (`final_loss < initial_loss`, identical `checkpoint_sha256` across runs), `SafetensorsValidator.validate_file` F32 span verification, manifest/tokenizer loading, `generate_sample`, symlink & manifest traversal rejection, plus regression coverage for `1408`-byte (`0x0580` / `\x80\x05`) Safetensors headers vs. genuine disguised pickle protocol 2–5 rejection in [`src/platform_core/deploy_security/governance.py`](../../../src/platform_core/deploy_security/governance.py).

### 2.3 Google Antigravity SDK Bridge, CLI & Workspace Skills ([`tests/test_agy_sdk_and_skills.py`](../../../tests/test_agy_sdk_and_skills.py))
- `AgySkillDiscovery`: verified discovery of all 5 workspace skills under [`.agents/skills/`](../../../.agents/skills/), YAML frontmatter metadata extraction, and rejection of `..` traversal, symlinked skill directories, and symlinked `SKILL.md` files.
- `AgyStdioMCPBridge`: verified valid Python identifier naming across all registered MCP tools and parameters, `session_tainted=True` hiding/blocking of `vuln_sync_live_feeds` (`-32003`), `serve_stdio` JSON-RPC 2.0 `initialize`, `tools/list`, `tools/call`, `ping`, and bounded `MAX_JSONRPC_LINE_BYTES` line handling (`-32600` recovery).
- `AgyLocalOrchestrator`: verified `is_sdk_installed()` graceful probe, LiteRT `~` expansion in `build_sdk_config`, tainted non-loopback `base_url` blocking, and strict `IndependentVerifierAgent` gating in `run_local_agent` (both `COMPLETED` on valid output and `VERIFIER_REJECTED` on empty output).
- `platform_core.cli` subprocesses: verified `recommend-strategy`, `harvest-corpus` (`--limit 0` rejection), `train-scratch-slm`, `run-agy-local`, and `mcp-stdio-bridge` under `-W error`.
- Workspace skill script subprocesses: verified `--help`, `--limit 0` failure, valid `--output` JSON runs, symlink `--output` rejection, `run_agy_agent.py` fail-closed `session_tainted=True` default & `--clean` override, `mcp-serve --request-file` line bounding, and `train_scratch_slm.py generate` `model_id` reporting across all 5 scripts:
  - [`.agents/skills/corpus-harvester/scripts/harvest_corpus.py`](../../../.agents/skills/corpus-harvester/scripts/harvest_corpus.py)
  - [`.agents/skills/local-model-advisor/scripts/recommend_strategy.py`](../../../.agents/skills/local-model-advisor/scripts/recommend_strategy.py)
  - [`.agents/skills/scratch-slm-trainer/scripts/train_scratch_slm.py`](../../../.agents/skills/scratch-slm-trainer/scripts/train_scratch_slm.py)
  - [`.agents/skills/pretrained-qlora-finetuner/scripts/run_qlora_pipeline.py`](../../../.agents/skills/pretrained-qlora-finetuner/scripts/run_qlora_pipeline.py)
  - [`.agents/skills/agy-local-agent-runner/scripts/run_agy_agent.py`](../../../.agents/skills/agy-local-agent-runner/scripts/run_agy_agent.py)
