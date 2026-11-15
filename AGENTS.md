# `platform_core` — Workspace Engineering & Domain Invariants

## 1. Test & CLI Verification Commands
- **Unit & Integration Tests (strict warning gate)**:
  `PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v`
- **CLI Entrypoints**:
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli evaluate-blueprint`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli train-model`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli create-custom-model --model-id <id> --domain {swe,cyber,binrev,data_protocol,architecture,visual_ocr,forensics,vuln_intel} --dataset-file <jsonl> --output-dir <dir>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain {swe,cyber,binrev,data_protocol,architecture,visual_ocr,forensics,vuln_intel}`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-custom-model --manifest <manifest.json> --payload-file <task.json>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli inspect-data --hex <hex_bytes>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli hardware-check`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli download-model --model-id <repo_id> --license <spdx> --local-dir <dir>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli sync-vuln-db --db-path <sqlite_db> --feeds kev epss`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli audit-vulns --project-dir <dir>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli scan-forensics --target-dir <dir> --platform {auto,ios,android,host}`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli analyze-image --path <file>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-benchmarks`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli harvest-corpus --pdf <file_or_dir> [--url <url>] [--distill-output <jsonl>]`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli recommend-strategy --corpus-tokens <int> --domain <domain>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli train-scratch-slm --model-id <id> --corpus-file <file> --output-dir <dir>`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli run-agy-local --prompt <prompt> [--runtime {local_openai,litert}]`
  - `PYTHONPATH=src .venv/bin/python -m platform_core.cli mcp-stdio-bridge [--server <name>]`
  - `PYTHONPATH=src .venv/bin/python examples/custom_model_end_to_end.py`

## 2. Architectural & Domain Invariants
1. **Executor vs. Verifier Separation (`SecVerifier` Gate)**:
   - Executor agents (`SoftwareEngineeringAgent`, `ReverseEngineeringAgent`, `DefensiveCyberAgent`, `MultimodalDataAgent`) must never set `TaskStatus.COMPLETED`. Only `IndependentVerifierAgent` (`can_mark_completed=True`) may transition a task to `COMPLETED` after deterministic verification.
2. **Taint Propagation (`TAINTED_UNTRUSTED`)**:
   - Any session ingesting external repositories or untrusted binaries at Step 1 must be marked `TAINTED_UNTRUSTED`, stripping `network_egress` and `admin_deploy` tool capabilities and enforcing `internal=True` sandbox network isolation.
3. **200K-Token Hybrid Knowledge Rule**:
   - `HybridKnowledgeStore.retrieve` must return `DIRECT_PREFIX_CACHE` whenever total corpus tokens are `< 200,000` (regardless of `top_k`), switching to `HYBRID_PGVECTORSCALE_SEARCH` only at `>= 200,000` tokens.
4. **Finite-Sample Entropy & Struct Layout IoU**:
   - `DataAndVisualMCPServer.classify_transformation` must normalize Shannon entropy against $\min(8.0, \log_2 N)$ so short (16B–64B) ciphertext blocks are classified as `ENCRYPTION`.
   - `BinRevDecompileRewardOracle.compute_struct_layout_iou` must score DWARF struct fields using byte-interval `[offset, offset + size)` overlap IoU rather than exact offset-key lookup.
5. **Forensic Anti-Fabrication & Epistemic Separation**:
   - `ForensicsMCPServer` and `IndependentVerifierAgent` must reject any `CONFIRMED_IOC_MATCH` lacking a real `artifact_path` and 64-hex `artifact_sha256`, preserve `visibility_limitations` on encrypted/partial acquisitions, and maintain `EpistemicStatus` (`FACT`, `HYPOTHESIS`, `UNCERTAIN`) separation on `PlatformState.epistemic_assessment`.
6. **Workspace Markdown & `.agents/` Link Portability**:
   - All checked-in `.md` files (including `docs/**`, `README.md`, `.agents/skills/**/SKILL.md`, and `.agents/artifacts/**`) MUST use repository-relative links only — never machine-local home-directory paths or `file:` URIs.
   - Workspace skills under `.agents/skills/<name>/SKILL.md` must match directory names in YAML `name:`, provide `--output` JSON reports and explicit positive `--limit` flags, and remain discoverable via `AgySkillDiscovery.discover_skills([".agents/skills"])`.
7. **Fail-Closed Script Defaults & Checkpoint Serialization Safety**:
   - CLI runners and skill scripts (`run-agy-local`, `mcp-stdio-bridge`, `run_agy_agent.py`) MUST default untrusted/agent runs to `session_tainted=True` (`--tainted`), requiring an explicit `--clean` override to enable live feeds.
   - Distilled teacher trajectories must keep `execution_verified=False` unless verified by an actual sandbox/compiler oracle (or explicitly opted in for unexecuted text synthesis).
   - Exported Safetensors checkpoints must pass `SafetensorsValidator` and avoid raw `<Q` header lengths colliding with `\x80\x02`–`\x80\x05` via benign metadata padding (`header_pad`).

## 3. Continuous Documentation Governance (Mandatory for All Agents)
- **Authoritative Standards**: Every human developer and AI coding agent MUST follow [docs/DOCUMENTATION_STANDARDS.md](docs/DOCUMENTATION_STANDARDS.md) and [docs/AI_DOCUMENTATION_POLICY.md](docs/AI_DOCUMENTATION_POLICY.md).
- **Pre-Implementation Discovery**: Before modifying code or docs, inspect [docs/DOCUMENTATION_INDEX.md](docs/DOCUMENTATION_INDEX.md) and [docs/DOCUMENTATION_COVERAGE.md](docs/DOCUMENTATION_COVERAGE.md) to identify affected documentation, diagrams, schemas, and module READMEs.
- **Same-Task Synchronization & Reporting**: Update affected READMEs, architecture diagrams, API/config references, and coverage matrices in the same task, verify all relative links, and include the mandatory `## Documentation Impact` and `## Documentation Assessment` blocks in the final task report.
