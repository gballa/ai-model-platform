# Contributing to `platform-core`

Thank you for contributing to the **Proprietary Technical Intelligence Platform (`platform-core`)**. This document defines the engineering workflow, architectural invariants, quality gates, and mandatory documentation governance required for all contributions.

---

## Table of Contents

1. [Code of Conduct & Engineering Principles](#1-code-of-conduct--engineering-principles)
2. [Development Environment Setup](#2-development-environment-setup)
3. [Architectural & Security Invariants](#3-architectural--security-invariants)
4. [Development & Verification Workflow](#4-development--verification-workflow)
5. [Mandatory Documentation Governance & Impact Checklist](#5-mandatory-documentation-governance--impact-checklist)
6. [Conventional Commits & Pull Request Standards](#6-conventional-commits--pull-request-standards)
7. [Related Documentation](#7-related-documentation)

---

## 1. Code of Conduct & Engineering Principles

- **Zero External Runtime Dependencies**: `platform-core` uses only the Python 3.11+ standard library (`dependencies = []` in [pyproject.toml](pyproject.toml)). Do not introduce third-party runtime packages without an approved Architecture Decision Record (ADR).
- **Minimal, Strictly Typed Diffs**: Use `from __future__ import annotations`, explicit type annotations, frozen dataclasses for immutable value objects, and deterministic error handling. Never leave `TODO` or `FIXME` comments or unused imports.
- **Documentation as Code**: Documentation evolves in the same commit/task as the implementation under [docs/DOCUMENTATION_STANDARDS.md](docs/DOCUMENTATION_STANDARDS.md) and [docs/AI_DOCUMENTATION_POLICY.md](docs/AI_DOCUMENTATION_POLICY.md).

---

## 2. Development Environment Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

See [docs/development/environment-setup.md](docs/development/environment-setup.md) for full details.

---

## 3. Architectural & Security Invariants

Every change must preserve the workspace invariants defined in [AGENTS.md](AGENTS.md):

1. **Executor vs. Verifier Separation (`SecVerifier` Gate)**: Executor agents (`SoftwareEngineeringAgent`, `ReverseEngineeringAgent`, `DefensiveCyberAgent`, `MultimodalDataAgent`) have `can_mark_completed=False` and must never transition a `SubTask` to `TaskStatus.COMPLETED`. Only `IndependentVerifierAgent` (`can_mark_completed=True`) may do so after deterministic sandbox verification.
2. **Taint Propagation (`TAINTED_UNTRUSTED`)**: Sessions ingesting external repositories or untrusted binaries at Step 1 must be marked `TAINTED_UNTRUSTED`, blocking `network_egress` and `admin_deploy` scopes and enforcing `internal=True` microVM network isolation.
3. **200K-Token Hybrid Knowledge Rule**: `HybridKnowledgeStore.retrieve()` must return `DIRECT_PREFIX_CACHE` whenever `0 < total_corpus_tokens < 200_000` regardless of `top_k`, switching to `HYBRID_PGVECTORSCALE_SEARCH` only at `>= 200_000` tokens.
4. **Finite-Sample Entropy & Byte-Interval Struct IoU**: `DataAndVisualMCPServer.classify_transformation()` normalizes Shannon entropy against $\min(8.0, \log_2 N)$ (`math.log2(min(n, 256))`), and `BinRevDecompileRewardOracle.compute_struct_layout_iou()` scores DWARF struct fields using byte-interval `[offset, offset + size)` overlap IoU.
5. **Concurrency, Sandbox & Parser Hardening**:
   - SQLite connections (`SQLiteStateCheckpointer`, `CodeGraphMCPServer`) must use `check_same_thread=False`, `threading.RLock()`, `PRAGMA busy_timeout = 30000`, and `PRAGMA journal_mode = WAL` (for file-backed DBs).
   - Sandbox file sync-back (`FirecrackerSandboxManager`) must reject symlinks (`path.is_symlink()`), enforce `path.resolve().is_relative_to(resolved_root)`, validate `vm_id`, and prune deleted files.
   - Streaming decompression (`zlib.decompressobj`) must enforce `max_length = MAX_DECOMPRESSION_BYTES + 1` before memory allocation.
   - Integer validation on schema/model fields must reject booleans (`not isinstance(val, bool)`).

---

## 4. Development & Verification Workflow

Before submitting any change, execute all verification gates from the repository root:

```bash
# 1. Run the full unit, integration, and security test suite with warnings treated as errors
PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v

# 2. Run the end-to-end custom model creation and workflow verification script
PYTHONPATH=src .venv/bin/python -W error examples/custom_model_end_to_end.py

# 3. Verify all CLI subcommands execute cleanly
PYTHONPATH=src .venv/bin/python -m platform_core.cli evaluate-blueprint --budget 1800000
PYTHONPATH=src .venv/bin/python -m platform_core.cli train-model
PYTHONPATH=src .venv/bin/python -m platform_core.cli run-workflow --domain swe
PYTHONPATH=src .venv/bin/python -m platform_core.cli inspect-data --hex 1f8b080000000000
```

See [docs/development/development-workflow.md](docs/development/development-workflow.md) for step-by-step instructions on extending modules, adding MCP tools, and registering new models.

---

## 5. Mandatory Documentation Governance & Impact Checklist

Per [docs/DOCUMENTATION_STANDARDS.md](docs/DOCUMENTATION_STANDARDS.md) and [docs/AI_DOCUMENTATION_POLICY.md](docs/AI_DOCUMENTATION_POLICY.md), every task and pull request must complete the **Documentation Impact Checklist**:

```markdown
## Documentation Impact Checklist

- [ ] Existing documentation reviewed (`docs/DOCUMENTATION_INDEX.md` & `docs/DOCUMENTATION_COVERAGE.md`).
- [ ] Relevant root and module `README.md` files updated.
- [ ] New functionality, CLI flags, or schemas documented in `docs/modules/` and `docs/api/`.
- [ ] Architecture diagrams in `docs/architecture/` and `docs/workflows/` updated if necessary.
- [ ] API references and contracts updated if necessary.
- [ ] Configuration and environment guides (`docs/development/configuration.md`) updated.
- [ ] How-To guides (`docs/HOW_TO_GUIDES.md`, `docs/CUSTOM_MODEL_GUIDE.md`, `docs/guides/`) updated if necessary.
- [ ] ADRs in `docs/architecture/decisions/` added or updated if architectural decisions changed.
- [ ] Internal relative links verified.
- [ ] No outdated or contradictory instructions introduced.
```

---

## 6. Conventional Commits & Pull Request Standards

Use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat(layer1): ...` — New capabilities in Layer 1 (`models`, `router`, `inference`, `serving`, `training`, `scratch_trainer`, `heretic`)
- `feat(layer2): ...` — New capabilities in Layer 2 (`state`, `sandbox`, `mcp_tools`, `vuln_intel_mcp`, `forensics_mcp`, `agents`, `orchestrator`, `agy_sdk_bridge`)
- `feat(layer3): ...` — New capabilities in Layer 3 (`memory`, `corpus_harvester`, `evaluation`, `observability`, `brain_engine`)
- `feat(data_ingestion): ...` — Synthetic trajectory factory and `DatasetHygienePipeline` changes
- `sec(governance): ...` — Security, firewall, Safetensors, or license auditing changes
- `fix(<module>): ...` — Bug fixes with accompanying regression test under `tests/` (`test_*.py` / `tests/e2e/`)
- `docs(<scope>): ...` — Documentation and governance updates

---

## 7. Related Documentation

- [Documentation Hub](docs/README.md)
- [Documentation Standards Policy](docs/DOCUMENTATION_STANDARDS.md)
- [AI Agent Documentation Policy](docs/AI_DOCUMENTATION_POLICY.md)
- [Development Workflow Guide](docs/development/development-workflow.md)
