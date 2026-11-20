# Documentation Standards & Governance Policy

**Status:** Mandatory Engineering Standard  
**Scope:** Entire `platform-core` repository (`src/`, `docs/`, `examples/`, `tests/`)  
**Audience:** Core engineers, contributors, reviewers, and AI coding agents

---

## Table of Contents

1. [Purpose & Core Principle](#1-purpose--core-principle)
2. [Documentation Architecture & Hierarchy](#2-documentation-architecture--hierarchy)
3. [README Responsibilities & Avoided Duplication](#3-readme-responsibilities--avoided-duplication)
4. [Markdown Formatting & File Naming Conventions](#4-markdown-formatting--file-naming-conventions)
5. [Technical Writing Standards](#5-technical-writing-standards)
6. [Architecture Diagram Standards](#6-architecture-diagram-standards)
7. [Code Example & Command Verification Requirements](#7-code-example--command-verification-requirements)
8. [Cross-Linking & Source-Code Traceability Rules](#8-cross-linking--source-code-traceability-rules)
9. [Documentation Update Requirements & Impact Gate](#9-documentation-update-requirements--impact-gate)
10. [Review, Validation & Quality Assurance Procedures](#10-review-validation--quality-assurance-procedures)
11. [AI Agent Documentation Responsibilities](#11-ai-agent-documentation-responsibilities)
12. [Related Documentation](#12-related-documentation)

---

## 1. Purpose & Core Principle

Documentation in `platform-core` is a first-class engineering deliverable. It must explain **what** the platform does, **how** its deterministic and neural subsystems interact, **why** specific architectural constraints exist, and **how** engineers can operate, extend, debug, and verify it without reverse-engineering source files.

> [!IMPORTANT]
> Source code (`src/platform_core/`) and verified configuration (`pyproject.toml`, `AGENTS.md`) are the sole primary sources of truth. Never document speculative, unimplemented, or fabricated behavior as active functionality.

---

## 2. Documentation Architecture & Hierarchy

The repository enforces a structured, non-duplicative hierarchy:

```text
/
├── README.md                              # Root project entry point & quickstart
├── AGENTS.md                              # Workspace invariants, CLI commands & AI policy pointer
├── CONTRIBUTING.md                        # Contribution workflow & Documentation Impact Checklist
├── CHANGELOG.md                           # Chronological release and architecture history
├── docs/
│   ├── README.md                          # Documentation hub & reader navigation guide
│   ├── DOCUMENTATION_STANDARDS.md         # Authoritative documentation policy (this file)
│   ├── AI_DOCUMENTATION_POLICY.md         # Enforceable contract for AI coding agents
│   ├── DOCUMENTATION_INDEX.md             # Living inventory of all subsystem docs
│   ├── DOCUMENTATION_COVERAGE.md          # Traceability & coverage matrix across source code
│   ├── CUSTOM_MODEL_GUIDE.md              # End-to-end custom model lifecycle playbook
│   ├── HOW_TO_GUIDES.md                   # Real-life domain playbooks & recipes
│   ├── overview/
│   │   └── project-overview.md            # Executive & technical capabilities overview
│   ├── architecture/
│   │   ├── README.md                      # Architecture index
│   │   ├── system-architecture.md         # Three-Layer topology, 4 pools, 6 agents
│   │   ├── component-architecture.md      # Class & package boundaries
│   │   ├── data-flow.md                   # Lifecycle sequences, SQLite schemas, CoW state
│   │   ├── integrations.md                # MCP, Firecracker, SGLang/vLLM, FSDP2/ZeRO-3, K8s
│   │   └── decisions/                     # Architecture Decision Records (ADR-0001..0006; proposed 0007..0009)
│   ├── modules/                           # Central module reference guides
│   ├── workflows/                         # 10-step execution, 5-stage training, 8-step evolution
│   ├── development/                       # Setup, config, workflow, extension, troubleshooting
│   ├── api/                               # Python API, CLI flags, JSON/JSONL schemas, MCP contracts
│   ├── testing/                           # Unit/integration tests, PropBench-9, QA validation
│   ├── deployment/                        # Safetensors packaging, SGLang/vLLM, K8s sandboxes
│   ├── security/                          # Taint isolation, seccomp, firewall, license & supply chain
│   ├── operations/                        # Telemetry, SQLite time-travel replay, canary runbooks
│   └── guides/                            # Operational playbooks (database, extensions, monitoring)
├── src/platform_core/
│   ├── README.md                          # Package overview & subpackage map
│   ├── layer1_intelligence/README.md      # Layer 1 module boundary & API guide
│   ├── layer2_execution/README.md         # Layer 2 module boundary & API guide
│   ├── layer3_evolution/README.md         # Layer 3 module boundary & API guide
│   └── deploy_security/README.md          # Deploy & Security module boundary & API guide
├── examples/README.md                     # Sample datasets, payloads, and scripts guide
└── tests/README.md                        # Test suite organization & execution guide
```

---

## 3. README Responsibilities & Avoided Duplication

To prevent documentation drift, each README tier has a strict responsibility boundary:

| Tier | Location | Primary Responsibility | What to Link Instead of Duplicating |
| :--- | :--- | :--- | :--- |
| **Root README** | `/README.md` | High-level project overview, capabilities, quickstart commands, architecture summary, and top-level navigation. | Link to `docs/architecture/`, `docs/api/`, and `docs/development/` for deep technical internals. |
| **Central Docs Hub** | `/docs/README.md` | Role-based navigation and entrypoint routing across `docs/` subdirectories. | Link to `/docs/DOCUMENTATION_INDEX.md` for the full registry. |
| **Module READMEs** | `src/platform_core/**/README.md`, `examples/README.md`, `tests/README.md` | Module responsibilities, internal classes, input/output contracts, dependencies, local usage snippets, and module-specific troubleshooting. | Link to `docs/architecture/data-flow.md` and `docs/workflows/` for cross-layer orchestration details. |

---

## 4. Markdown Formatting & File Naming Conventions

1. **File Naming**:
   - Governance, top-level standards, and root files use `UPPER_SNAKE_CASE.md` (`README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `DOCUMENTATION_STANDARDS.md`, `AI_DOCUMENTATION_POLICY.md`, `DOCUMENTATION_INDEX.md`, `DOCUMENTATION_COVERAGE.md`, `CUSTOM_MODEL_GUIDE.md`, `HOW_TO_GUIDES.md`).
   - Topic guides and architecture files inside `docs/<category>/` use `kebab-case.md` (`system-architecture.md`, `getting-started.md`).
   - Architecture Decision Records use `ADR-XXXX-short-slug.md`.
2. **Heading Hierarchy**:
   - Exactly one `# H1` title per document.
   - Include a `## Table of Contents` in any document exceeding 80 lines.
   - Do not skip heading levels (e.g., never jump from `##` to `####`).
3. **Callouts**:
   - Use GitHub-flavored Markdown alerts (`> [!NOTE]`, `> [!TIP]`, `> [!IMPORTANT]`, `> [!WARNING]`, `> [!CAUTION]`) sparingly for critical invariants or security boundaries. Never place two alerts consecutively.
4. **Tone & Style**:
   - Use precise, objective engineering prose.
   - Do not use decorative emojis or marketing hyperbole.

---

## 5. Technical Writing Standards

Every How-To guide and operational playbook must include the following eight sections in order:

1. **Purpose** — What engineering goal the guide accomplishes.
2. **Prerequisites** — Required Python version, virtual environment state, and files.
3. **Required Configuration** — Relevant dataclasses, CLI arguments, or environment settings.
4. **Step-by-Step Instructions** — Numbered, deterministic actions.
5. **Verified Commands and Examples** — Copy-pasteable shell commands or Python snippets verified against the codebase.
6. **Expected Results** — Exact JSON keys, return types, state transitions, or exit codes produced.
7. **Common Errors and Troubleshooting** — Concrete exception types (`PickleSupplyChainError`, `PermissionError`, `ValueError`, `MemoryError`) and remediation steps.
8. **Related Documentation** — Relative links to connected architecture, module, and API documents.

---

## 6. Architecture Diagram Standards

1. **Supported Mermaid Diagram Types Only**:
   - Flowcharts: `flowchart TB` / `flowchart LR`
   - Sequence diagrams: `sequenceDiagram`
   - State diagrams: `stateDiagram-v2`
   - Class diagrams: `classDiagram`
   - Entity-Relationship diagrams: `erDiagram`
2. **Label Quoting**:
   - Always wrap node labels containing parentheses, brackets, colons, or math symbols in double quotes: `NodeId["Label (Step 1: TAINTED_UNTRUSTED)"]`.
   - Do not use raw HTML tags inside Mermaid node labels.
3. **Contextual Framing**:
   - Every diagram must be preceded by a title/heading and followed by an explanation mapping diagram nodes to concrete classes and files in `src/platform_core/`.

---

## 7. Code Example & Command Verification Requirements

1. Every shell command must be runnable from the repository root using `PYTHONPATH=src .venv/bin/python`.
2. Every Python snippet must import only existing symbols from `platform_core` and clean up stateful resources (`orchestrator.close()`, `checkpointer.close()`, `graph.close()`).
3. Never invent CLI flags, environment variables, or third-party dependencies.

---

## 8. Cross-Linking & Source-Code Traceability Rules

1. Use relative Markdown links (`[models.py](../src/platform_core/layer1_intelligence/models.py)`) within repository documentation so links work across local checkouts and Git viewers.
2. Whenever a document describes an invariant, class, or workflow, cite the exact source module (`src/platform_core/...`) and test class in `tests/test_platform_core.py` that verifies it.
3. Register every new or moved document in [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) and update [DOCUMENTATION_COVERAGE.md](DOCUMENTATION_COVERAGE.md).

---

## 9. Documentation Update Requirements & Impact Gate

No code change is complete until its documentation impact has been evaluated against the mandatory **Documentation Impact Gate** defined in [AI_DOCUMENTATION_POLICY.md](AI_DOCUMENTATION_POLICY.md#3-mandatory-documentation-impact-gate) and [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## 10. Review, Validation & Quality Assurance Procedures

Before completing any documentation or code change, run the verification suite from the repository root:

```bash
# 1. Verify all unit, integration, and security tests pass under strict warning gate
PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v

# 2. Verify end-to-end custom model example script executes cleanly
PYTHONPATH=src .venv/bin/python -W error examples/custom_model_end_to_end.py

# 3. Verify all relative Markdown file links resolve to existing files on disk
PYTHONPATH=src .venv/bin/python -c '
import pathlib, re, sys
root = pathlib.Path(".")
link_re = re.compile(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]*)?\)")
broken = []
for md in sorted(root.rglob("*.md")):
    if ".venv" in md.parts or ".agents" in md.parts:
        continue
    text = md.read_text(encoding="utf-8")
    for m in link_re.finditer(text):
        target = m.group(1).strip()
        if target.startswith(("http://", "https://", "mailto:", "file://")):
            continue
        resolved = (md.parent / target).resolve()
        if not resolved.exists():
            broken.append((str(md), target))
if broken:
    for src, tgt in broken:
        print(f"BROKEN LINK: {src} -> {tgt}")
    sys.exit(1)
print("All relative Markdown links verified successfully.")
'
```

---

## 11. AI Agent Documentation Responsibilities

All autonomous and interactive AI coding agents operating in this repository must comply with [AI_DOCUMENTATION_POLICY.md](AI_DOCUMENTATION_POLICY.md), referenced from [AGENTS.md](../AGENTS.md).

---

## 12. Related Documentation

- [AI Agent Documentation Policy](AI_DOCUMENTATION_POLICY.md)
- [Living Documentation Index](DOCUMENTATION_INDEX.md)
- [Documentation Coverage & Traceability Matrix](DOCUMENTATION_COVERAGE.md)
- [Contributing & Development Governance](../CONTRIBUTING.md)
- [Workspace Invariants (`AGENTS.md`)](../AGENTS.md)
