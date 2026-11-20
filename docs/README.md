# `platform-core` Documentation Hub

Welcome to the central engineering documentation for the **Proprietary Technical Intelligence Platform (`platform-core`)**.

---

## Table of Contents

1. [Quick Navigation by Engineering Role](#1-quick-navigation-by-engineering-role)
2. [Documentation Directory Map](#2-documentation-directory-map)
3. [Governance, Standards & Traceability Registries](#3-governance-standards--traceability-registries)
4. [Module-Level Source READMEs](#4-module-level-source-readmes)

---

## 1. Quick Navigation by Engineering Role

| If You Want To... | Start Here |
| :--- | :--- |
| **Understand what `platform-core` does and why its architecture exists** | [Project Overview](overview/project-overview.md) & [System Architecture](architecture/system-architecture.md) |
| **Set up the environment and run your first CLI workflow in 2 minutes** | [Getting Started Guide](development/getting-started.md) & [Root README](../README.md) |
| **Create, save (`.safetensors` + `.manifest.json`), load, and run a custom model** | [Custom Model Creation & Execution Guide](CUSTOM_MODEL_GUIDE.md) & [5-Stage Post-Training Workflow](workflows/model-post-training-pipeline.md) |
| **Follow real-life recipes across SWE, Cybersecurity, Binary Decompilation, and Protocol Forensics** | [Step-by-Step Real-Life How-To Guides](HOW_TO_GUIDES.md) & [Engineering Playbooks Catalog](guides/README.md) |
| **Extend the platform (add MCP tools, CPG rules, or custom models)** | [Development Workflow Guide](development/development-workflow.md) & [API & Schema Contracts](api/README.md) |
| **Deploy serving endpoints (`SGLang`/`vLLM`) or Kubernetes `agent-sandbox` CRDs** | [Build & Deployment Guide](deployment/README.md) & [Security Architecture](security/README.md) |
| **Diagnose errors, inspect SQLite checkpoints, or run time-travel state replay** | [Troubleshooting Playbook](development/troubleshooting.md) & [Operations & Diagnostics Runbook](operations/README.md) |

---

## 2. Documentation Directory Map

| Directory / File | Scope |
| :--- | :--- |
| [`overview/`](overview/project-overview.md) | Executive summary, strategic rationale, 8 supported domains, Scenario A/B/C economics, and local vs. cluster scope boundaries. |
| [`architecture/`](architecture/README.md) | [System Architecture](architecture/system-architecture.md), [Component Architecture](architecture/component-architecture.md), [Data Flow & Lifecycles](architecture/data-flow.md), [Integrations & Boundaries](architecture/integrations.md), and [Architecture Decision Records (`ADR-0001..0006`)](architecture/decisions/README.md). |
| [`modules/`](modules/README.md) | Deep-dive module references for [CLI (`cli.md`)](modules/cli.md), [Layer 1 Intelligence](modules/layer1-intelligence.md), [Layer 2 Execution](modules/layer2-execution.md), [Layer 3 Evolution & Data Ingestion](modules/layer3-evolution.md), and [Deploy & Security](modules/deploy-security.md). |
| [`workflows/`](workflows/README.md) | End-to-end execution and learning lifecycles: [10-Step Agent Execution Lifecycle](workflows/agent-execution-lifecycle.md), [5-Stage Model Post-Training Pipeline](workflows/model-post-training-pipeline.md), and [8-Step Controlled Improvement Cycle](workflows/controlled-improvement-cycle.md). |
| [`development/`](development/README.md) | [Getting Started](development/getting-started.md), [Environment Setup](development/environment-setup.md), [Configuration Reference](development/configuration.md), [Development Workflow](development/development-workflow.md), and [Troubleshooting](development/troubleshooting.md). |
| [`api/`](api/README.md) | Public Python API exports, CLI subcommand flags (23 subcommands), JSON/JSONL file contracts, and HMAC-signed MCP tool contracts. |
| [`testing/`](testing/README.md) | Unit, integration, security & 4-tier E2E test suite (`211` tests across `tests/`) and `PropBench-9` / `BenchmarkSuiteRunner` evaluation. |
| [`deployment/`](deployment/README.md) | `.safetensors` packaging, `SGLang`/`vLLM` launch commands, `PyTorch FSDP2`/`DeepSpeed ZeRO-3` specs, and Kubernetes `agent-sandbox` CRDs. |
| [`security/`](security/README.md) | Threat model, `TAINTED_UNTRUSTED` lockdown, 24-syscall seccomp, `CyberGymFirewall`, `SafetensorsValidator`, and `LicenseComplianceAuditor`. |
| [`operations/`](operations/README.md) | OpenTelemetry span inspection, SQLite WAL checkpoint auditing & time-travel replay, CoW SLA monitoring, and Canary Promotion Gate runbooks. |
| [`guides/`](guides/README.md) | Complete index of practical engineering playbooks, including SQLite database operations and AI agent/prompt pipeline development. |

---

## 3. Governance, Standards & Traceability Registries

- **[Documentation Standards Policy (`DOCUMENTATION_STANDARDS.md`)](DOCUMENTATION_STANDARDS.md)**: Authoritative formatting, diagramming, verification, and maintenance standards.
- **[AI Agent Documentation Policy (`AI_DOCUMENTATION_POLICY.md`)](AI_DOCUMENTATION_POLICY.md)**: Mandatory contract, impact gate, and task-reporting format for all AI coding agents.
- **[Living Documentation Index (`DOCUMENTATION_INDEX.md`)](DOCUMENTATION_INDEX.md)**: Complete registry of every subsystem and document in the repository.
- **[Documentation Coverage & Traceability Matrix (`DOCUMENTATION_COVERAGE.md`)](DOCUMENTATION_COVERAGE.md)**: Source-code traceability and verification status across all modules, workflows, and integrations.

---

## 4. Module-Level Source READMEs

- [`src/platform_core/README.md`](../src/platform_core/README.md)
- [`src/platform_core/layer1_intelligence/README.md`](../src/platform_core/layer1_intelligence/README.md)
- [`src/platform_core/layer2_execution/README.md`](../src/platform_core/layer2_execution/README.md)
- [`src/platform_core/layer3_evolution/README.md`](../src/platform_core/layer3_evolution/README.md)
- [`src/platform_core/data_ingestion/README.md`](../src/platform_core/data_ingestion/README.md)
- [`src/platform_core/deploy_security/README.md`](../src/platform_core/deploy_security/README.md)
- [`examples/README.md`](../examples/README.md)
- [`tests/README.md`](../tests/README.md)
