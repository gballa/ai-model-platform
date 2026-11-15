# Architecture Decision Records (ADRs)

This directory records the foundational architectural decisions implemented in `platform-core`. All ADRs are grounded in the repository source code (`src/platform_core/`) and the validated architecture blueprint.

---

## ADR Index

| ID | Title | Status | Primary Source Modules |
| :--- | :--- | :--- | :--- |
| [ADR-0001](ADR-0001-three-layer-hybrid-architecture-and-post-training.md) | Three-Layer Hybrid Intelligence Architecture & 5-Stage Open-Weight Post-Training (`Scenario-B`) | Accepted | `layer1_intelligence/models.py`, `layer1_intelligence/training.py` |
| [ADR-0002](ADR-0002-executor-verifier-separation-and-cow-rollback.md) | 6-Agent Consolidation, `SecVerifier` Executor/Verifier Separation & `<15ms` CoW Snapshot Rollback | Accepted | `layer2_execution/agents.py`, `layer2_execution/sandbox.py`, `layer2_execution/orchestrator.py` |
| [ADR-0003](ADR-0003-taint-isolation-safetensors-and-sovereign-licensing.md) | `TAINTED_UNTRUSTED` Information-Flow Lockdown, Safetensors-Only Checkpoints & Sovereign License Matrix | Accepted | `deploy_security/governance.py`, `layer2_execution/state.py` |
| [ADR-0004](ADR-0004-bitemporal-memory-and-200k-hybrid-knowledge-store.md) | Bitemporal Graphiti/GAM Episodic Memory, 200K-Token Prefix-Cache Threshold & 3-Tier SQLite Code Graph | Accepted | `layer3_evolution/memory.py`, `layer2_execution/mcp_tools.py` |
| [ADR-0005](ADR-0005-local-first-open-weight-forensics-and-vuln-intel.md) | Local-First Open-Weight Lineup, Offline Vulnerability Intelligence Mirror, & Anti-Fabrication Spyware Forensics | Accepted | `layer1_intelligence/inference.py`, `layer2_execution/vuln_intel_mcp.py`, `layer2_execution/forensics_mcp.py` |
| [ADR-0006](ADR-0006-local-ai-creator-and-antigravity-sdk.md) | Zero-Dependency Local AI Model Creator, Corpus Harvester, Compact Scratch SLM, & Google Antigravity SDK Bridge | Accepted | `layer3_evolution/corpus_harvester.py`, `layer1_intelligence/scratch_trainer.py`, `layer2_execution/agy_sdk_bridge.py`, `deploy_security/governance.py` |

---

## ADR Template & Maintenance Rules

Per [docs/DOCUMENTATION_STANDARDS.md](../../DOCUMENTATION_STANDARDS.md), every ADR must contain:
1. **Title and Identifier** (`ADR-XXXX`)
2. **Status** (`Proposed`, `Accepted`, `Superseded by ADR-YYYY`, `Deprecated`)
3. **Context**
4. **Decision**
5. **Consequences**
6. **Alternatives Considered**
7. **Source Code Traceability**

Never fabricate historical decisions. When an architectural decision is revised, preserve the original ADR and mark its status as `Superseded by ADR-YYYY`.
