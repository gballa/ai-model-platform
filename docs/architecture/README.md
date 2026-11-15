# Architecture Documentation Index

This directory contains the authoritative architectural documentation for `platform-core`, grounded directly in the implementation under [`src/platform_core/`](../../src/platform_core/).

---

## Navigation

| Document | Scope & Contents |
| :--- | :--- |
| [System Architecture](system-architecture.md) | System context, Three-Layer Hybrid Intelligence topology, 4-Pool Model Lineup, 6 Specialist Agent consolidation, and deployment topology. |
| [Component Architecture](component-architecture.md) | Package boundaries, class relationships across Layer 1, Layer 2, Layer 3, and Deploy/Security, and inter-module dependency rules. |
| [Data Flow & Lifecycles](data-flow.md) | 10-Step execution sequence diagram, SubTask state machine, SQLite checkpoint & SCIP code-graph ER schemas, CoW snapshot rollback flow, and 5-Stage post-training pipeline data flow. |
| [Integrations & Boundaries](integrations.md) | HMAC-signed MCP tool contracts, Firecracker microVM / `python3 -I` sandbox boundary, SGLang/vLLM launch contracts, FSDP2/ZeRO-3 training specs, Kubernetes `agent-sandbox` CRDs, and Squid `CyberGymFirewall`. |
| [Architecture Decision Records (`decisions/`)](decisions/README.md) | Historical and technical rationale for core architectural invariants (`ADR-0001` through `ADR-0006`). |

---

## Related Documentation

- [Project Overview](../overview/project-overview.md)
- [Module Reference (`docs/modules/`)](../modules/README.md)
- [Workflows (`docs/workflows/`)](../workflows/README.md)
- [Security Architecture (`docs/security/`)](../security/README.md)
