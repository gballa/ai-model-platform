# ADR-0007: Multi-Region SQLite Checkpointer Synchronization

- **Identifier:** ADR-0007
- **Status:** Proposed
- **Date:** 2026-11-18
- **Source Modules:** [`state.py`](../../../../src/platform_core/layer2_execution/state.py)

---

## 1. Context

The current `SQLiteStateCheckpointer` in `layer2_execution` provides local, thread-safe WAL-based persistence. However, multi-region high availability (HA) requires robust state synchronization across geographically distributed nodes. Without multi-region consistency, state-dependent agent executions face potential divergence during cross-region failover.

## 2. Decision

1. **Distributed Consensus-Based State Replication**: Replace local WAL-based state with a distributed, Paxos or Raft-based consensus mechanism that synchronizes `SQLiteStateCheckpointer` updates across multi-region clusters.
2. **Asynchronous Journaling**: Implement asynchronous journaling for non-critical state updates to maintain performance while ensuring durability via a global state store.
3. **Bitemporal State Ledger**: Extend the bitemporal memory model (as per `ADR-0004`) to include region-awareness in the ledger entries, ensuring conflict resolution based on transaction ordering.

## 3. Consequences

- **Positive**: Enables HA failover between regions with minimal state divergence; ensures durability of checkpointed state.
- **Trade-offs**: Introduces network latency for synchronous state updates; increased complexity in the SQLite checkpointer and ledger management.

## 4. Alternatives Considered

1. **Active-Active Replication**: Rejected due to high conflict rate during concurrent state updates by multiple agents.
2. **Cloud-Native Database Services**: Rejected to maintain `platform-core`'s local-first, portable architecture requirements.
