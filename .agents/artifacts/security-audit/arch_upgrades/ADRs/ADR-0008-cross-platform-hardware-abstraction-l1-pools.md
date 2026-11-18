# ADR-0008: Cross-Platform Hardware Abstraction for L1 Pools

- **Identifier:** ADR-0008
- **Status:** Proposed
- **Date:** 2026-11-18
- **Source Modules:** [`models.py`](../../../../src/platform_core/layer1_intelligence/models.py)

---

## 1. Context

Layer 1 intelligence pools (`POOL_1_ORCHESTRATOR`, `POOL_2_SWE_CYBER`, `POOL_3_BINREV`, `POOL_4_VISUAL_OCR`) currently have tight couplings to specific underlying hardware platforms (e.g., specific CUDA versions, Apple Silicon MLX backends). This hinders portability across diverse deployment environments and complicates scaling L1 capacity in heterogeneous clusters.

## 2. Decision

1. **Hardware-Agnostic Execution Interface**: Introduce an `ExecutionCapability` abstraction layer in `layer1_intelligence` that normalizes heterogeneous hardware features (e.g., VRAM availability, compute capacity, tensor operation support) into a unified interface.
2. **Dynamic Capability Discovery**: Implement a `DynamicCapabilityDiscoverer` that auto-detects host hardware features and selects the optimal `ServingBackend` (`SGLang`, `vLLM`, `mlx_lm`, `llama_cpp`) at runtime.
3. **Resource Mapping Matrix**: Standardize a resource mapping matrix to allow the `AdaptiveModelRouter` to route tasks based on hardware-agnostic capability requirements rather than platform-specific device IDs.

## 3. Consequences

- **Positive**: Increased deployment flexibility; reduced platform-specific code duplication in `models.py` and `serving.py`.
- **Trade-offs**: Introduces abstraction layer overhead; requires ongoing maintenance of the `ExecutionCapability` interface as hardware platforms evolve.

## 4. Alternatives Considered

1. **Hardware-Specific Pool Definitions**: Rejected because it increases maintenance burden and hinders cross-platform deployment.
2. **Cloud-Native Hardware Abstraction (e.g., K8s Device Plugins)**: Rejected to maintain `platform-core`'s local-first, portable architecture requirements and avoid reliance on platform-specific orchestrator plugins.
