# Module Documentation Index

This directory provides centralized reference documentation for every subpackage and module in `src/platform_core/`. Each subpackage also includes a local `README.md` colocated with its source files.

---

## Module Catalog

| Module / Subpackage | Central Documentation | Local Source README | Primary Source Files |
| :--- | :--- | :--- | :--- |
| **`platform_core` (Root & CLI)** | [CLI & Entrypoints (`cli.md`)](cli.md) | [`src/platform_core/README.md`](../../src/platform_core/README.md) | [`__init__.py`](../../src/platform_core/__init__.py), [`cli.py`](../../src/platform_core/cli.py) |
| **`layer1_intelligence`** | [Layer 1: Intelligence & Model Creation](layer1-intelligence.md) | [`src/platform_core/layer1_intelligence/README.md`](../../src/platform_core/layer1_intelligence/README.md) | [`models.py`](../../src/platform_core/layer1_intelligence/models.py), [`inference.py`](../../src/platform_core/layer1_intelligence/inference.py), [`router.py`](../../src/platform_core/layer1_intelligence/router.py), [`serving.py`](../../src/platform_core/layer1_intelligence/serving.py), [`training.py`](../../src/platform_core/layer1_intelligence/training.py), [`scratch_trainer.py`](../../src/platform_core/layer1_intelligence/scratch_trainer.py) |
| **`layer2_execution`** | [Layer 2: Stateful Execution & Sandboxing](layer2-execution.md) | [`src/platform_core/layer2_execution/README.md`](../../src/platform_core/layer2_execution/README.md) | [`state.py`](../../src/platform_core/layer2_execution/state.py), [`sandbox.py`](../../src/platform_core/layer2_execution/sandbox.py), [`mcp_tools.py`](../../src/platform_core/layer2_execution/mcp_tools.py), [`vuln_intel_mcp.py`](../../src/platform_core/layer2_execution/vuln_intel_mcp.py), [`forensics_mcp.py`](../../src/platform_core/layer2_execution/forensics_mcp.py), [`agents.py`](../../src/platform_core/layer2_execution/agents.py), [`orchestrator.py`](../../src/platform_core/layer2_execution/orchestrator.py), [`agy_sdk_bridge.py`](../../src/platform_core/layer2_execution/agy_sdk_bridge.py) |
| **`layer3_evolution`** | [Layer 3: Evolution, Memory & Evaluation](layer3-evolution.md) | [`src/platform_core/layer3_evolution/README.md`](../../src/platform_core/layer3_evolution/README.md) | [`memory.py`](../../src/platform_core/layer3_evolution/memory.py), [`data_factory.py`](../../src/platform_core/layer3_evolution/data_factory.py), [`corpus_harvester.py`](../../src/platform_core/layer3_evolution/corpus_harvester.py), [`evaluation.py`](../../src/platform_core/layer3_evolution/evaluation.py), [`observability.py`](../../src/platform_core/layer3_evolution/observability.py) |
| **`deploy_security`** | [Deploy & Supply-Chain Security](deploy-security.md) | [`src/platform_core/deploy_security/README.md`](../../src/platform_core/deploy_security/README.md) | [`governance.py`](../../src/platform_core/deploy_security/governance.py) |

---

## Related Documentation

- [Component Architecture](../architecture/component-architecture.md)
- [API & CLI Contract Reference](../api/README.md)
- [Documentation Coverage Matrix](../DOCUMENTATION_COVERAGE.md)
