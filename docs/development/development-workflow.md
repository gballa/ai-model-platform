# Development Workflow & Extending the Platform

---

## 1. Purpose

Provide a step-by-step engineering playbook for adding new modules, MCP tools, CPG taint rules, custom models, or benchmark specs to `platform-core` while maintaining strict type safety, zero warnings, and full documentation synchronization.

---

## 2. Prerequisites

- Working `.venv` environment (`PYTHONPATH=src .venv/bin/python`).
- Familiarity with [AGENTS.md](../../AGENTS.md), [docs/DOCUMENTATION_STANDARDS.md](../DOCUMENTATION_STANDARDS.md), and [docs/AI_DOCUMENTATION_POLICY.md](../AI_DOCUMENTATION_POLICY.md).

---

## 3. Required Configuration

All tests must be executed with Python's `-W error` flag (`PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v`), which promotes any `DeprecationWarning` or `ResourceWarning` (such as an unclosed SQLite connection) into a test failure.

---

## 4. Step-by-Step Instructions

### 4.1 Pre-Implementation Discovery (Stage 1 & 2 of Lifecycle)
1. Inspect [docs/DOCUMENTATION_INDEX.md](../DOCUMENTATION_INDEX.md) and [docs/DOCUMENTATION_COVERAGE.md](../DOCUMENTATION_COVERAGE.md).
2. Identify which module (`layer1_intelligence`, `layer2_execution`, `layer3_evolution`, or `deploy_security`) owns the capability and which documentation files will be affected.

### 4.2 Adding a New Scoped MCP Tool (Example Workflow)
1. **Implement the deterministic method** on the appropriate MCP server in [`src/platform_core/layer2_execution/mcp_tools.py`](../../src/platform_core/layer2_execution/mcp_tools.py).
2. **Register and sign its `MCPToolManifest`** inside `ExecutionLifecycleOrchestrator._build_signed_manifests()` in [`src/platform_core/layer2_execution/orchestrator.py`](../../src/platform_core/layer2_execution/orchestrator.py) with required scopes from `SignedManifestVerifier.VALID_SCOPES`.
3. **Bind the tool** to the appropriate subtask in `PrincipalOrchestratorAgent.decompose_objective()` ([`agents.py`](../../src/platform_core/layer2_execution/agents.py)) and ensure the assigned agent's `allowed_mcp_scopes` includes the tool's `required_scopes`.
4. **Add unit and adversarial tests** in [`tests/test_platform_core.py`](../../tests/test_platform_core.py).
5. **Update documentation**: Update `docs/architecture/integrations.md`, `docs/modules/layer2-execution.md`, `src/platform_core/layer2_execution/README.md`, and `docs/DOCUMENTATION_COVERAGE.md`.

### 4.3 Registering a New Model or CPG Vulnerability Rule
- **New Model**: Instantiate `ModelSpec(...)` with an `APPROVED_COMMERCIAL` license (`Apache-2.0`, `MIT`, `BSD-3-Clause`) and call `registry.register_model(spec, set_as_pool_default=True)`.
- **New CPG Rule**: Append a `(cwe_id, severity, compiled_regex, description, remediation_hint)` tuple to `DefensiveCyberMCPServer.SINK_RULES` in [`mcp_tools.py`](../../src/platform_core/layer2_execution/mcp_tools.py).

---

## 5. Verified Commands and Examples

### Registering and Signing a Custom Scoped MCP Tool Manifest

```python
from platform_core.deploy_security import MCPToolManifest, SignedManifestVerifier

verifier = SignedManifestVerifier(signing_key="sovereign-platform-mcp-hmac-key-2026")
manifest = MCPToolManifest(
    tool_name="code_graph.analyze_blast_radius",
    server_id="code-graph-mcp",
    version="1.0.0",
    description="Compute SCIP structural + Git co-change blast radius.",
    parameters_schema={"type": "object", "required": ["target_file"]},
    required_scopes=("read_code",),
    timeout_sec=30,
)
signed = verifier.sign(manifest)
is_valid = verifier.verify(
    signed,
    granted_scopes=frozenset({"read_code", "write_code"}),
    session_tainted=True,
)
print("Manifest Verified:", is_valid, "| HMAC:", signed.signature[:16])
```

### Mandatory Pre-Commit Quality & Hygiene Verification Commands

```bash
# 1. Run full test suite under strict warning gate
PYTHONPATH=src .venv/bin/python -W error -m unittest discover -s tests -v

# 2. Check for any TODO/FIXME comments or unused imports
PYTHONPATH=src .venv/bin/python -c '
import ast, pathlib, sys
for p in sorted(pathlib.Path(".").rglob("*.py")):
    if ".venv" in p.parts:
        continue
    src = p.read_text(encoding="utf-8")
    if "TODO" in src or "FIXME" in src:
        print(f"Found TODO/FIXME in {p}")
        sys.exit(1)
    ast.parse(src)
print("Zero TODOs and valid AST across all Python files.")
'
```

---

## 6. Expected Results

- The manifest snippet prints `Manifest Verified: True | HMAC: <16-char hex>`.
- The test suite runs 20/20 tests with `OK` and zero warnings.
- The hygiene scan outputs `Zero TODOs and valid AST across all Python files.`

---

## 7. Common Errors and Troubleshooting

| Error | Cause | Resolution |
| :--- | :--- | :--- |
| `PermissionError: Scoped MCP verification failed for tool ...` | Tool's `required_scopes` are not in the assigned agent's `allowed_mcp_scopes`, or tool requires `network_egress`/`admin_deploy` on a `TAINTED_UNTRUSTED` session. | Grant only minimum necessary scopes from `VALID_SCOPES` and avoid `network_egress`/`admin_deploy` on tainted tasks. |
| `ValueError: Unknown MCP permission scopes` | Using a custom scope name not in `SignedManifestVerifier.VALID_SCOPES`. | Use an existing scope in `VALID_SCOPES` or update `VALID_SCOPES` and its tests/docs. |

---

## 8. Related Documentation

- [Contributing Guidelines](../../CONTRIBUTING.md)
- [AI Agent Documentation Policy](../AI_DOCUMENTATION_POLICY.md)
- [Documentation Standards Policy](../DOCUMENTATION_STANDARDS.md)
- [Testing & Quality Assurance Guide](../testing/README.md)
