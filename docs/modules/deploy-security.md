# Module Reference: Deploy & Supply-Chain Security (`platform_core.deploy_security`)

**Source Directory:** [`src/platform_core/deploy_security/`](../../src/platform_core/deploy_security/)  
**Local Module README:** [`src/platform_core/deploy_security/README.md`](../../src/platform_core/deploy_security/README.md)

---

## Table of Contents

1. [Module Responsibilities & Boundaries](#1-module-responsibilities--boundaries)
2. [`LicenseComplianceAuditor` — Sovereign IP & EU Compliance Gate](#2-licensecomplianceauditor--sovereign-ip--eu-compliance-gate)
3. [`SafetensorsValidator` — Binary Checkpoint & Anti-Pickle Gate](#3-safetensorsvalidator--binary-checkpoint--anti-pickle-gate)
4. [`SignedManifestVerifier` — HMAC-SHA256 Scoped MCP Tool Gate](#4-signedmanifestverifier--hmac-sha256-scoped-mcp-tool-gate)
5. [`CyberGymFirewall` — Taint Egress Lockdown & Squid Config Generator](#5-cybergymfirewall--taint-egress-lockdown--squid-config-generator)
6. [`K8sAgentSandboxGenerator` — Kubernetes `agent-sandbox` CRDs](#6-k8sagentsandboxgenerator--kubernetes-agent-sandbox-crds)
7. [Testing & Verification](#7-testing--verification)
8. [Related Documentation](#8-related-documentation)

---

## 1. Module Responsibilities & Boundaries

`platform_core.deploy_security` (`governance.py`) provides the foundational security primitives used across Layers 1, 2, and 3. It has zero internal dependencies on other `platform_core` subpackages.

---

## 2. `LicenseComplianceAuditor` — Sovereign IP & EU Compliance Gate

`LicenseComplianceAuditor.audit(artifact_name: str, license_id: str) -> LicenseAuditResult` classifies licenses into three `LicenseVerdict` categories:

| Verdict | Licenses | `eu_compliant` | `allows_commercial_distillation` |
| :--- | :--- | :--- | :--- |
| `APPROVED_COMMERCIAL` | `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `PostgreSQL`, `CC0-1.0` | `True` | `True` |
| `REQUIRES_LEGAL_REVIEW` | `Modified-MIT`, `Mistral-Ecosystem`, `Elastic-2.0` | `True` | `False` |
| `REJECTED_PROHIBITED` | `Llama-4-Community` (`eu_compliant=False`), `GPL-2.0`, `GPL-3.0`, `AGPL-3.0`, `Proprietary-Closed-API`, `Research-Only`, empty string, or any unrecognized license | `False` (except known non-EU-banned copyleft/research) | `False` |

---

## 3. `SafetensorsValidator` — Binary Checkpoint & Anti-Pickle Gate

- **Exceptions**: `PickleSupplyChainError(PermissionError)`, `SafetensorsValidationError(ValueError)`.
- **Forbidden Extensions**: `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.joblib`.
- **Supported Dtypes (`DTYPE_BYTE_SIZES`)**: `BOOL` (1B), `U8` (1B), `I8` (1B), `F8_E4M3` (1B), `F8_E5M2` (1B), `I16` (2B), `U16` (2B), `F16` (2B), `BF16` (2B), `I32` (4B), `U32` (4B), `F32` (4B), `F64` (8B), `I64` (8B), `U64` (8B).
- **Validation Rules (`validate_file` & `validate_bytes`)**:
  1. Rejects symlinked files (`path.is_symlink() -> PermissionError`).
  2. Rejects forbidden extensions and disguised pickle magic bytes (`\x80\x02`–`\x80\x05`) with `PickleSupplyChainError`, while checking whether a `\x80\x02`–`\x80\x05` prefix is a legitimate little-endian `<Q` Safetensors JSON header (`0 < candidate_len <= MAX_HEADER_BYTES`, `8 + candidate_len <= len(raw_bytes)`, and `raw_bytes[8:9] == b"{"`) so valid `640`, `896`, `1152`, or `1408`-byte headers do not trigger false positives. (As an extra safeguard for external header scanners, `_PureStdlibTransformer.export_safetensors_bytes()` in `scratch_trainer.py` also pads `metadata["header_pad"]` to avoid those 2-byte prefixes.)
  3. Verifies optional `expected_sha256`.
  4. Unpacks 8-byte little-endian header size (`0 < header_size <= 100 MiB`).
  5. Validates `__metadata__` (must be `dict[str, str]`) and tensor entries (`dtype`, `shape` of non-bool non-negative `int`s, `data_offsets` `[start, end]`).
  6. Verifies exact tensor byte span (`(end - start) == math.prod(shape) * DTYPE_BYTE_SIZES[dtype]`) and contiguous, non-overlapping coverage from byte `0` to `data_buffer_len`.

---

## 4. `SignedManifestVerifier` — HMAC-SHA256 Scoped MCP Tool Gate

- Requires `len(signing_key) >= 16` bytes.
- `sign(manifest: MCPToolManifest) -> MCPToolManifest`: Validates `timeout_sec in [1, 3600]` and `required_scopes <= VALID_SCOPES`, then computes HMAC-SHA256 over `manifest.canonical_payload()`.
- `verify(manifest, granted_scopes, session_tainted=False) -> bool`: Verifies HMAC signature via `hmac.compare_digest`, blocks `network_egress` and `admin_deploy` when `session_tainted=True`, and checks `set(manifest.required_scopes).issubset(granted_scopes)`.

---

## 5. `CyberGymFirewall` — Taint Egress Lockdown & Squid Config Generator

- `evaluate_egress(url_or_host, session_tainted) -> FirewallDecision`:
  - Blocks 100% of egress when `session_tainted=True`.
  - Blocks non-`http`/`https` schemes, IP literals (`127.0.0.1`, `169.254.169.254`, etc.), `localhost`, `*.localhost`, and `metadata.google.internal`.
  - Allows only hosts in `allowed_domains` (`DEFAULT_ALLOWLIST`).
- `generate_squid_conf() -> str`: Renders the Squid proxy ACL configuration.

---

## 6. `K8sAgentSandboxGenerator` — Kubernetes `agent-sandbox` CRDs

- `build_sandbox_template(...)`: Emits `agentsandbox.x-k8s.io/v1alpha1` `SandboxTemplate` (`kata-fc`, `seccompSyscallLimit: 24`, `cowSnapshotRestoreTargetMs: 8.5`).
- `build_sandbox_claim(...)`: Emits `SandboxClaim` annotated with session ID and taint state.

---

## 7. Testing & Verification

Covered by `TestDeployAndSupplyChainSecurity` in [`tests/test_platform_core.py`](../../tests/test_platform_core.py).

---

## 8. Related Documentation

- [Security Architecture & Governance](../security/README.md)
- [Deployment & Cluster Configuration Guide](../deployment/README.md)
- [Deploy & Security Local README](../../src/platform_core/deploy_security/README.md)
