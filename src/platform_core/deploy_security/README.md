# `platform_core.deploy_security` — Deployment, Sandboxing & Supply-Chain Security

---

## 1. Module Responsibilities and Boundaries

`platform_core.deploy_security` (`governance.py`) is the zero-internal-dependency security foundation of `platform-core`. It enforces:
1. **Safetensors-Only Checkpoint Validation (`SafetensorsValidator`)**: Blocks unsafe Python pickle checkpoints and verifies contiguous tensor byte spans and SHA-256 digests.
2. **Sovereign License Compliance (`LicenseComplianceAuditor`)**: Enforces the commercial/EU license allowlist (`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `PostgreSQL`, `CC0-1.0`).
3. **Cryptographic MCP Tool Manifest Signing (`SignedManifestVerifier`)**: Signs and verifies `MCPToolManifest` contracts with HMAC-SHA256 and strips `network_egress`/`admin_deploy` on tainted sessions.
4. **Taint-Aware Network Egress Firewall (`CyberGymFirewall`)**: Blocks all outbound traffic on `TAINTED_UNTRUSTED` sessions, blocks IP literals and metadata endpoints on clean sessions, and renders Squid proxy configurations.
5. **Kubernetes `agent-sandbox` Manifest Generation (`K8sAgentSandboxGenerator`)**: Emits `SandboxTemplate` and `SandboxClaim` CRDs for Firecracker microVM isolation.

---

## 2. Internal Architecture

All classes reside in [`governance.py`](governance.py) and depend exclusively on the Python 3.11+ standard library (`dataclasses`, `enum`, `hashlib`, `hmac`, `ipaddress`, `json`, `math`, `pathlib`, `struct`, `typing`, `urllib.parse`).

---

## 3. Main Components

| Class / Exception | Key Methods / Attributes | Purpose |
| :--- | :--- | :--- |
| `PickleSupplyChainError` | Subclass of `PermissionError` | Raised on `.pkl`/`.pt`/`.bin` extensions or `\x80\x02`–`\x80\x05` pickle magic bytes. |
| `SafetensorsValidationError` | Subclass of `ValueError` | Raised on malformed headers, out-of-bounds/overlapping tensor offsets, or SHA-256 mismatch. |
| `LicenseComplianceAuditor` | `audit(artifact_name, license_id) -> LicenseAuditResult` | Classifies licenses into `APPROVED_COMMERCIAL`, `REQUIRES_LEGAL_REVIEW`, or `REJECTED_PROHIBITED`. |
| `SafetensorsValidator` | `create_valid_safetensors_bytes()`, `validate_file()`, `validate_bytes()` | Creates and validates spec-compliant `.safetensors` buffers and files. |
| `SignedManifestVerifier` | `sign(manifest)`, `verify(manifest, granted_scopes, session_tainted)` | HMAC-SHA256 signing and scope/taint verification for MCP tools. |
| `CyberGymFirewall` | `evaluate_egress(url_or_host, session_tainted)`, `generate_squid_conf()` | Network egress policy evaluation and Squid ACL rendering. |
| `K8sAgentSandboxGenerator` | `build_sandbox_template()`, `build_sandbox_claim()` | Kubernetes `agentsandbox.x-k8s.io/v1alpha1` CRD generation. |

---

## 4. Dependencies and Integrations

- Imported by `layer1_intelligence` (`models.py`, `training.py`), `layer2_execution` (`sandbox.py`, `orchestrator.py`), and `layer3_evolution` (`data_factory.py`).

---

## 5. Execution and Data Flow

- **Checkpoint Verification**: `validate_file(path)` -> checks `not path.is_symlink()` -> checks `path.suffix == ".safetensors"` -> reads bytes -> `validate_bytes()` -> checks pickle magic -> checks SHA-256 -> parses 8-byte header length and JSON header -> verifies `(end - start) == math.prod(shape) * dtype_byte_size` and contiguous `[0, data_buffer_len]` coverage.
- **Egress Evaluation**: `evaluate_egress(dest, session_tainted)` -> denies immediately if `session_tainted=True` -> parses scheme (`http`/`https`) and hostname -> blocks IP literals (`ipaddress.ip_address`) and `localhost`/`metadata.google.internal` -> allows only if `host in allowed_domains`.

---

## 6. Configuration Requirements

- `SignedManifestVerifier(signing_key)` requires a key of at least `16` UTF-8 bytes.
- `MCPToolManifest.timeout_sec` must be in `[1, 3600]`, and `required_scopes` must be a subset of `SignedManifestVerifier.VALID_SCOPES`.

---

## 7. Usage Examples

```python
from platform_core.deploy_security import CyberGymFirewall, LicenseComplianceAuditor, SafetensorsValidator

auditor = LicenseComplianceAuditor()
print(auditor.audit("Qwen3.8-27B", "Apache-2.0").verdict.value)  # APPROVED_COMMERCIAL

validator = SafetensorsValidator()
buf = validator.create_valid_safetensors_bytes(
    tensors_meta={"w": {"dtype": "FP16" if False else "F16", "shape": [2, 2], "data_offsets": [0, 8]}},
    data_payload=b"\x00" * 8,
)
print("Verified tensors:", validator.validate_bytes(buf)["tensor_count"])  # 1

fw = CyberGymFirewall()
print("Tainted egress allowed:", fw.evaluate_egress("https://pypi.internal.platform.local", session_tainted=True).allowed)  # False
```

---

## 8. Testing and Troubleshooting

```bash
PYTHONPATH=src .venv/bin/python -W error -m unittest tests.test_platform_core.TestDeployAndSupplyChainSecurity -v
```

---

## 9. Related Documentation

- [Central Deploy & Security Module Reference](../../../docs/modules/deploy-security.md)
- [Security Architecture & Threat Model](../../../docs/security/README.md)
- [ADR-0003: Taint Isolation, Safetensors & Sovereign Licensing](../../../docs/architecture/decisions/ADR-0003-taint-isolation-safetensors-and-sovereign-licensing.md)
