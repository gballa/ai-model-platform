# ADR-0003: `TAINTED_UNTRUSTED` Information-Flow Lockdown, Safetensors-Only Checkpoints & Sovereign License Matrix

- **Identifier:** ADR-0003
- **Status:** Accepted
- **Date:** 2026-11-15
- **Source Modules:** [`governance.py`](../../../src/platform_core/deploy_security/governance.py), [`state.py`](../../../src/platform_core/layer2_execution/state.py), [`sandbox.py`](../../../src/platform_core/layer2_execution/sandbox.py), [`training.py`](../../../src/platform_core/layer1_intelligence/training.py)

---

## 1. Context

`platform-core` ingests untrusted third-party repositories, stripped binaries (which may contain adversarial prompt-injection strings in `.rodata`), compressed streams, and model weight files. Without strict supply-chain and information-flow controls:
- Embedded prompt injections in binaries or docs could trick an agent into exfiltrating host credentials (`AWS_*`, `GITHUB_*`, `HF_TOKEN`) or hitting cloud metadata endpoints (`169.254.169.254`).
- Loading PyTorch `.pkl`/`.pt`/`.bin` checkpoints executes arbitrary Python bytecode via `pickle`.
- Training on or registering models with viral copyleft (`GPL-3.0`/`AGPL-3.0`) or EU-restricted (`Llama-4-Community`) licenses compromises commercial IP sovereignty.

---

## 2. Decision

1. **Step 1 Taint Classification (`TAINTED_UNTRUSTED`)**: Any session with `has_untrusted_artifacts=True` is marked `TaintLevel.TAINTED_UNTRUSTED` at Step 1:
   - `SignedManifestVerifier.verify()` blocks any tool requiring `network_egress` or `admin_deploy` scopes.
   - `CyberGymFirewall.evaluate_egress()` blocks 100% of outbound network connections (`internal=True` microVM bridge).
   - `FirecrackerSandboxManager._build_sanitized_env()` strips all credential environment variables (`SENSITIVE_ENV_PREFIXES`) and host paths before spawning `python3 -I`.
2. **Safetensors-Only Checkpoint Gate (`SafetensorsValidator`)**:
   - Reject `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.ckpt`, and `.joblib` extensions with `PickleSupplyChainError`.
   - Inspect the first 2 bytes of every checkpoint buffer for disguised pickle magic headers (`\x80\x02`–`\x80\x05`).
   - Verify 8-byte little-endian header size bounds (`<= 100 MiB`), valid dtype/shape definitions (rejecting Python `bool` as `int`), exact byte-span match (`(end - start) == math.prod(shape) * dtype_byte_size`), contiguous non-overlapping `[0, data_buffer_len]` coverage, and SHA-256 integrity.
3. **Default-Deny Commercial License Matrix (`LicenseComplianceAuditor`)**:
   - Permit only `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `PostgreSQL`, and `CC0-1.0` (`LicenseVerdict.APPROVED_COMMERCIAL`) for model registration (`ModelRegistry.register_model`), MOPD distillation teachers (`MOPDDistiller`), and training trajectories (`DatasetHygienePipeline`).
   - Block `Llama-4-Community`, `GPL-2.0`, `GPL-3.0`, `AGPL-3.0`, `Proprietary-Closed-API`, `Research-Only`, and any unrecognized license identifier.

---

## 3. Consequences

- **Positive**: Complete immunity against pickle deserialization RCE, credential exfiltration from tainted sandboxes, symlink path traversal during sandbox sync-back or manifest loading, and IP contamination from non-permissive weights or datasets.
- **Trade-offs**: Legacy `.pt`/`.bin` checkpoints must be converted to `.safetensors` before registration, and custom models must explicitly specify an approved SPDX license identifier.

---

## 4. Alternatives Considered

1. **`weights_only=True` in PyTorch Pickle Loader**: Rejected in favor of strict `.safetensors` binary format verification (`SafetensorsValidator`) which provides zero-copy header validation without any pickle interpreter surface.
2. **Blocklist-Only License Filtering**: Rejected in favor of an explicit allowlist (`APPROVED_LICENSES`) with default-deny fallback for unrecognized licenses.
