"""Supply-Chain Security, License Governance, Firewall Policy, and K8s Sandbox Manifests.

Implements Section 10.5 & Phase 1/3/8 security controls from the architecture blueprint:
1. Safetensors-only model weight verification (blocking arbitrary Python pickle execution).
2. Sovereign License Compliance Matrix (permitting Apache-2.0/MIT/BSD; blocking Llama 4 EU ban,
   copyleft GPL/AGPL, and closed-API distillation teachers).
3. Cryptographically signed MCP tool manifests (HMAC-SHA256) with scoped capabilities.
4. CyberGym Firewall (`cybergym.firewall` pattern) enforcing `TAINTED_UNTRUSTED` network egress
   isolation and SSRF/metadata protection.
5. Kubernetes `kubernetes-sigs/agent-sandbox` (`SandboxTemplate` & `SandboxClaim`) generators.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import ipaddress
import json
import math
from pathlib import Path
import struct
from typing import Any
from urllib.parse import urlparse


class PickleSupplyChainError(PermissionError):
    """Raised when an unsafe pickle-based checkpoint (.pkl, .pt, .pth, .bin) is rejected."""


class SafetensorsValidationError(ValueError):
    """Raised when a Safetensors file fails structural or cryptographic verification."""


class LicenseVerdict(str, Enum):
    """Compliance verdict for model weights or training datasets."""

    APPROVED_COMMERCIAL = "APPROVED_COMMERCIAL"
    REQUIRES_LEGAL_REVIEW = "REQUIRES_LEGAL_REVIEW"
    REJECTED_PROHIBITED = "REJECTED_PROHIBITED"


@dataclass(frozen=True)
class LicenseAuditResult:
    """Result of auditing a model checkpoint or dataset license."""

    artifact_name: str
    license_id: str
    verdict: LicenseVerdict
    rationale: str
    eu_compliant: bool
    allows_commercial_distillation: bool


class LicenseComplianceAuditor:
    """Audits base models and datasets against the platform's sovereign IP policy."""

    APPROVED_LICENSES: frozenset[str] = frozenset(
        {
            "Apache-2.0",
            "MIT",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "PostgreSQL",
            "CC0-1.0",
        }
    )
    LEGAL_REVIEW_LICENSES: frozenset[str] = frozenset(
        {
            "Modified-MIT",
            "Mistral-Ecosystem",
            "Elastic-2.0",
        }
    )
    PROHIBITED_LICENSES: dict[str, str] = {
        "Llama-4-Community": (
            "Rejected: 700M MAU limit, non-OSI compliant, and multimodal models are "
            "explicitly prohibited for individuals/companies domiciled in the EU."
        ),
        "GPL-2.0": "Rejected: Copyleft viral licensing contaminates proprietary model weights.",
        "GPL-3.0": "Rejected: Copyleft viral licensing contaminates proprietary model weights.",
        "AGPL-3.0": "Rejected: Network copyleft incompatible with sovereign commercial deployment.",
        "Proprietary-Closed-API": (
            "Rejected: Zero weight ownership and Terms of Service prohibit commercial "
            "distillation into competing foundation/specialist models."
        ),
        "Research-Only": "Rejected: Non-commercial research restriction (e.g., DeepSeek-V3.2-Speciale).",
    }

    def audit(self, artifact_name: str, license_id: str) -> LicenseAuditResult:
        """Evaluate an artifact's license against platform compliance rules."""
        cleaned = license_id.strip()
        if not cleaned:
            return LicenseAuditResult(
                artifact_name=artifact_name,
                license_id=cleaned,
                verdict=LicenseVerdict.REJECTED_PROHIBITED,
                rationale="Missing or empty license identifier; unproven provenance.",
                eu_compliant=False,
                allows_commercial_distillation=False,
            )

        if cleaned in self.APPROVED_LICENSES:
            return LicenseAuditResult(
                artifact_name=artifact_name,
                license_id=cleaned,
                verdict=LicenseVerdict.APPROVED_COMMERCIAL,
                rationale=f"Permissive OSI-compliant license ({cleaned}); safe for commercial weights and distillation.",
                eu_compliant=True,
                allows_commercial_distillation=True,
            )

        if cleaned in self.LEGAL_REVIEW_LICENSES:
            return LicenseAuditResult(
                artifact_name=artifact_name,
                license_id=cleaned,
                verdict=LicenseVerdict.REQUIRES_LEGAL_REVIEW,
                rationale=f"Conditional license ({cleaned}); requires legal sign-off before production redistribution.",
                eu_compliant=True,
                allows_commercial_distillation=False,
            )

        if cleaned in self.PROHIBITED_LICENSES:
            return LicenseAuditResult(
                artifact_name=artifact_name,
                license_id=cleaned,
                verdict=LicenseVerdict.REJECTED_PROHIBITED,
                rationale=self.PROHIBITED_LICENSES[cleaned],
                eu_compliant=(cleaned != "Llama-4-Community"),
                allows_commercial_distillation=False,
            )

        return LicenseAuditResult(
            artifact_name=artifact_name,
            license_id=cleaned,
            verdict=LicenseVerdict.REJECTED_PROHIBITED,
            rationale=f"Unrecognized license '{cleaned}'; blocked by default-deny provenance gate.",
            eu_compliant=False,
            allows_commercial_distillation=False,
        )


class SafetensorsValidator:
    """Validates model weight files to prevent pickle execution and corrupted tensor offsets."""

    FORBIDDEN_EXTENSIONS: frozenset[str] = frozenset(
        {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib"}
    )
    MAX_HEADER_BYTES: int = 100 * 1024 * 1024  # 100 MiB ceiling per Safetensors spec
    DTYPE_BYTE_SIZES: dict[str, int] = {
        "BOOL": 1,
        "U8": 1,
        "I8": 1,
        "F8_E4M3": 1,
        "F8_E5M2": 1,
        "I16": 2,
        "U16": 2,
        "F16": 2,
        "BF16": 2,
        "I32": 4,
        "U32": 4,
        "F32": 4,
        "F64": 8,
        "I64": 8,
        "U64": 8,
    }
    VALID_DTYPES: frozenset[str] = frozenset(DTYPE_BYTE_SIZES.keys())

    @classmethod
    def create_valid_safetensors_bytes(
        cls,
        tensors_meta: dict[str, dict[str, Any]],
        data_payload: bytes,
        metadata: dict[str, str] | None = None,
    ) -> bytes:
        """Construct a spec-compliant Safetensors binary buffer for testing and checkpointing."""
        header_dict: dict[str, Any] = {}
        if metadata is not None:
            header_dict["__metadata__"] = metadata
        for name, spec in tensors_meta.items():
            header_dict[name] = spec
        header_bytes = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
        # Pad header to 8-byte alignment with spaces if needed
        pad_len = (8 - (len(header_bytes) % 8)) % 8
        header_bytes += b" " * pad_len
        return struct.pack("<Q", len(header_bytes)) + header_bytes + data_payload

    def validate_file(
        self,
        file_path: str | Path,
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Validate a Safetensors file on disk and return its parsed header metadata."""
        path = Path(file_path)
        if path.is_symlink():
            raise PermissionError(f"Symlinked Safetensors file rejected: {path}")
        suffix = path.suffix.lower()
        if suffix in self.FORBIDDEN_EXTENSIONS:
            raise PickleSupplyChainError(
                f"Rejected unsafe checkpoint '{path.name}' with forbidden extension '{suffix}'. "
                "Only '.safetensors' checkpoints are permitted."
            )
        if suffix != ".safetensors":
            raise SafetensorsValidationError(
                f"Checkpoint '{path.name}' must use '.safetensors' extension (got '{suffix}')."
            )
        if not path.is_file():
            raise FileNotFoundError(f"Safetensors file not found: {path}")

        raw_bytes = path.read_bytes()
        return self.validate_bytes(
            raw_bytes=raw_bytes,
            artifact_name=path.name,
            expected_sha256=expected_sha256,
        )

    def validate_bytes(
        self,
        raw_bytes: bytes,
        artifact_name: str = "memory_buffer.safetensors",
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Validate raw Safetensors bytes for pickle magic, header bounds, and tensor offsets."""
        if len(raw_bytes) < 8:
            raise SafetensorsValidationError(
                f"Safetensors artifact '{artifact_name}' is truncated (< 8 bytes)."
            )

        # Detect disguised pickle magic bytes (\x80\x02, \x80\x03, \x80\x04, \x80\x05)
        # while avoiding false positives on legitimate Safetensors headers whose <Q length
        # ends in 0x0280, 0x0380, 0x0480, or 0x0580 (e.g. 640, 896, 1152, 1408 bytes).
        if raw_bytes[:2] in {b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"}:
            (candidate_len,) = struct.unpack("<Q", raw_bytes[:8])
            is_safetensors_json = (
                0 < candidate_len <= self.MAX_HEADER_BYTES
                and 8 + candidate_len <= len(raw_bytes)
                and raw_bytes[8:9] == b"{"
            )
            if not is_safetensors_json:
                raise PickleSupplyChainError(
                    f"Disguised Python pickle header detected inside '{artifact_name}'!"
                )

        actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        if expected_sha256 is not None and actual_sha256.lower() != expected_sha256.lower():
            raise SafetensorsValidationError(
                f"SHA-256 mismatch for '{artifact_name}': expected {expected_sha256}, got {actual_sha256}."
            )

        (header_size,) = struct.unpack("<Q", raw_bytes[:8])
        if header_size == 0 or header_size > self.MAX_HEADER_BYTES:
            raise SafetensorsValidationError(
                f"Invalid Safetensors header size {header_size} in '{artifact_name}'."
            )
        if 8 + header_size > len(raw_bytes):
            raise SafetensorsValidationError(
                f"Safetensors header size ({header_size}) exceeds file size ({len(raw_bytes)}) in '{artifact_name}'."
            )

        try:
            header_json = raw_bytes[8 : 8 + header_size].decode("utf-8")
            header = json.loads(header_json)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SafetensorsValidationError(
                f"Malformed JSON header in Safetensors '{artifact_name}': {exc}"
            ) from exc

        if not isinstance(header, dict) or not header:
            raise SafetensorsValidationError(
                f"Safetensors header in '{artifact_name}' must be a non-empty JSON object."
            )

        data_buffer_len = len(raw_bytes) - (8 + header_size)
        intervals: list[tuple[int, int, str]] = []
        tensor_count = 0

        for key, entry in header.items():
            if key == "__metadata__":
                if not isinstance(entry, dict) or not all(
                    isinstance(k, str) and isinstance(v, str) for k, v in entry.items()
                ):
                    raise SafetensorsValidationError(
                        f"'__metadata__' in '{artifact_name}' must map strings to strings."
                    )
                continue

            if not isinstance(entry, dict):
                raise SafetensorsValidationError(
                    f"Tensor entry '{key}' in '{artifact_name}' must be a JSON object."
                )
            dtype = entry.get("dtype")
            shape = entry.get("shape")
            offsets = entry.get("data_offsets")

            if dtype not in self.VALID_DTYPES:
                raise SafetensorsValidationError(
                    f"Unsupported dtype '{dtype}' for tensor '{key}' in '{artifact_name}'."
                )
            if (
                not isinstance(shape, list)
                or not all(
                    isinstance(dim, int) and not isinstance(dim, bool) and dim >= 0
                    for dim in shape
                )
            ):
                raise SafetensorsValidationError(
                    f"Invalid shape '{shape}' for tensor '{key}' in '{artifact_name}'."
                )
            if (
                not isinstance(offsets, list)
                or len(offsets) != 2
                or not all(isinstance(x, int) and not isinstance(x, bool) for x in offsets)
            ):
                raise SafetensorsValidationError(
                    f"Invalid data_offsets '{offsets}' for tensor '{key}' in '{artifact_name}'."
                )
            start, end = offsets[0], offsets[1]
            if start < 0 or end < start or end > data_buffer_len:
                raise SafetensorsValidationError(
                    f"Out-of-bounds data_offsets [{start}, {end}] for tensor '{key}' "
                    f"(payload size {data_buffer_len}) in '{artifact_name}'."
                )
            expected_bytes = math.prod(shape) * self.DTYPE_BYTE_SIZES[dtype]
            if (end - start) != expected_bytes:
                raise SafetensorsValidationError(
                    f"Tensor '{key}' data_offsets [{start}, {end}] span {end - start} bytes, "
                    f"but shape {shape} with dtype '{dtype}' requires {expected_bytes} bytes in '{artifact_name}'."
                )
            intervals.append((start, end, key))
            tensor_count += 1

        if tensor_count == 0:
            raise SafetensorsValidationError(
                f"Safetensors '{artifact_name}' contains zero tensor definitions."
            )

        # Ensure tensor regions are contiguous, non-overlapping, and cover the full data buffer
        intervals.sort(key=lambda item: (item[0], item[1]))
        prev_end = 0
        for start, end, key in intervals:
            if start < prev_end:
                raise SafetensorsValidationError(
                    f"Overlapping tensor data offsets detected at tensor '{key}' in '{artifact_name}'."
                )
            if start > prev_end:
                raise SafetensorsValidationError(
                    f"Unindexed gap [{prev_end}, {start}] detected before tensor '{key}' in '{artifact_name}'."
                )
            prev_end = end
        if prev_end != data_buffer_len:
            raise SafetensorsValidationError(
                f"Trailing unindexed data bytes [{prev_end}, {data_buffer_len}] in '{artifact_name}'."
            )

        return {
            "artifact_name": artifact_name,
            "sha256": actual_sha256,
            "header_size": header_size,
            "data_bytes": data_buffer_len,
            "tensor_count": tensor_count,
            "header": header,
        }


@dataclass(frozen=True)
class MCPToolManifest:
    """Signed Model Context Protocol (MCP) tool contract (Section 1.8 & 10.5)."""

    tool_name: str
    server_id: str
    version: str
    description: str
    parameters_schema: dict[str, Any]
    required_scopes: tuple[str, ...]
    timeout_sec: int = 60
    allows_tainted_execution: bool = True
    requires_human_approval: bool = False
    signature: str = ""

    def canonical_payload(self) -> bytes:
        """Return canonical JSON bytes (excluding signature) for HMAC signing."""
        payload = {
            "tool_name": self.tool_name,
            "server_id": self.server_id,
            "version": self.version,
            "description": self.description,
            "parameters_schema": self.parameters_schema,
            "required_scopes": list(self.required_scopes),
            "timeout_sec": self.timeout_sec,
            "allows_tainted_execution": self.allows_tainted_execution,
            "requires_human_approval": self.requires_human_approval,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SignedManifestVerifier:
    """Cryptographically signs and verifies MCP tool manifests using HMAC-SHA256."""

    VALID_SCOPES: frozenset[str] = frozenset(
        {
            "read_code",
            "write_code",
            "analyze_binary",
            "decompile_binary",
            "audit_security",
            "parse_data",
            "ground_visual",
            "run_sandbox",
            "network_egress",
            "admin_deploy",
        }
    )

    def __init__(self, signing_key: str | bytes) -> None:
        if isinstance(signing_key, str):
            signing_key = signing_key.encode("utf-8")
        if len(signing_key) < 16:
            raise ValueError("MCP manifest signing key must be at least 16 bytes.")
        self._key = signing_key

    def sign(self, manifest: MCPToolManifest) -> MCPToolManifest:
        """Validate manifest invariants and return a signed copy."""
        self._validate_invariants(manifest)
        digest = hmac.new(self._key, manifest.canonical_payload(), hashlib.sha256).hexdigest()
        return MCPToolManifest(
            tool_name=manifest.tool_name,
            server_id=manifest.server_id,
            version=manifest.version,
            description=manifest.description,
            parameters_schema=manifest.parameters_schema,
            required_scopes=manifest.required_scopes,
            timeout_sec=manifest.timeout_sec,
            allows_tainted_execution=manifest.allows_tainted_execution,
            requires_human_approval=manifest.requires_human_approval,
            signature=digest,
        )

    def verify(
        self,
        manifest: MCPToolManifest,
        granted_scopes: set[str] | frozenset[str],
        session_tainted: bool = False,
    ) -> bool:
        """Verify HMAC signature, scope authorization, and taint isolation policy."""
        self._validate_invariants(manifest)
        if not manifest.signature:
            return False
        expected = hmac.new(self._key, manifest.canonical_payload(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(manifest.signature, expected):
            return False

        # Taint separation: tainted sessions cannot invoke network_egress or admin_deploy
        if session_tainted:
            if not manifest.allows_tainted_execution:
                return False
            if "network_egress" in manifest.required_scopes or "admin_deploy" in manifest.required_scopes:
                return False

        return set(manifest.required_scopes).issubset(granted_scopes)

    def _validate_invariants(self, manifest: MCPToolManifest) -> None:
        if not manifest.tool_name or not manifest.server_id:
            raise ValueError("MCPToolManifest requires non-empty tool_name and server_id.")
        if not (1 <= manifest.timeout_sec <= 3600):
            raise ValueError(f"Tool timeout_sec must be in [1, 3600], got {manifest.timeout_sec}.")
        unknown_scopes = set(manifest.required_scopes) - self.VALID_SCOPES
        if unknown_scopes:
            raise ValueError(f"Unknown MCP permission scopes: {sorted(unknown_scopes)}")


@dataclass(frozen=True)
class FirewallDecision:
    """Result of evaluating a network egress request through CyberGymFirewall."""

    allowed: bool
    reason: str
    destination: str
    tainted_session: bool


class CyberGymFirewall:
    """Implements the `cybergym.firewall` Squid proxy allowlist & taint egress lockdown."""

    DEFAULT_ALLOWLIST: frozenset[str] = frozenset(
        {
            "mirror.internal.platform.local",
            "pypi.internal.platform.local",
            "crates.internal.platform.local",
            "scip-registry.internal.platform.local",
        }
    )

    def __init__(self, allowed_domains: set[str] | frozenset[str] | None = None) -> None:
        self.allowed_domains: frozenset[str] = (
            frozenset(d.lower().strip() for d in allowed_domains)
            if allowed_domains is not None
            else self.DEFAULT_ALLOWLIST
        )

    def evaluate_egress(self, url_or_host: str, session_tainted: bool) -> FirewallDecision:
        """Evaluate whether an outbound connection is permitted."""
        if session_tainted:
            return FirewallDecision(
                allowed=False,
                reason="Blocked: Session is TAINTED_UNTRUSTED (internal=True bridge enforced; zero outbound egress).",
                destination=url_or_host,
                tainted_session=True,
            )

        raw = url_or_host.strip()
        if not raw:
            return FirewallDecision(
                allowed=False,
                reason="Blocked: Empty destination URL or host.",
                destination=url_or_host,
                tainted_session=False,
            )

        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        if parsed.scheme not in {"https", "http"}:
            return FirewallDecision(
                allowed=False,
                reason=f"Blocked: Unsupported scheme '{parsed.scheme}'.",
                destination=url_or_host,
                tainted_session=False,
            )

        host = (parsed.hostname or "").lower().strip()
        if not host:
            return FirewallDecision(
                allowed=False,
                reason="Blocked: Missing hostname.",
                destination=url_or_host,
                tainted_session=False,
            )

        # Block raw IP addresses, loopback, link-local (169.254.169.254 cloud metadata), and RFC1918
        try:
            ip_obj = ipaddress.ip_address(host)
            return FirewallDecision(
                allowed=False,
                reason=f"Blocked: Direct IP literal '{ip_obj}' is forbidden (anti-SSRF/metadata protection).",
                destination=url_or_host,
                tainted_session=False,
            )
        except ValueError:
            pass

        if host in {"localhost", "metadata.google.internal"} or host.endswith(".localhost"):
            return FirewallDecision(
                allowed=False,
                reason=f"Blocked: Localhost/metadata hostname '{host}' is forbidden.",
                destination=url_or_host,
                tainted_session=False,
            )

        if host in self.allowed_domains:
            return FirewallDecision(
                allowed=True,
                reason=f"Allowed: Host '{host}' matches Squid proxy allowlist.",
                destination=url_or_host,
                tainted_session=False,
            )

        return FirewallDecision(
            allowed=False,
            reason=f"Blocked: Host '{host}' is not in the Squid proxy allowlist.",
            destination=url_or_host,
            tainted_session=False,
        )

    def generate_squid_conf(self) -> str:
        """Render a hardened Squid proxy configuration implementing the allowlist."""
        domains = " ".join(sorted(self.allowed_domains))
        return "\n".join(
            [
                "# Auto-generated by CyberGymFirewall (Section 10.5)",
                "acl localnet src 10.240.0.0/16",
                "acl SSL_ports port 443",
                "acl Safe_ports port 80 443",
                f"acl allowed_domains dstdomain {domains}",
                "http_access deny !Safe_ports",
                "http_access deny CONNECT !SSL_ports",
                "http_access allow localnet allowed_domains",
                "http_access deny all",
            ]
        )


@dataclass(frozen=True)
class K8sAgentSandboxGenerator:
    """Generates `kubernetes-sigs/agent-sandbox` CRDs for Firecracker microVM isolation."""

    namespace: str = "ai-platform-sandboxes"

    def build_sandbox_template(
        self,
        template_name: str = "firecracker-secverifier-template",
        vcpu_count: int = 2,
        memory_mib: int = 512,
        network_internal_only: bool = True,
    ) -> dict[str, Any]:
        """Generate a `SandboxTemplate` CRD with Firecracker KVM + 24-syscall seccomp filter."""
        return {
            "apiVersion": "agentsandbox.x-k8s.io/v1alpha1",
            "kind": "SandboxTemplate",
            "metadata": {
                "name": template_name,
                "namespace": self.namespace,
                "labels": {
                    "platform.ai/layer": "layer2-execution",
                    "platform.ai/isolation": "firecracker-kvm",
                },
            },
            "spec": {
                "runtimeClassName": "kata-fc",
                "microVM": {
                    "hypervisor": "firecracker",
                    "bootTargetMs": 125,
                    "cowSnapshotRestoreTargetMs": 8.5,
                    "vcpuCount": vcpu_count,
                    "memoryMiB": memory_mib,
                    "jailer": {
                        "enabled": True,
                        "chrootBaseDir": "/srv/jailer/firecracker",
                        "seccompSyscallLimit": 24,
                        "cgroupV2": True,
                        "dropAllCapabilities": True,
                    },
                },
                "networkPolicy": {
                    "internalBridgeOnly": network_internal_only,
                    "allowHostMounts": False,
                    "squidProxyService": "cybergym-squid-proxy.ai-platform-sandboxes.svc.cluster.local:3128",
                },
            },
        }

    def build_sandbox_claim(
        self,
        claim_name: str,
        template_name: str,
        session_id: str,
        tainted: bool = True,
    ) -> dict[str, Any]:
        """Generate a `SandboxClaim` CRD binding an agent task to an isolated Firecracker VM."""
        return {
            "apiVersion": "agentsandbox.x-k8s.io/v1alpha1",
            "kind": "SandboxClaim",
            "metadata": {
                "name": claim_name,
                "namespace": self.namespace,
                "annotations": {
                    "platform.ai/session-id": session_id,
                    "platform.ai/taint-state": "TAINTED_UNTRUSTED" if tainted else "CLEAN",
                },
            },
            "spec": {
                "templateRef": {"name": template_name},
                "lifecycle": {
                    "preExecutionCoWSnapshot": True,
                    "autoRollbackOnVerifierReject": True,
                    "maxExecutionSeconds": 300,
                },
            },
        }
