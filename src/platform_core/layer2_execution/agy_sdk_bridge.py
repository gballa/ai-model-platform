"""Layer 2 Google Antigravity (AGY) Local SDK Bridge, Skill Discovery & Stdio MCP Server.

Integrates `platform_core` deterministic MCP servers, taint isolation, and the
`IndependentVerifierAgent` (`SecVerifier`) gate with the Google Antigravity SDK
(`LiteRTAgentConfig`, `LocalOpenAIAgentConfig`, `skills_paths`, `SubagentConfig`,
`McpStdioServer`), while preserving zero required third-party dependencies
(`dependencies = []`) via dynamic lazy SDK probing and a pure-stdlib fallback.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, TextIO

from platform_core.layer1_intelligence.inference import (
    ChatMessage,
    DeterministicMockBackend,
    InferenceBackend,
    InferenceRequest,
)

from .agents import IndependentVerifierAgent
from .forensics_mcp import ForensicsMCPServer
from .mcp_tools import (
    BinRevMCPServer,
    CodeGraphMCPServer,
    DataAndVisualMCPServer,
    DefensiveCyberMCPServer,
)
from .sandbox import FirecrackerSandboxManager
from .state import (
    EpistemicAssessment,
    EpistemicClaim,
    EpistemicStatus,
    PlatformState,
    SubTask,
    TaintLevel,
    TaskStatus,
)
from .vuln_intel_mcp import VulnIntelMCPServer

MAX_JSONRPC_LINE_BYTES: int = 1 * 1024 * 1024  # 1 MiB bounded stdio read
MAX_SUBAGENT_DEPTH_CAP: int = 3
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_TAINT_BLOCKED_TOOL_NAMES: frozenset[str] = frozenset(
    {"vuln_sync_live_feeds", "network_egress", "admin_deploy"}
)


def _require_strict_int(value: Any, field_name: str, minimum: int = 0) -> int:
    """Validate an integer field while rejecting booleans (`bool` is a subclass of `int`)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer (not bool), got {type(value).__name__}.")
    if value < minimum:
        raise ValueError(f"{field_name} must be >= {minimum}, got {value}.")
    return value


def _validate_no_traversal(raw_path: str | Path, label: str) -> Path:
    """Reject explicit '..' traversal components and symlinks on input paths."""
    path = Path(raw_path)
    if ".." in path.parts:
        raise PermissionError(f"Path traversal ('..') rejected for {label}: {raw_path}")
    if path.is_symlink():
        raise PermissionError(f"Symlinked {label} rejected: {raw_path}")
    return path


def _validate_loopback_or_url(base_url: str, session_tainted: bool) -> str:
    """Validate HTTP(S) endpoint URL and enforce loopback isolation when tainted."""
    from urllib.parse import urlparse

    cleaned = base_url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid OpenAI-compatible base_url: {base_url!r}")
    host = (parsed.hostname or "").lower().strip("[]")
    if session_tainted and host not in _LOOPBACK_HOSTS:
        raise PermissionError(
            f"TAINTED_UNTRUSTED session blocked from non-loopback endpoint '{host}'."
        )
    return cleaned


@dataclass(frozen=True)
class AgyLocalAgentSpec:
    """Declarative specification for running a local AGY SDK or fallback agent."""

    agent_name: str
    runtime_kind: str = "local_openai"  # "litert" | "local_openai"
    model_or_path: str = "Qwen/Qwen3.5-35B-A3B"
    base_url: str | None = "http://127.0.0.1:8080/v1"
    litert_backend: str = "gpu"  # "gpu" | "npu"
    enable_speculative_decoding: bool = False
    skills_paths: tuple[str, ...] = (".agents/skills",)
    mcp_servers: tuple[dict[str, Any], ...] = ()
    subagents: tuple[dict[str, Any], ...] = ()
    max_subagent_depth: int = 2
    session_tainted: bool = True
    system_instructions: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.agent_name, str) or not self.agent_name.strip():
            raise ValueError("agent_name must be a non-empty string.")
        if "/" in self.agent_name or "\\" in self.agent_name or ".." in self.agent_name:
            raise PermissionError(f"Invalid agent_name '{self.agent_name}': path characters forbidden.")
        if self.runtime_kind not in {"litert", "local_openai"}:
            raise ValueError(
                f"Unsupported runtime_kind {self.runtime_kind!r}: expected 'litert' or 'local_openai'."
            )
        if self.litert_backend not in {"gpu", "npu"}:
            raise ValueError(
                f"Unsupported litert_backend {self.litert_backend!r}: expected 'gpu' or 'npu'."
            )
        _require_strict_int(self.max_subagent_depth, "max_subagent_depth", minimum=0)


@dataclass(frozen=True)
class AgyExecutionResult:
    """Structured outcome of an AGY local agent or deterministic fallback run."""

    agent_name: str
    execution_backend: str  # "google_antigravity_sdk" | "stdlib_fallback"
    sdk_available: bool
    config_snapshot: dict[str, Any]
    loaded_skills: tuple[str, ...]
    bound_mcp_servers: tuple[str, ...]
    subagent_delegations: tuple[str, ...]
    response_text: str
    verified_by_independent_verifier: bool
    status: str
    taint_level: str = TaintLevel.TAINTED_UNTRUSTED.value
    epistemic_assessment: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize execution result to a JSON-compatible dictionary."""
        return asdict(self)


class AgySkillDiscovery:
    """Pure-stdlib `SKILL.md` YAML frontmatter parser with symlink & traversal checks."""

    @staticmethod
    def _unquote_yaml_scalar(value: str) -> str:
        stripped = value.strip()
        if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
            inner = stripped[1:-1]
            if stripped[0] == '"':
                inner = inner.replace('\\"', '"').replace("\\n", "\n")
            else:
                inner = inner.replace("''", "'")
            return inner
        return stripped

    @classmethod
    def parse_skill_frontmatter(cls, markdown_text: str) -> dict[str, str]:
        """Extract top-level YAML frontmatter scalars from a `SKILL.md` without external deps."""
        cleaned = markdown_text.lstrip("\ufeff")
        lines = cleaned.splitlines()
        if not lines or lines[0].strip() != "---":
            return {}

        end_idx: int | None = None
        for idx in range(1, len(lines)):
            if lines[idx].strip() == "---":
                end_idx = idx
                break
        if end_idx is None:
            return {}

        parsed: dict[str, str] = {}
        current_key: str | None = None
        block_mode: str | None = None
        block_lines: list[str] = []

        def _flush_block() -> None:
            nonlocal current_key, block_mode, block_lines
            if current_key is not None and block_mode is not None:
                joined = "\n".join(block_lines) if block_mode == "|" else " ".join(
                    part.strip() for part in block_lines if part.strip()
                )
                parsed[current_key] = joined.strip()
            current_key = None
            block_mode = None
            block_lines = []

        for raw_line in lines[1:end_idx]:
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                if block_mode is not None:
                    block_lines.append("")
                continue
            if raw_line[0] in {" ", "\t"} and current_key is not None:
                if block_mode is not None:
                    block_lines.append(raw_line.strip())
                else:
                    existing = parsed.get(current_key, "")
                    cont = cls._unquote_yaml_scalar(raw_line)
                    parsed[current_key] = f"{existing} {cont}".strip() if existing else cont
                continue

            _flush_block()
            if ":" not in raw_line:
                continue
            key_raw, val_raw = raw_line.split(":", 1)
            key = key_raw.strip()
            if not key:
                continue
            val_stripped = val_raw.strip()
            if val_stripped in {"|", ">", "|-", ">-"}:
                current_key = key
                block_mode = val_stripped[0]
                block_lines = []
            else:
                current_key = key
                block_mode = None
                parsed[key] = cls._unquote_yaml_scalar(val_stripped)

        _flush_block()
        return parsed

    @classmethod
    def _load_single_skill_dir(cls, skill_dir: Path, root_resolved: Path) -> dict[str, str] | None:
        if skill_dir.is_symlink():
            raise PermissionError(f"Symlinked skill directory rejected: {skill_dir}")
        resolved_dir = skill_dir.resolve()
        if not resolved_dir.is_relative_to(root_resolved):
            raise PermissionError(
                f"Skill directory '{skill_dir}' escapes configured root '{root_resolved}'."
            )
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            return None
        if skill_md.is_symlink():
            raise PermissionError(f"Symlinked SKILL.md rejected: {skill_md}")
        resolved_md = skill_md.resolve()
        if not resolved_md.is_relative_to(root_resolved) or not resolved_md.is_file():
            raise PermissionError(f"Invalid or escaping SKILL.md rejected: {skill_md}")

        content = resolved_md.read_text(encoding="utf-8")
        meta = cls.parse_skill_frontmatter(content)
        skill_name = meta.get("name", "").strip() or skill_dir.name
        return {
            "name": skill_name,
            "description": meta.get("description", "").strip(),
            "path": str(resolved_dir),
            "skill_file": str(resolved_md),
        }

    @classmethod
    def discover_skills(cls, skills_paths: list[str | Path] | tuple[str | Path, ...]) -> list[dict[str, str]]:
        """Discover valid `SKILL.md` directories from parent or direct skill paths."""
        discovered: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()

        for raw_entry in skills_paths:
            entry = _validate_no_traversal(raw_entry, "skills_path")
            if not entry.exists():
                continue
            if not entry.is_dir():
                raise NotADirectoryError(f"Skill path must be a directory: {entry}")

            resolved_entry = entry.resolve()
            direct_skill_md = entry / "SKILL.md"
            if direct_skill_md.exists() or direct_skill_md.is_symlink():
                item = cls._load_single_skill_dir(entry, resolved_entry)
                if item is not None:
                    key = (item["name"], item["path"])
                    if key not in seen:
                        seen.add(key)
                        discovered.append(item)
                continue

            for child in sorted(entry.iterdir(), key=lambda p: p.name):
                if child.is_symlink():
                    raise PermissionError(f"Symlinked skill entry rejected: {child}")
                if not child.is_dir():
                    continue
                item = cls._load_single_skill_dir(child, resolved_entry)
                if item is not None:
                    key = (item["name"], item["path"])
                    if key not in seen:
                        seen.add(key)
                        discovered.append(item)

        return discovered


@dataclass(frozen=True)
class _RegisteredMCPTool:
    name: str
    server: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any], bool], dict[str, Any]]
    network_egress: bool = False
    admin_deploy: bool = False


class AgyStdioMCPBridge:
    """Newline-delimited JSON-RPC 2.0 MCP stdio bridge over existing `platform_core` servers."""

    SUPPORTED_SERVERS: frozenset[str] = frozenset(
        {"data_visual", "vuln_intel", "forensics", "code_graph", "binrev", "defensive_cyber"}
    )

    def __init__(self, vuln_db_path: str | Path = ":memory:") -> None:
        self.data_visual_mcp = DataAndVisualMCPServer()
        self.vuln_intel_mcp = VulnIntelMCPServer(db_path=vuln_db_path)
        self.forensics_mcp = ForensicsMCPServer()
        self.code_graph_mcp = CodeGraphMCPServer(db_path=":memory:")
        self.binrev_mcp = BinRevMCPServer()
        self.defensive_cyber_mcp = DefensiveCyberMCPServer()
        self._closed = False
        self._tools: dict[str, _RegisteredMCPTool] = self._build_tool_registry()

    def close(self) -> None:
        """Close underlying SQLite-backed MCP servers idempotently."""
        if getattr(self, "_closed", True):
            return
        self._closed = True
        for resource in (
            getattr(self, "vuln_intel_mcp", None),
            getattr(self, "code_graph_mcp", None),
            getattr(getattr(self, "forensics_mcp", None), "ioc_engine", None),
        ):
            if resource is not None and hasattr(resource, "close"):
                try:
                    resource.close()
                except Exception:
                    pass

    def __enter__(self) -> AgyStdioMCPBridge:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if hasattr(value, "value") and not isinstance(value, (str, bytes)):
            return value.value
        if isinstance(value, dict):
            return {str(k): AgyStdioMCPBridge._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [AgyStdioMCPBridge._json_safe(v) for v in value]
        return value

    @staticmethod
    def _decode_payload_bytes(args: dict[str, Any], hex_key: str = "hex_data") -> bytes:
        if hex_key in args and args[hex_key] is not None:
            raw_hex = str(args[hex_key]).strip()
            return bytes.fromhex(raw_hex)
        if "utf8_text" in args and args["utf8_text"] is not None:
            return str(args["utf8_text"]).encode("utf-8")
        raise ValueError(f"Provide either '{hex_key}' or 'utf8_text'.")

    def _build_tool_registry(self) -> dict[str, _RegisteredMCPTool]:
        specs = [
            _RegisteredMCPTool(
                name="data_classify_transformation",
                server="data_visual",
                description="Classify byte payload into Encoding, Compression, Encryption, or Hashing.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "hex_data": {"type": "string"},
                        "utf8_text": {"type": "string"},
                    },
                },
                handler=self._handle_data_classify,
            ),
            _RegisteredMCPTool(
                name="data_extract_document_text",
                server="data_visual",
                description="Safely extract text from .pdf, .md, .txt, .json, or .csv without symlinks.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "doc_path": {"type": "string"},
                        "max_chars": {"type": "integer"},
                    },
                    "required": ["doc_path"],
                },
                handler=self._handle_data_extract_doc,
            ),
            _RegisteredMCPTool(
                name="data_synthesize_kaitai_ksy",
                server="data_visual",
                description="Synthesize and validate Kaitai Struct .ksy schema coverage.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "format_id": {"type": "string"},
                        "magic_hex": {"type": "string"},
                        "fields": {"type": "array"},
                        "sample_hex": {"type": "string"},
                    },
                    "required": ["format_id", "fields", "sample_hex"],
                },
                handler=self._handle_data_kaitai,
            ),
            _RegisteredMCPTool(
                name="data_ground_visual_observations",
                server="data_visual",
                description="Calibrate visual OCR bounding boxes and flag low-confidence zoom regions.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "regions": {"type": "array"},
                        "min_confidence": {"type": "number"},
                    },
                    "required": ["regions"],
                },
                handler=self._handle_data_visual_ground,
            ),
            _RegisteredMCPTool(
                name="data_inspect_image_artifact",
                server="data_visual",
                description="Inspect PNG/JPEG/GIF/WEBP dimensions and SHA-256 without symlinks.",
                input_schema={
                    "type": "object",
                    "properties": {"image_path": {"type": "string"}},
                    "required": ["image_path"],
                },
                handler=self._handle_data_inspect_image,
            ),
            _RegisteredMCPTool(
                name="vuln_audit_dependencies",
                server="vuln_intel",
                description="Correlate project dependencies against mirrored OSV/NVD/KEV/EPSS/CWE feeds.",
                input_schema={
                    "type": "object",
                    "properties": {"project_dir": {"type": "string"}},
                    "required": ["project_dir"],
                },
                handler=self._handle_vuln_audit,
            ),
            _RegisteredMCPTool(
                name="vuln_get_cwe_info",
                server="vuln_intel",
                description="Look up CWE metadata and mitigations from the local SQLite catalog.",
                input_schema={
                    "type": "object",
                    "properties": {"cwe_id": {"type": "string"}},
                    "required": ["cwe_id"],
                },
                handler=self._handle_vuln_cwe,
            ),
            _RegisteredMCPTool(
                name="vuln_mirror_stats",
                server="vuln_intel",
                description="Return row counts in the local offline vulnerability mirror.",
                input_schema={"type": "object", "properties": {}},
                handler=self._handle_vuln_stats,
            ),
            _RegisteredMCPTool(
                name="vuln_correlate_package",
                server="vuln_intel",
                description="Correlate a single package/version against local vulnerability records.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "package": {"type": "string"},
                        "version": {"type": "string"},
                        "ecosystem": {"type": "string"},
                    },
                    "required": ["package", "version"],
                },
                handler=self._handle_vuln_correlate,
            ),
            _RegisteredMCPTool(
                name="vuln_sync_live_feeds",
                server="vuln_intel",
                description="Clean-zone live sync of KEV/EPSS/OSV feeds (blocked when tainted).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "feeds": {"type": "array"},
                    },
                },
                handler=self._handle_vuln_sync_feeds,
                network_egress=True,
            ),
            _RegisteredMCPTool(
                name="forensics_scan_target",
                server="forensics",
                description="Execute non-fabricating iOS/Android/Host STIX2 spyware IOC triage.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target_dir": {"type": "string"},
                        "platform": {"type": "string"},
                    },
                    "required": ["target_dir"],
                },
                handler=self._handle_forensics_scan,
            ),
            _RegisteredMCPTool(
                name="code_index_file",
                server="code_graph",
                description="Incrementally index a source file into the SCIP/AST code graph.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"},
                        "source_code": {"type": "string"},
                    },
                    "required": ["file_path", "source_code"],
                },
                handler=self._handle_code_index,
            ),
            _RegisteredMCPTool(
                name="code_query_symbol",
                server="code_graph",
                description="Resolve symbol definitions and inverse callers from the code graph.",
                input_schema={
                    "type": "object",
                    "properties": {"symbol_name": {"type": "string"}},
                    "required": ["symbol_name"],
                },
                handler=self._handle_code_query,
            ),
            _RegisteredMCPTool(
                name="code_analyze_blast_radius",
                server="code_graph",
                description="Compute structural and git co-change blast radius for a target file.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target_file": {"type": "string"},
                        "min_cochanges": {"type": "integer"},
                    },
                    "required": ["target_file"],
                },
                handler=self._handle_code_blast,
            ),
            _RegisteredMCPTool(
                name="binrev_inspect_binary",
                server="binrev",
                description="Inspect binary container format, checksec flags, and prompt-injection strings.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "hex_bytes": {"type": "string"},
                        "utf8_text": {"type": "string"},
                        "artifact_name": {"type": "string"},
                    },
                },
                handler=self._handle_binrev_inspect,
            ),
            _RegisteredMCPTool(
                name="binrev_decompile_sk2",
                server="binrev",
                description="Execute Two-Phase SK2Decompile (Skeleton -> Skin) with ReCopilot context.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "raw_ghidra_pseudocode": {"type": "string"},
                        "callers": {"type": "array"},
                        "callees": {"type": "array"},
                        "dataflow_aliases": {"type": "object"},
                        "cross_ref_strings": {"type": "array"},
                    },
                    "required": ["raw_ghidra_pseudocode"],
                },
                handler=self._handle_binrev_decompile,
            ),
            _RegisteredMCPTool(
                name="cyber_scan_cpg_taint",
                server="defensive_cyber",
                description="Scan source code for CWE source-to-sink taint paths.",
                input_schema={
                    "type": "object",
                    "properties": {"source_code": {"type": "string"}},
                    "required": ["source_code"],
                },
                handler=self._handle_cyber_scan,
            ),
            _RegisteredMCPTool(
                name="cyber_verify_dual_gate_patch",
                server="defensive_cyber",
                description="Run SecVerifier Dual-Gate PoC + regression remediation verification.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "patched_source": {"type": "string"},
                        "poc_triggered_crash": {"type": "boolean"},
                        "regression_tests_passed": {"type": "integer"},
                        "regression_tests_total": {"type": "integer"},
                    },
                    "required": [
                        "patched_source",
                        "poc_triggered_crash",
                        "regression_tests_passed",
                        "regression_tests_total",
                    ],
                },
                handler=self._handle_cyber_verify_patch,
            ),
        ]
        registry: dict[str, _RegisteredMCPTool] = {}
        for spec in specs:
            if not spec.name.isidentifier():
                raise ValueError(f"MCP tool name must be a valid Python identifier: {spec.name!r}")
            props = spec.input_schema.get("properties", {})
            for param_name in props:
                if not str(param_name).isidentifier():
                    raise ValueError(
                        f"MCP parameter name must be a valid Python identifier: {param_name!r}"
                    )
            registry[spec.name] = spec
        return registry

    def _handle_data_classify(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        raw = self._decode_payload_bytes(args, hex_key="hex_data")
        return self._json_safe(self.data_visual_mcp.classify_transformation(raw))

    def _handle_data_extract_doc(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        max_chars = _require_strict_int(args.get("max_chars", 200_000), "max_chars", minimum=1)
        return self.data_visual_mcp.extract_document_text(str(args["doc_path"]), max_chars=max_chars)

    def _handle_data_kaitai(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        magic = bytes.fromhex(str(args.get("magic_hex", "")).strip())
        sample = bytes.fromhex(str(args["sample_hex"]).strip())
        return self.data_visual_mcp.synthesize_kaitai_struct_ksy(
            format_id=str(args["format_id"]),
            magic_bytes=magic,
            fields=list(args["fields"]),
            sample_payload=sample,
        )

    def _handle_data_visual_ground(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        return self.data_visual_mcp.ground_visual_observations(
            regions=list(args["regions"]),
            min_confidence=float(args.get("min_confidence", 0.80)),
        )

    def _handle_data_inspect_image(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        return self.data_visual_mcp.inspect_image_artifact(str(args["image_path"]))

    def _handle_vuln_audit(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        return self.vuln_intel_mcp.audit_project_dependencies(str(args["project_dir"]))

    def _handle_vuln_cwe(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        cwe_id = str(args["cwe_id"])
        return {"cwe_id": cwe_id, "record": self.vuln_intel_mcp.get_cwe_info(cwe_id)}

    def _handle_vuln_stats(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del args, session_tainted
        return self.vuln_intel_mcp.mirror_stats()

    def _handle_vuln_correlate(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        matches = self.vuln_intel_mcp.correlate_package(
            package=str(args["package"]),
            version=str(args["version"]),
            ecosystem=str(args.get("ecosystem", "PyPI")),
        )
        return {"matches": [m.to_dict() for m in matches], "count": len(matches)}

    def _handle_vuln_sync_feeds(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        feeds = [str(f) for f in args.get("feeds", ["kev", "epss"])]
        return self.vuln_intel_mcp.sync_live_feeds(feeds=feeds, session_tainted=session_tainted)

    def _handle_forensics_scan(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        assessment = self.forensics_mcp.analyze_forensic_target(
            target_dir=str(args["target_dir"]),
            platform=str(args.get("platform", "auto")),
            use_mvt_cli=False,
        )
        return assessment.to_dict()

    def _handle_code_index(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        return self.code_graph_mcp.index_file(
            file_path=str(args["file_path"]),
            source_code=str(args["source_code"]),
        )

    def _handle_code_query(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        return self.code_graph_mcp.query_symbol(str(args["symbol_name"]))

    def _handle_code_blast(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        min_co = _require_strict_int(args.get("min_cochanges", 1), "min_cochanges", minimum=1)
        return self.code_graph_mcp.analyze_blast_radius(
            target_file=str(args["target_file"]),
            min_cochanges=min_co,
        )

    def _handle_binrev_inspect(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        raw = self._decode_payload_bytes(args, hex_key="hex_bytes")
        return self.binrev_mcp.inspect_binary(
            raw,
            artifact_name=str(args.get("artifact_name", "sample.bin")),
        )

    def _handle_binrev_decompile(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        return self.binrev_mcp.run_two_phase_sk2_decompile(
            raw_ghidra_pseudocode=str(args["raw_ghidra_pseudocode"]),
            callers=list(args["callers"]) if args.get("callers") is not None else None,
            callees=list(args["callees"]) if args.get("callees") is not None else None,
            dataflow_aliases=(
                dict(args["dataflow_aliases"]) if args.get("dataflow_aliases") is not None else None
            ),
            cross_ref_strings=(
                list(args["cross_ref_strings"]) if args.get("cross_ref_strings") is not None else None
            ),
        )

    def _handle_cyber_scan(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        findings = self.defensive_cyber_mcp.scan_cpg_taint(str(args["source_code"]))
        return {"findings": [asdict(f) for f in findings], "count": len(findings)}

    def _handle_cyber_verify_patch(self, args: dict[str, Any], session_tainted: bool) -> dict[str, Any]:
        del session_tainted
        passed = _require_strict_int(args["regression_tests_passed"], "regression_tests_passed", minimum=0)
        total = _require_strict_int(args["regression_tests_total"], "regression_tests_total", minimum=0)
        return self.defensive_cyber_mcp.verify_dual_gate_patch(
            patched_source=str(args["patched_source"]),
            poc_triggered_crash=bool(args["poc_triggered_crash"]),
            regression_tests_passed=passed,
            regression_tests_total=total,
        )

    @classmethod
    def _validate_server_names(cls, server_names: list[str] | None) -> set[str]:
        if server_names is None:
            return set(cls.SUPPORTED_SERVERS)
        selected = {str(s).strip() for s in server_names}
        unknown = sorted(selected - cls.SUPPORTED_SERVERS)
        if unknown:
            raise ValueError(
                f"Unsupported MCP server(s): {unknown}. Supported: {sorted(cls.SUPPORTED_SERVERS)}"
            )
        return selected

    def list_tools(
        self,
        server_names: list[str] | None = None,
        session_tainted: bool = False,
    ) -> list[dict[str, Any]]:
        """List MCP tool schemas filtered by server selection and `TAINTED_UNTRUSTED` policy."""
        allowed_servers = self._validate_server_names(server_names)
        result: list[dict[str, Any]] = []
        for tool in self._tools.values():
            if tool.server not in allowed_servers:
                continue
            if session_tainted and (tool.network_egress or tool.admin_deploy):
                continue
            result.append(
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                    "server": tool.server,
                }
            )
        return result

    def dispatch_request(
        self,
        request: dict[str, Any],
        session_tainted: bool = False,
    ) -> dict[str, Any]:
        """Execute a single JSON-RPC 2.0 MCP request (`initialize`, `tools/list`, `tools/call`)."""
        if not isinstance(request, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: expected JSON object."},
            }

        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") if isinstance(request.get("params"), dict) else {}

        if not isinstance(method, str) or not method:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: missing string 'method'."},
            }

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "platform_core_mcp",
                        "version": "1.0.0",
                        "session_tainted": bool(session_tainted),
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method.startswith("notifications/"):
            return {"jsonrpc": "2.0", "id": req_id, "result": {"acknowledged": True}}

        if method == "tools/list":
            raw_servers = params.get("server_names")
            server_list = list(raw_servers) if isinstance(raw_servers, list) else None
            try:
                tools = self.list_tools(server_names=server_list, session_tainted=session_tainted)
            except ValueError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": str(exc)},
                }
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}

        if method == "tools/call":
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: missing tool 'name'."},
                }
            tool = self._tools.get(tool_name)
            if tool is None:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Unknown MCP tool '{tool_name}'."},
                }
            if session_tainted and (tool.network_egress or tool.admin_deploy):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": (
                            f"PermissionError: Tool '{tool_name}' is blocked in "
                            "TAINTED_UNTRUSTED session."
                        ),
                    },
                }
            raw_args = params.get("arguments")
            if raw_args is None:
                tool_args: dict[str, Any] = {}
            elif isinstance(raw_args, dict):
                tool_args = raw_args
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: 'arguments' must be an object."},
                }

            try:
                payload = tool.handler(tool_args, session_tainted)
            except PermissionError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32003, "message": f"PermissionError: {exc}"},
                }
            except (ValueError, KeyError, FileNotFoundError, TypeError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"{type(exc).__name__}: {exc}"},
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": f"{type(exc).__name__}: {exc}"},
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
                    "structuredContent": payload,
                    "isError": False,
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_stdio(
        self,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
        session_tainted: bool = False,
    ) -> int:
        """Serve newline-delimited JSON-RPC 2.0 MCP requests with bounded line reads."""
        in_stream = stdin if stdin is not None else sys.stdin
        out_stream = stdout if stdout is not None else sys.stdout
        processed = 0

        while True:
            line = in_stream.readline(MAX_JSONRPC_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_JSONRPC_LINE_BYTES and not line.endswith("\n"):
                # Drain oversized line in bounded chunks before returning invalid request error
                while True:
                    chunk = in_stream.readline(MAX_JSONRPC_LINE_BYTES)
                    if not chunk or chunk.endswith("\n"):
                        break
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32600,
                        "message": f"JSON-RPC request line exceeded {MAX_JSONRPC_LINE_BYTES} bytes.",
                    },
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()
                processed += 1
                continue

            stripped = line.strip()
            if not stripped:
                continue

            try:
                req = json.loads(stripped)
            except json.JSONDecodeError as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()
                processed += 1
                continue

            is_notification = (
                isinstance(req, dict)
                and req.get("id") is None
                and isinstance(req.get("method"), str)
                and req["method"].startswith("notifications/")
            )
            resp = self.dispatch_request(req, session_tainted=session_tainted)
            processed += 1
            if not is_notification:
                out_stream.write(json.dumps(resp) + "\n")
                out_stream.flush()

        return processed

    @staticmethod
    def build_mcp_stdio_config(
        server_names: list[str] | None = None,
        python_executable: str | None = None,
        name: str = "platform_core_mcp",
        enabled_tools: list[str] | None = None,
        session_tainted: bool = True,
    ) -> dict[str, Any]:
        """Build a `types.McpStdioServer`-compatible descriptor for `platform_core` MCP."""
        selected = sorted(AgyStdioMCPBridge._validate_server_names(server_names))
        args = ["-m", "platform_core.cli", "mcp-stdio-bridge"]
        if server_names is not None:
            args.extend(["--servers", *selected])
        if not session_tainted:
            args.append("--clean")

        if enabled_tools is None:
            with AgyStdioMCPBridge() as bridge:
                computed_tools = [
                    t["name"]
                    for t in bridge.list_tools(
                        server_names=selected if server_names is not None else None,
                        session_tainted=session_tainted,
                    )
                ]
        else:
            computed_tools = [
                str(t)
                for t in enabled_tools
                if not (session_tainted and str(t) in _TAINT_BLOCKED_TOOL_NAMES)
            ]

        return {
            "name": name,
            "command": python_executable or sys.executable,
            "args": args,
            "server_names": selected,
            "enabled_tools": computed_tools,
        }


class AgyLocalOrchestrator:
    """Orchestrates local AGY SDK agents (`LiteRT` / `LocalOpenAI`) or deterministic fallback."""

    def __init__(self, inference_backend: InferenceBackend | None = None) -> None:
        self.inference_backend = inference_backend

    @staticmethod
    def is_sdk_installed() -> bool:
        """Check dynamically whether `google.antigravity` is importable."""
        if "google.antigravity" in sys.modules:
            return True
        try:
            return importlib.util.find_spec("google.antigravity") is not None
        except (ModuleNotFoundError, ValueError):
            return False

    @staticmethod
    def build_default_subagent_specs() -> list[dict[str, Any]]:
        """Return default `platform_core` specialist subagent specs honoring SecVerifier."""
        return [
            {
                "name": "software_engineering",
                "description": "Code graph symbol analysis, blast-radius checks, and safe patching.",
                "agent_behavior": "AUTONOMOUS",
                "enabled_tools": [
                    "VIEW_FILE",
                    "code_index_file",
                    "code_query_symbol",
                    "code_analyze_blast_radius",
                ],
                "allowed_subagents": [],
                "can_mark_completed": False,
            },
            {
                "name": "defensive_cyber",
                "description": "CPG taint analysis, vulnerability correlation, and forensic IOC triage.",
                "agent_behavior": "AUTONOMOUS",
                "enabled_tools": [
                    "VIEW_FILE",
                    "cyber_scan_cpg_taint",
                    "vuln_audit_dependencies",
                    "forensics_scan_target",
                ],
                "allowed_subagents": [],
                "can_mark_completed": False,
            },
            {
                "name": "reverse_engineering",
                "description": "Binary container checksec audit and two-phase SK2Decompile recovery.",
                "agent_behavior": "AUTONOMOUS",
                "enabled_tools": [
                    "VIEW_FILE",
                    "binrev_inspect_binary",
                    "binrev_decompile_sk2",
                ],
                "allowed_subagents": [],
                "can_mark_completed": False,
            },
            {
                "name": "multimodal_data",
                "description": "Payload transformation taxonomy, Kaitai .ksy synthesis, and visual grounding.",
                "agent_behavior": "AUTONOMOUS",
                "enabled_tools": [
                    "VIEW_FILE",
                    "data_classify_transformation",
                    "data_synthesize_kaitai_ksy",
                    "data_ground_visual_observations",
                ],
                "allowed_subagents": [],
                "can_mark_completed": False,
            },
            {
                "name": "independent_verifier",
                "description": "Adversarial SecVerifier gate validating outputs prior to COMPLETED.",
                "agent_behavior": "AUTONOMOUS",
                "enabled_tools": [
                    "VIEW_FILE",
                    "cyber_verify_dual_gate_patch",
                ],
                "allowed_subagents": [],
                "can_mark_completed": True,
            },
        ]

    @staticmethod
    def _filter_mcp_server_dicts(
        raw_servers: tuple[dict[str, Any], ...],
        session_tainted: bool,
    ) -> list[dict[str, Any]]:
        if not raw_servers:
            return [AgyStdioMCPBridge.build_mcp_stdio_config(session_tainted=session_tainted)]

        filtered: list[dict[str, Any]] = []
        for idx, srv in enumerate(raw_servers):
            entry = dict(srv)
            entry.setdefault("name", f"mcp_server_{idx + 1}")
            has_enabled = entry.get("enabled_tools") is not None
            has_disabled = entry.get("disabled_tools") is not None
            if has_enabled and has_disabled:
                raise ValueError(
                    f"MCP server '{entry['name']}' cannot specify both 'enabled_tools' and 'disabled_tools'."
                )
            if session_tainted:
                if has_enabled:
                    entry["enabled_tools"] = [
                        str(t)
                        for t in entry["enabled_tools"]
                        if str(t) not in _TAINT_BLOCKED_TOOL_NAMES
                    ]
                else:
                    existing_disabled = list(entry.get("disabled_tools") or [])
                    for blocked in sorted(_TAINT_BLOCKED_TOOL_NAMES):
                        if blocked not in existing_disabled:
                            existing_disabled.append(blocked)
                    entry["disabled_tools"] = existing_disabled
            filtered.append(entry)
        return filtered

    @classmethod
    def _build_config_snapshot(cls, spec: AgyLocalAgentSpec) -> dict[str, Any]:
        effective_depth = min(
            _require_strict_int(spec.max_subagent_depth, "max_subagent_depth", minimum=0),
            MAX_SUBAGENT_DEPTH_CAP,
        )
        discovered_skills = AgySkillDiscovery.discover_skills(list(spec.skills_paths))
        mcp_configs = cls._filter_mcp_server_dicts(spec.mcp_servers, session_tainted=spec.session_tainted)

        if effective_depth == 0:
            subagents: list[dict[str, Any]] = []
        else:
            raw_subs = list(spec.subagents) if spec.subagents else cls.build_default_subagent_specs()
            subagents = []
            for sub in raw_subs:
                sub_copy = dict(sub)
                if spec.session_tainted and "enabled_tools" in sub_copy:
                    sub_copy["enabled_tools"] = [
                        str(t)
                        for t in sub_copy["enabled_tools"]
                        if str(t) not in _TAINT_BLOCKED_TOOL_NAMES
                    ]
                subagents.append(sub_copy)

        snapshot: dict[str, Any] = {
            "agent_name": spec.agent_name,
            "runtime_kind": spec.runtime_kind,
            "session_tainted": spec.session_tainted,
            "network_isolation": "internal_only" if spec.session_tainted else "clean_allowlist",
            "policy_mode": "deny_run_command_and_egress" if spec.session_tainted else "confirm_run_command",
            "skills_paths": [str(Path(p)) for p in spec.skills_paths],
            "discovered_skills": discovered_skills,
            "mcp_servers": mcp_configs,
            "subagents": subagents,
            "capabilities": {
                "enable_subagents": effective_depth > 0,
                "max_subagent_depth": effective_depth,
                "allowed_subagents": [str(s["name"]) for s in subagents],
            },
            "system_instructions": spec.system_instructions,
        }

        if spec.runtime_kind == "litert":
            if ".." in Path(spec.model_or_path).parts:
                raise PermissionError(f"Path traversal rejected in LiteRT model_path: {spec.model_or_path}")
            expanded_model_path = os.path.expanduser(spec.model_or_path)
            model_path_obj = Path(expanded_model_path)
            if model_path_obj.is_symlink():
                raise PermissionError(f"Symlinked LiteRT model_path rejected: {expanded_model_path}")
            snapshot["config_class"] = "LiteRTAgentConfig"
            snapshot["model_path"] = expanded_model_path
            snapshot["backend"] = spec.litert_backend
            snapshot["enable_speculative_decoding"] = bool(spec.enable_speculative_decoding)
        else:
            if not spec.base_url:
                raise ValueError("base_url is required when runtime_kind='local_openai'.")
            validated_url = _validate_loopback_or_url(spec.base_url, session_tainted=spec.session_tainted)
            snapshot["config_class"] = "LocalOpenAIAgentConfig"
            snapshot["model"] = spec.model_or_path
            snapshot["base_url"] = validated_url

        return snapshot

    def build_sdk_config(self, spec: AgyLocalAgentSpec) -> Any:
        """Build a live `google.antigravity` local config or structured dict snapshot if absent."""
        snapshot = self._build_config_snapshot(spec)
        if not self.is_sdk_installed():
            return snapshot

        from google.antigravity import (  # type: ignore[import-not-found]
            LiteRTAgentConfig,
            LocalOpenAIAgentConfig,
            types,
        )
        from google.antigravity.hooks import policy  # type: ignore[import-not-found]

        mcp_server_objs = []
        for srv in snapshot["mcp_servers"]:
            kwargs: dict[str, Any] = {
                "name": srv["name"],
                "command": srv["command"],
                "args": list(srv.get("args", [])),
            }
            if srv.get("enabled_tools") is not None:
                kwargs["enabled_tools"] = list(srv["enabled_tools"])
            elif srv.get("disabled_tools") is not None:
                kwargs["disabled_tools"] = list(srv["disabled_tools"])
            mcp_server_objs.append(types.McpStdioServer(**kwargs))

        subagent_objs = []
        for sub in snapshot["subagents"]:
            cap_kwargs: dict[str, Any] = {
                "agent_behavior": getattr(
                    types.AgentBehavior,
                    str(sub.get("agent_behavior", "AUTONOMOUS")).upper(),
                    types.AgentBehavior.AUTONOMOUS,
                )
            }
            if sub.get("enabled_tools"):
                cap_kwargs["enabled_tools"] = list(sub["enabled_tools"])
            if sub.get("allowed_subagents") is not None:
                cap_kwargs["allowed_subagents"] = list(sub["allowed_subagents"])
            subagent_objs.append(
                types.SubagentConfig(
                    name=str(sub["name"]),
                    description=str(sub.get("description", "")),
                    capabilities=types.SubagentCapabilities(**cap_kwargs),
                )
            )

        caps = types.CapabilitiesConfig(
            enable_subagents=snapshot["capabilities"]["enable_subagents"],
            max_subagent_depth=snapshot["capabilities"]["max_subagent_depth"],
            allowed_subagents=list(snapshot["capabilities"]["allowed_subagents"]),
        )

        policies: list[Any] = [policy.deny("run_command")] if spec.session_tainted else []
        for srv_obj in mcp_server_objs:
            policies.append(policy.allow(srv_obj))

        common_kwargs: dict[str, Any] = {
            "system_instructions": snapshot["system_instructions"],
            "skills_paths": list(snapshot["skills_paths"]),
            "mcp_servers": mcp_server_objs,
            "subagents": subagent_objs,
            "capabilities": caps,
        }
        if policies:
            common_kwargs["policies"] = policies

        if spec.runtime_kind == "litert":
            return LiteRTAgentConfig(
                model_path=snapshot["model_path"],
                backend=snapshot["backend"],
                enable_speculative_decoding=snapshot["enable_speculative_decoding"],
                **common_kwargs,
            )

        return LocalOpenAIAgentConfig(
            model=snapshot["model"],
            base_url=snapshot["base_url"],
            **common_kwargs,
        )

    @staticmethod
    def _run_coro_sync(coro: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()

    @staticmethod
    def _verify_with_independent_verifier(
        spec: AgyLocalAgentSpec,
        snapshot: dict[str, Any],
        platform_state: PlatformState,
        response_text: str,
        execution_backend: str,
    ) -> tuple[bool, PlatformState]:
        """Run `IndependentVerifierAgent` + `FirecrackerSandboxManager` SecVerifier gate."""
        taint_violated = False
        if spec.session_tainted:
            for srv in snapshot["mcp_servers"]:
                enabled = set(srv.get("enabled_tools") or [])
                if enabled & _TAINT_BLOCKED_TOOL_NAMES:
                    taint_violated = True
                    break
            if platform_state.taint_level != TaintLevel.TAINTED_UNTRUSTED:
                taint_violated = True

        has_non_empty_response = bool(response_text.strip())
        subtask = SubTask(
            subtask_id="agy-exec-1",
            title=f"Verify local AGY execution for {spec.agent_name}",
            domain="swe",
            assigned_agent=spec.agent_name,
            status=TaskStatus.AWAITING_VERIFICATION,
            scoped_tools=[
                str(t)
                for srv in snapshot["mcp_servers"]
                for t in (srv.get("enabled_tools") or [])
            ],
            candidate_output={
                "edit_applied": has_non_empty_response and not taint_violated,
                "edit_error": (
                    "Taint invariant violated."
                    if taint_violated
                    else ("Empty agent response." if not has_non_empty_response else None)
                ),
                "test_script": (
                    "with open('agent_response.txt', 'r', encoding='utf-8') as f:\n"
                    "    txt = f.read().strip()\n"
                    "assert len(txt) > 0, 'Agent response cannot be empty'\n"
                ),
            },
        )

        sandbox = FirecrackerSandboxManager()
        safe_vm_id = re.sub(r"[^A-Za-z0-9._-]+", "_", f"agy-{spec.agent_name}").strip("._-") or "agy-vm"
        sandbox.provision_microvm(
            vm_id=safe_vm_id,
            initial_files={"agent_response.txt": response_text},
            tainted=spec.session_tainted,
        )
        verifier = IndependentVerifierAgent()
        cyber_mcp = DefensiveCyberMCPServer()
        verify_result = verifier.verify_subtask(
            subtask=subtask,
            sandbox=sandbox,
            vm_id=safe_vm_id,
            cyber_mcp=cyber_mcp,
        )
        passed = bool(verify_result.get("passed", False)) and (
            subtask.status == TaskStatus.COMPLETED
        ) and (subtask.verified_by_agent == verifier.descriptor.agent_id)

        claims = [
            EpistemicClaim(
                claim_id="agy-config-taint",
                status=EpistemicStatus.FACT if not taint_violated else EpistemicStatus.UNCERTAIN,
                statement=(
                    f"Session taint={platform_state.taint_level.value}, "
                    f"skills={len(snapshot['discovered_skills'])}, "
                    f"mcp_servers={len(snapshot['mcp_servers'])}."
                ),
                evidence_refs=(safe_vm_id, verifier.descriptor.agent_id),
                confidence=1.0 if not taint_violated else 0.0,
                source_tool="agy_sdk_bridge",
                requires_human_verification=taint_violated,
            ),
            EpistemicClaim(
                claim_id="agy-model-output",
                status=EpistemicStatus.HYPOTHESIS if passed else EpistemicStatus.UNCERTAIN,
                statement=f"Model output generated via {execution_backend} ({len(response_text)} chars).",
                evidence_refs=("agent_response.txt",),
                confidence=0.85 if passed else 0.15,
                source_tool=execution_backend,
                requires_human_verification=not passed,
            ),
        ]
        platform_state.subtasks = [subtask]
        platform_state.epistemic_assessment = EpistemicAssessment.from_claims(claims)
        platform_state.status = TaskStatus.COMPLETED if passed else TaskStatus.VERIFIER_REJECTED
        return passed, platform_state

    def run_local_agent(
        self,
        spec: AgyLocalAgentSpec,
        prompt: str,
        force_fallback: bool = False,
    ) -> AgyExecutionResult:
        """Execute a local AGY SDK agent or zero-dependency fallback gated by `SecVerifier`."""
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string.")

        snapshot = self._build_config_snapshot(spec)
        sdk_available = self.is_sdk_installed()

        platform_state = PlatformState(
            session_id=f"agy-{spec.agent_name}",
            objective=prompt,
            task_domain="swe",
            taint_level=TaintLevel.TAINTED_UNTRUSTED if spec.session_tainted else TaintLevel.CLEAN,
            status=TaskStatus.AWAITING_VERIFICATION,
            has_untrusted_artifacts=spec.session_tainted,
        )

        if sdk_available and not force_fallback:
            from google.antigravity import Agent  # type: ignore[import-not-found]

            sdk_config = self.build_sdk_config(spec)

            async def _invoke_sdk() -> str:
                async with Agent(config=sdk_config) as agent:
                    resp = await agent.chat(prompt)
                    if hasattr(resp, "text"):
                        maybe_coro = resp.text()
                        if inspect.isawaitable(maybe_coro):
                            return str(await maybe_coro)
                        return str(maybe_coro)
                    return str(resp)

            response_text = str(self._run_coro_sync(_invoke_sdk()))
            execution_backend = "google_antigravity_sdk"
        else:
            backend = self.inference_backend or DeterministicMockBackend()
            skills_summary = ", ".join(s["name"] for s in snapshot["discovered_skills"]) or "none"
            subagent_names = ", ".join(s["name"] for s in snapshot["subagents"]) or "none"
            sys_msg = (
                spec.system_instructions
                or (
                    f"Local orchestrator '{spec.agent_name}' "
                    f"(runtime={spec.runtime_kind}, skills=[{skills_summary}], "
                    f"subagents=[{subagent_names}], taint={platform_state.taint_level.value})."
                )
            )
            model_id = snapshot.get("model_path") if spec.runtime_kind == "litert" else snapshot["model"]
            inf_resp = backend.generate(
                InferenceRequest(
                    model_id=str(model_id),
                    messages=(
                        ChatMessage(role="system", content=sys_msg),
                        ChatMessage(role="user", content=prompt),
                    ),
                )
            )
            response_text = inf_resp.content
            execution_backend = "stdlib_fallback"

        verified, final_state = self._verify_with_independent_verifier(
            spec=spec,
            snapshot=snapshot,
            platform_state=platform_state,
            response_text=response_text,
            execution_backend=execution_backend,
        )

        return AgyExecutionResult(
            agent_name=spec.agent_name,
            execution_backend=execution_backend,
            sdk_available=sdk_available,
            config_snapshot=snapshot,
            loaded_skills=tuple(s["name"] for s in snapshot["discovered_skills"]),
            bound_mcp_servers=tuple(str(s["name"]) for s in snapshot["mcp_servers"]),
            subagent_delegations=tuple(str(s["name"]) for s in snapshot["subagents"]),
            response_text=response_text,
            verified_by_independent_verifier=verified,
            status=final_state.status.value,
            taint_level=final_state.taint_level.value,
            epistemic_assessment=(
                final_state.epistemic_assessment.to_dict()
                if final_state.epistemic_assessment is not None
                else {}
            ),
        )
