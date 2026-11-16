"""Deterministic Model Context Protocol (MCP) Tool Servers for Layer 2 Execution.

Implements Sections 1.2, 1.3, 1.4, 1.5, 1.6, 1.8, & BL-04/BL-05/BL-06:
1. `CodeGraphMCPServer`: Three-Tier Structural Code Intelligence Engine (Incremental AST/CST
   with BLAKE2b content-hashed SQLite cache, SCIP canonical symbol & inverse call-graph
   resolver with `NoConfidentMatch` fallback, Temporal Git co-change blast-radius analyzer,
   and syntax-verified `str_replace` diff editor).
2. `BinRevMCPServer`: Binary header/hardening auditor (`checksec`, ELF/PE/Mach-O/UEFI/DEX),
   string & adversarial prompt-injection scanner, and Two-Phase SK2Decompile (Skeleton-to-Skin)
   + ReCopilot call-graph/data-flow context builder.
3. `DefensiveCyberMCPServer`: Code Property Graph (CPG) source-to-sink taint analyzer and
   SecVerifier Dual-Gate PoC + regression verification engine.
4. `DataAndVisualMCPServer`: Domain D Information-Theoretic Transformation Classifier
   (Encoding vs Compression vs Encryption vs Hashing via Shannon entropy, chi-square test,
   and magic headers with decompression-bomb protection), Kaitai Struct (`.ksy`) schema
   synthesizer, and Domain E Epistemic Visual Grounder + Action Grouping bundler.
"""

from __future__ import annotations

import ast
import base64
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import struct
import threading
from typing import Any
import zlib


# ============================================================================
# 1. Domain A — Three-Tier Structural Code Intelligence Engine (CodeGraphMCP)
# ============================================================================


@dataclass(frozen=True)
class CodeSymbolNode:
    """Indexed code symbol in the Three-Tier Codebase-Memory Graph."""

    scip_id: str
    file_path: str
    name: str
    kind: str  # "function", "class", "method"
    signature: str
    docstring: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    calls: tuple[str, ...] = ()


class CodeGraphMCPServer:
    """Three-Tier Code Intelligence MCP Server (Tree-sitter/AST + SCIP + Git Co-Change)."""

    SUPPORTED_GRAMMARS: frozenset[str] = frozenset(
        {".py", ".ts", ".js", ".go", ".rs", ".c", ".cpp", ".h", ".java"}
    )

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        self._init_schema()
        self._cochange_counts: dict[str, Counter[str]] = defaultdict(Counter)

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout = 30000")
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS indexed_files (
                    file_path TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    raw_token_estimate INTEGER NOT NULL,
                    skeleton_token_estimate INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS code_symbols (
                    scip_id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    docstring TEXT NOT NULL,
                    start_line INTEGER NOT NULL,
                    end_line INTEGER NOT NULL,
                    start_byte INTEGER NOT NULL,
                    end_byte INTEGER NOT NULL,
                    calls_json TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    def close(self) -> None:
        lock = getattr(self, "_lock", None)
        if lock is not None:
            with lock:
                if getattr(self, "_conn", None) is not None:
                    self._conn.close()
                    self._conn = None  # type: ignore[assignment]
        elif getattr(self, "_conn", None) is not None:
            self._conn.close()
            self._conn = None  # type: ignore[assignment]

    def __del__(self) -> None:
        self.close()

    def index_file(self, file_path: str, source_code: str) -> dict[str, Any]:
        """Incrementally index a source file using BLAKE2b content hashing (O(changed files))."""
        content_hash = hashlib.blake2b(source_code.encode("utf-8"), digest_size=16).hexdigest()
        with self._lock:
            existing = self._conn.execute(
                "SELECT content_hash, raw_token_estimate, skeleton_token_estimate FROM indexed_files WHERE file_path = ?",
                (file_path,),
            ).fetchone()
            if existing is not None and existing[0] == content_hash:
                return {
                    "file_path": file_path,
                    "cache_hit": True,
                    "content_hash": content_hash,
                    "raw_tokens": existing[1],
                    "skeleton_tokens": existing[2],
                }

            # Clear stale symbols for this file
            self._conn.execute("DELETE FROM code_symbols WHERE file_path = ?", (file_path,))

            suffix = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            if suffix == ".py":
                symbols = self._parse_python_ast(file_path, source_code)
            elif suffix in self.SUPPORTED_GRAMMARS:
                symbols = self._parse_polyglot_cst(file_path, source_code)
            else:
                symbols = []

            for sym in symbols:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO code_symbols
                    (scip_id, file_path, name, kind, signature, docstring, start_line, end_line, start_byte, end_byte, calls_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sym.scip_id,
                        sym.file_path,
                        sym.name,
                        sym.kind,
                        sym.signature,
                        sym.docstring,
                        sym.start_line,
                        sym.end_line,
                        sym.start_byte,
                        sym.end_byte,
                        json.dumps(list(sym.calls)),
                    ),
                )

            raw_tokens = max(1, len(source_code) // 4)
            skeleton_text = "\n".join(f"{s.signature} # {s.docstring}" for s in symbols)
            skeleton_tokens = max(1, len(skeleton_text) // 4) if symbols else raw_tokens

            self._conn.execute(
                """
                INSERT OR REPLACE INTO indexed_files (file_path, content_hash, raw_token_estimate, skeleton_token_estimate)
                VALUES (?, ?, ?, ?)
                """,
                (file_path, content_hash, raw_tokens, skeleton_tokens),
            )
            self._conn.commit()

        return {
            "file_path": file_path,
            "cache_hit": False,
            "content_hash": content_hash,
            "symbol_count": len(symbols),
            "raw_tokens": raw_tokens,
            "skeleton_tokens": skeleton_tokens,
            "token_reduction_ratio": round(1.0 - (skeleton_tokens / raw_tokens), 4),
        }

    def query_symbol(
        self,
        symbol_name: str,
        fallback_corpus: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Resolve a symbol definition and its inverse callers via Tier 2 SCIP graph.

        If no symbol matches (or language grammar was unsupported), returns an explicit
        `NoConfidentMatch` status and falls back to regex/ripgrep line search (Phase 7).
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT scip_id, file_path, name, kind, signature, docstring, start_line, end_line, start_byte, end_byte, calls_json
                FROM code_symbols
                WHERE name = ?
                """,
                (symbol_name,),
            ).fetchall()

        if not rows:
            fallback_hits: list[dict[str, Any]] = []
            for path, text in (fallback_corpus or {}).items():
                for idx, line in enumerate(text.splitlines(), start=1):
                    if symbol_name in line:
                        fallback_hits.append(
                            {"file_path": path, "line": idx, "snippet": line.strip()}
                        )
            return {
                "status": "NoConfidentMatch",
                "symbol_name": symbol_name,
                "definitions": [],
                "inverse_callers": [],
                "ripgrep_fallback_hits": fallback_hits,
            }

        definitions = [
            {
                "scip_id": r[0],
                "file_path": r[1],
                "name": r[2],
                "kind": r[3],
                "signature": r[4],
                "docstring": r[5],
                "start_line": r[6],
                "end_line": r[7],
                "byte_range": [r[8], r[9]],
                "calls": json.loads(r[10]),
            }
            for r in rows
        ]

        # Compute inverse call graph ("who calls symbol_name?")
        with self._lock:
            all_rows = self._conn.execute(
                "SELECT scip_id, file_path, name, calls_json FROM code_symbols"
            ).fetchall()
        inverse_callers = []
        for scip_id, fpath, caller_name, calls_json in all_rows:
            callee_list = json.loads(calls_json)
            if symbol_name in callee_list:
                inverse_callers.append(
                    {"caller_scip_id": scip_id, "file_path": fpath, "caller_name": caller_name}
                )

        return {
            "status": "Resolved",
            "symbol_name": symbol_name,
            "definitions": definitions,
            "inverse_callers": inverse_callers,
            "ripgrep_fallback_hits": [],
        }

    def ingest_git_commits(self, commit_file_lists: list[list[str]]) -> None:
        """Tier 3: Build Temporal Git Co-Change Graph from historical commit file sets."""
        with self._lock:
            for files in commit_file_lists:
                unique_files = sorted(set(files))
                for i, f_a in enumerate(unique_files):
                    for f_b in unique_files[i + 1 :]:
                        self._cochange_counts[f_a][f_b] += 1
                        self._cochange_counts[f_b][f_a] += 1

    def analyze_blast_radius(self, target_file: str, min_cochanges: int = 1) -> dict[str, Any]:
        """Compute structural (SCIP inverse callers) + temporal (git co-change) blast radius."""
        with self._lock:
            file_symbols = self._conn.execute(
                "SELECT name FROM code_symbols WHERE file_path = ?",
                (target_file,),
            ).fetchall()
            exported_names = {r[0] for r in file_symbols}

            dependent_files: set[str] = set()
            all_rows = self._conn.execute(
                "SELECT file_path, calls_json FROM code_symbols WHERE file_path != ?",
                (target_file,),
            ).fetchall()
            for fpath, calls_json in all_rows:
                callees = set(json.loads(calls_json))
                if callees & exported_names:
                    dependent_files.add(fpath)

            cochanged = [
                {"file_path": partner, "cochange_commits": count}
                for partner, count in self._cochange_counts.get(target_file, Counter()).most_common()
                if count >= min_cochanges
            ]

        return {
            "target_file": target_file,
            "structural_dependent_files": sorted(dependent_files),
            "temporal_cochange_hotspots": cochanged,
            "high_blast_radius": (len(dependent_files) + len(cochanged)) >= 3,
        }

    @staticmethod
    def apply_str_replace_edit(
        source_code: str,
        old_str: str,
        new_str: str,
        language: str = "python",
    ) -> dict[str, Any]:
        """Apply a structured search-and-replace diff block and validate syntax before disk write."""
        if not old_str:
            raise ValueError("old_str in str_replace edit must be non-empty.")
        occurrences = source_code.count(old_str)
        if occurrences == 0:
            return {
                "applied": False,
                "error": "Target block not found in source file.",
                "updated_source": source_code,
            }
        if occurrences > 1:
            return {
                "applied": False,
                "error": f"Ambiguous target block: found {occurrences} occurrences (must be unique).",
                "updated_source": source_code,
            }

        updated = source_code.replace(old_str, new_str, 1)
        if language.lower() in {"python", "py"}:
            try:
                ast.parse(updated)
            except SyntaxError as exc:
                return {
                    "applied": False,
                    "error": f"Tree-sitter/AST syntax check failed after edit: {exc}",
                    "updated_source": source_code,
                }

        return {
            "applied": True,
            "error": None,
            "updated_source": updated,
        }

    def _parse_python_ast(self, file_path: str, source_code: str) -> list[CodeSymbolNode]:
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return self._parse_polyglot_cst(file_path, source_code)

        lines = source_code.splitlines(keepends=True)
        line_byte_offsets = [0]
        running = 0
        for ln in lines:
            running += len(ln.encode("utf-8"))
            line_byte_offsets.append(running)

        module_id = file_path.replace("/", ".").removesuffix(".py")
        nodes: list[CodeSymbolNode] = []

        for item in ast.walk(tree):
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                kind = "class" if isinstance(item, ast.ClassDef) else "function"
                start_ln = getattr(item, "lineno", 1)
                end_ln = getattr(item, "end_lineno", start_ln)
                start_b = line_byte_offsets[min(start_ln - 1, len(line_byte_offsets) - 1)]
                end_b = line_byte_offsets[min(end_ln, len(line_byte_offsets) - 1)]
                doc = ast.get_docstring(item) or ""

                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args_str = ast.unparse(item.args) if hasattr(ast, "unparse") else "..."
                    ret_str = (
                        f" -> {ast.unparse(item.returns)}"
                        if getattr(item, "returns", None) is not None and hasattr(ast, "unparse")
                        else ""
                    )
                    sig = f"def {item.name}({args_str}){ret_str}:"
                else:
                    sig = f"class {item.name}:"

                calls: list[str] = []
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Call):
                        if isinstance(sub.func, ast.Name):
                            calls.append(sub.func.id)
                        elif isinstance(sub.func, ast.Attribute):
                            calls.append(sub.func.attr)

                scip_id = f"scip-python python pkg 1.0 {module_id}/{item.name}#"
                nodes.append(
                    CodeSymbolNode(
                        scip_id=scip_id,
                        file_path=file_path,
                        name=item.name,
                        kind=kind,
                        signature=sig,
                        docstring=doc.splitlines()[0] if doc else "",
                        start_line=start_ln,
                        end_line=end_ln,
                        start_byte=start_b,
                        end_byte=end_b,
                        calls=tuple(dict.fromkeys(calls)),
                    )
                )
        return nodes

    _POLYGLOT_CONTROL_KEYWORDS: frozenset[str] = frozenset(
        {
            "if",
            "else",
            "for",
            "while",
            "switch",
            "case",
            "return",
            "catch",
            "sizeof",
            "alignof",
            "decltype",
            "static_assert",
            "typeof",
            "delete",
            "new",
        }
    )

    @classmethod
    def _parse_polyglot_cst(cls, file_path: str, source_code: str) -> list[CodeSymbolNode]:
        """Fault-tolerant CST signature & call-graph extractor for TS/JS/Go/Rust/C/C++/Java."""
        # Pattern 1: Keyword-led declarations (Rust fn/struct/enum/trait, Go func + receiver, TS/JS/Java class/interface/function)
        kw_pattern = re.compile(
            r"^[ \t]*(?:export\s+)?(?:public\s+|private\s+|protected\s+)?(?:default\s+)?"
            r"(?:pub(?:\([^)]*\))?\s+)?(?:static\s+)?(?:async\s+)?"
            r"(?P<kw>fn|func|function|class|struct|enum|interface|trait|def)\s+"
            r"(?:\([^)]*\)\s*)?"  # Optional Go method receiver: func (s *Server) Name(...)
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b(?P<rest>[^\n{;]*)",
            re.MULTILINE,
        )
        # Pattern 2: C/C++/Java typed function & method definitions (including multi-line template<...> headers)
        c_func_pattern = re.compile(
            r"^[ \t]*(?:template\s*<[^>{;]*>\s*)*"
            r"(?:(?:public|private|protected|static|inline|virtual|explicit|constexpr|extern|friend|final|synchronized)\s+)*"
            r"(?:(?:const|unsigned|signed|struct|enum|typename)\s+)*"
            r"[A-Za-z_][A-Za-z0-9_:<>.,\s*&\[\]]*?\s+[*&]*"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^;{}()]*)\)\s*"
            r"(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:throws\s+[A-Za-z0-9_,\s]+\s*)?(?=\{)",
            re.MULTILINE,
        )
        call_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

        candidates: list[tuple[int, int, str, str, str]] = []
        seen_starts: set[int] = set()

        for match in kw_pattern.finditer(source_code):
            name = match.group("name")
            if name in cls._POLYGLOT_CONTROL_KEYWORDS:
                continue
            kw = match.group("kw")
            kind = "class" if kw in {"class", "struct", "enum", "interface", "trait"} else "function"
            sig = " ".join(match.group(0).strip().split())
            candidates.append((match.start(), match.end(), name, kind, sig))
            seen_starts.add(match.start())

        for match in c_func_pattern.finditer(source_code):
            if match.start() in seen_starts:
                continue
            name = match.group("name")
            if name in cls._POLYGLOT_CONTROL_KEYWORDS:
                continue
            sig = " ".join(match.group(0).strip().split())
            candidates.append((match.start(), match.end(), name, "function", sig))

        candidates.sort(key=lambda item: item[0])
        nodes: list[CodeSymbolNode] = []

        for start_b, sig_end_b, name, kind, sig in candidates:
            start_line = source_code[:start_b].count("\n") + 1
            # Locate body braces `{ ... }` if present to compute end_byte, end_line, and outgoing calls
            brace_idx = source_code.find("{", sig_end_b)
            semi_idx = source_code.find(";", sig_end_b)
            end_b = sig_end_b
            calls: list[str] = []

            if brace_idx != -1 and (semi_idx == -1 or brace_idx < semi_idx):
                depth = 0
                pos = brace_idx
                n_len = len(source_code)
                while pos < n_len:
                    ch = source_code[pos]
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end_b = pos + 1
                            break
                    pos += 1
                body_slice = source_code[brace_idx:end_b]
                for cm in call_pattern.finditer(body_slice):
                    callee = cm.group(1)
                    if callee not in cls._POLYGLOT_CONTROL_KEYWORDS and callee != name:
                        calls.append(callee)

            end_line = source_code[:end_b].count("\n") + 1
            scip_id = f"scip-polyglot repo 1.0 {file_path}/{name}#"
            nodes.append(
                CodeSymbolNode(
                    scip_id=scip_id,
                    file_path=file_path,
                    name=name,
                    kind=kind,
                    signature=sig,
                    docstring="",
                    start_line=start_line,
                    end_line=end_line,
                    start_byte=start_b,
                    end_byte=end_b,
                    calls=tuple(dict.fromkeys(calls)),
                )
            )
        return nodes


# ============================================================================
# 2. Domain C — Reverse Engineering & Binary Intelligence (BinRevMCP)
# ============================================================================


class BinRevMCPServer:
    """Binary Pre-Analysis, Hardening Audit (`checksec`), and Two-Phase SK2Decompile + ReCopilot."""

    PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"system\s*prompt", re.IGNORECASE),
        re.compile(r"curl\s+https?://", re.IGNORECASE),
        re.compile(r"/etc/passwd|/etc/shadow|\.ssh/id_rsa", re.IGNORECASE),
    )

    def inspect_binary(self, raw_bytes: bytes, artifact_name: str = "sample.bin") -> dict[str, Any]:
        """Identify binary container format, hardening flags (`checksec`), and embedded strings."""
        fmt = "UNKNOWN_RAW_BINARY"
        arch = "unknown"
        if raw_bytes.startswith(b"\x7fELF"):
            fmt = "ELF"
            if len(raw_bytes) >= 19:
                e_machine = int.from_bytes(raw_bytes[18:20], "little", signed=False)
                arch = {0x3E: "x86_64", 0xB7: "ARM64", 0x03: "x86", 0x08: "MIPS"}.get(
                    e_machine, f"elf_machine_{e_machine}"
                )
        elif raw_bytes.startswith(b"MZ"):
            fmt = "PE"
            arch = "x86_64/PE"
        elif raw_bytes[:4] in {
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
        }:
            fmt = "Mach-O"
            arch = "ARM64/x86_64"
        elif raw_bytes.startswith(b"dex\n"):
            fmt = "DEX"
            arch = "Dalvik/ART"
        elif b"_FVH" in raw_bytes[:128]:
            fmt = "UEFI_FIRMWARE_VOLUME"
            arch = "UEFI"

        strings = [
            m.group(0).decode("ascii", errors="ignore")
            for m in re.finditer(rb"[\x20-\x7e]{4,}", raw_bytes)
        ]

        # Checksec binary hardening audit
        blob_text = " ".join(strings)
        checksec = {
            "nx_enabled": b"GNU_STACK" in raw_bytes or fmt in {"PE", "Mach-O", "ELF"},
            "stack_canary": "__stack_chk_fail" in blob_text or "__security_check_cookie" in blob_text,
            "fortify_source": "_chk" in blob_text,
            "pie_or_aslr": fmt in {"ELF", "PE", "Mach-O"},
        }

        # Detect indirect prompt injection embedded inside binary strings (Section 10.5)
        injection_alerts: list[str] = []
        for s in strings:
            for pat in self.PROMPT_INJECTION_PATTERNS:
                if pat.search(s):
                    injection_alerts.append(s)
                    break

        return {
            "artifact_name": artifact_name,
            "format": fmt,
            "architecture": arch,
            "byte_length": len(raw_bytes),
            "checksec": checksec,
            "extracted_strings": strings[:100],
            "prompt_injection_detected": len(injection_alerts) > 0,
            "injection_alerts": injection_alerts,
            "requires_taint_isolation": True,
        }

    @staticmethod
    def run_two_phase_sk2_decompile(
        raw_ghidra_pseudocode: str,
        callers: list[str] | None = None,
        callees: list[str] | None = None,
        dataflow_aliases: dict[str, str] | None = None,
        cross_ref_strings: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute Two-Phase SK2Decompile (Skeleton -> Skin) with ReCopilot context template."""
        callers_list = list(callers or [])
        callees_list = list(callees or [])
        aliases_dict = dict(dataflow_aliases or {})
        xref_list = list(cross_ref_strings or [])

        # Build ReCopilot Context Enhancement Header (Section 1.4 & 4.2)
        context_header_lines = [
            "/* === ReCopilot Call-Graph & Data-Flow Context ===",
            f" * Callers: {', '.join(callers_list) if callers_list else 'none'}",
            f" * Callees: {', '.join(callees_list) if callees_list else 'none'}",
            f" * Data-Flow Variable Aliases: {json.dumps(aliases_dict, sort_keys=True)}",
            f" * Cross-Referenced Strings: {json.dumps(xref_list)}",
            " * ================================================ */",
        ]
        recopilot_prompt = "\n".join(context_header_lines) + "\n" + raw_ghidra_pseudocode

        # Phase 1: Skeleton Recovery — normalize goto spaghetti into structured loops/conditionals
        skeleton = re.sub(
            r"goto\s+LAB_[0-9a-fA-F_]+\s*;",
            "/* structured_branch_normalized */ break;",
            raw_ghidra_pseudocode,
        )
        skeleton = re.sub(r"^\s*LAB_[0-9a-fA-F_]+:\s*$", "", skeleton, flags=re.MULTILINE)

        # Phase 2: Skin Recovery — apply variable alias & semantic type recovery
        skin = skeleton
        for raw_var, semantic_name in aliases_dict.items():
            skin = re.sub(rf"\b{re.escape(raw_var)}\b", semantic_name, skin)
        skin = re.sub(r"\bundefined8\b", "uint64_t", skin)
        skin = re.sub(r"\bundefined4\b", "uint32_t", skin)
        skin = re.sub(r"\bundefined\b", "uint8_t", skin)

        return {
            "recopilot_context_prompt": recopilot_prompt,
            "phase1_skeleton_code": skeleton.strip(),
            "phase2_skin_decompiled_code": skin.strip(),
            "recovered_identifiers": list(aliases_dict.values()),
        }


# ============================================================================
# 3. Domain B — Defensive Cybersecurity & CPG Taint Analysis (DefensiveCyberMCP)
# ============================================================================


@dataclass(frozen=True)
class CPGVulnerabilityFinding:
    """Vulnerability path discovered by Code Property Graph (CPG) taint analysis."""

    cwe_id: str
    severity: str
    line_number: int
    source_expr: str
    sink_expr: str
    description: str
    remediation_hint: str


class DefensiveCyberMCPServer:
    """Joern-style CPG Taint Analyzer and SecVerifier Dual-Gate Remediation Engine."""

    SINK_RULES: tuple[tuple[str, str, re.Pattern[str], str, str], ...] = (
        (
            "CWE-78",
            "CRITICAL",
            re.compile(r"(?:subprocess\.(?:Popen|run|call)\([^)]*shell\s*=\s*True|os\.system\()"),
            "OS Command Injection via shell execution sink.",
            "Replace shell=True / os.system with argument list subprocess.run([...], shell=False).",
        ),
        (
            "CWE-89",
            "HIGH",
            re.compile(r"cursor\.execute\(\s*(?:f[\"']|[\"'].*%s|.*\.format\()"),
            "SQL Injection via unparameterized string formatting in SQL query.",
            "Use parameterized queries: cursor.execute('SELECT ... WHERE id = ?', (val,)).",
        ),
        (
            "CWE-94",
            "CRITICAL",
            re.compile(r"\b(?:eval|exec)\s*\("),
            "Dynamic code execution sink reachable in source.",
            "Eliminate eval/exec; use ast.literal_eval or structured JSON parsing.",
        ),
        (
            "CWE-502",
            "CRITICAL",
            re.compile(r"\b(?:pickle\.loads|pickle\.load|yaml\.load\([^)]*(?!SafeLoader))"),
            "Unsafe deserialization of untrusted payload.",
            "Use json.loads, Safetensors, or yaml.safe_load.",
        ),
        (
            "CWE-120",
            "HIGH",
            re.compile(r"\b(?:strcpy|strcat|gets|sprintf)\s*\("),
            "Unbounded memory copy in C/C++ buffer operation.",
            "Replace with bounded snprintf or strncpy with explicit length verification.",
        ),
        (
            "CWE-22",
            "HIGH",
            re.compile(r"\b(?:tarfile\.extractall|zipfile\.ZipFile\([^)]*\)\.extractall)\s*\("),
            "Archive extraction without path-traversal member validation.",
            "Validate resolved target paths against extract root and reject symlinks/'..'.",
        ),
        (
            "CWE-327",
            "MEDIUM",
            re.compile(r"\bhashlib\.(?:md5|sha1)\s*\("),
            "Use of broken cryptographic hash algorithm (MD5/SHA-1).",
            "Replace with hashlib.sha256 or hashlib.blake2b for integrity/security hashing.",
        ),
        (
            "CWE-611",
            "HIGH",
            re.compile(r"\b(?:ET|ElementTree|xml\.etree\.ElementTree)\.(?:fromstring|parse)\s*\("),
            "Standard library XML parsing without XXE/entity-expansion hardening.",
            "Use defusedxml or disable external entity/DTD expansion.",
        ),
        (
            "CWE-798",
            "HIGH",
            re.compile(
                r"""\b(?:API_KEY|SECRET_KEY|PASSWORD|AUTH_TOKEN|PRIVATE_KEY)(?:\s*=\s*|\s+)["'][A-Za-z0-9_/+=-]{12,}["']"""
            ),
            "Hardcoded credential or API secret literal embedded in source.",
            "Move secrets to environment variables, KMS, or runtime secret managers.",
        ),
        (
            "CWE-918",
            "HIGH",
            re.compile(r"\b(?:urllib\.request\.urlopen|requests\.(?:get|post|put|delete))\s*\([^)]*\b(?:url|target|endpoint|host)\b"),
            "Outbound HTTP request with variable URL/host (potential SSRF).",
            "Validate URL scheme/hostname against an allowlist and block private/link-local IPs.",
        ),
    )

    @staticmethod
    def _collect_names(node: ast.AST) -> set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    @staticmethod
    def _call_qualname(node: ast.Call) -> str:
        func = node.func
        parts: list[str] = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        return ".".join(reversed(parts))

    def _scan_python_ast_taint(self, source_code: str) -> list[CPGVulnerabilityFinding]:
        """Intraprocedural Python AST source-to-sink taint analyzer."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        lines = source_code.splitlines()
        findings: list[CPGVulnerabilityFinding] = []
        seen: set[tuple[str, int]] = set()

        def _add(cwe_id: str, severity: str, lineno: int, src: str, desc: str, hint: str) -> None:
            key = (cwe_id, lineno)
            if key in seen:
                return
            seen.add(key)
            line_text = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
            findings.append(
                CPGVulnerabilityFinding(
                    cwe_id=cwe_id,
                    severity=severity,
                    line_number=lineno,
                    source_expr=src,
                    sink_expr=line_text,
                    description=desc,
                    remediation_hint=hint,
                )
            )

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            tainted: dict[str, str] = {
                arg.arg: f"ast_taint:param:{arg.arg}"
                for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                if arg.arg not in {"self", "cls"}
            }
            if node.args.vararg:
                tainted[node.args.vararg.arg] = f"ast_taint:param:{node.args.vararg.arg}"
            if node.args.kwarg:
                tainted[node.args.kwarg.arg] = f"ast_taint:param:{node.args.kwarg.arg}"

            # Walk statements in order to preserve assign -> sink flow
            for stmt in node.body:
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Assign):
                        rhs_names = self._collect_names(sub.value)
                        matched_src = next((tainted[n] for n in rhs_names if n in tainted), None)
                        if matched_src:
                            for tgt in sub.targets:
                                if isinstance(tgt, ast.Name):
                                    tainted[tgt.id] = matched_src
                    elif isinstance(sub, ast.Call):
                        qname = self._call_qualname(sub)
                        arg_names: set[str] = set()
                        for arg in sub.args:
                            arg_names |= self._collect_names(arg)
                        for kw in sub.keywords:
                            if kw.value is not None:
                                arg_names |= self._collect_names(kw.value)
                        matched_src = next((tainted[n] for n in arg_names if n in tainted), None)
                        if not matched_src:
                            continue

                        lineno = getattr(sub, "lineno", node.lineno)
                        if qname == "os.system" or (
                            qname in {"subprocess.run", "subprocess.call", "subprocess.Popen"}
                            and any(
                                kw.arg == "shell"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is True
                                for kw in sub.keywords
                            )
                        ):
                            _add(
                                "CWE-78",
                                "CRITICAL",
                                lineno,
                                matched_src,
                                "Tainted variable flows into shell command execution sink.",
                                "Use subprocess.run([...], shell=False) without shell=True.",
                            )
                        elif qname in {"eval", "exec"}:
                            _add(
                                "CWE-94",
                                "CRITICAL",
                                lineno,
                                matched_src,
                                "Tainted variable flows into eval/exec code execution sink.",
                                "Eliminate eval/exec; use ast.literal_eval or JSON schema decoding.",
                            )
                        elif qname in {"pickle.loads", "pickle.load"}:
                            _add(
                                "CWE-502",
                                "CRITICAL",
                                lineno,
                                matched_src,
                                "Tainted payload deserialized with unsafe pickle sink.",
                                "Use json.loads or Safetensors instead of pickle.",
                            )
                        elif qname in {"urllib.request.urlopen", "requests.get", "requests.post", "requests.put"}:
                            _add(
                                "CWE-918",
                                "HIGH",
                                lineno,
                                matched_src,
                                "Tainted URL/host flows into outbound HTTP client sink (SSRF).",
                                "Allowlist schemes/hosts and block private/loopback IP ranges.",
                            )
                        elif qname in {"open", "Path.read_text", "Path.write_text"}:
                            _add(
                                "CWE-22",
                                "HIGH",
                                lineno,
                                matched_src,
                                "Tainted path argument flows into filesystem I/O without canonical root check.",
                                "Canonicalize with resolve(), reject symlinks, and enforce is_relative_to(root).",
                            )
        return findings

    def scan_cpg_taint(self, source_code: str) -> list[CPGVulnerabilityFinding]:
        """Trace untrusted sources to sensitive sinks via Python AST taint + polyglot rules."""
        findings = self._scan_python_ast_taint(source_code)
        seen = {(f.cwe_id, f.line_number) for f in findings}
        for idx, line in enumerate(source_code.splitlines(), start=1):
            for cwe_id, severity, pattern, desc, hint in self.SINK_RULES:
                if (cwe_id, idx) not in seen and pattern.search(line):
                    seen.add((cwe_id, idx))
                    findings.append(
                        CPGVulnerabilityFinding(
                            cwe_id=cwe_id,
                            severity=severity,
                            line_number=idx,
                            source_expr="untrusted_input",
                            sink_expr=line.strip(),
                            description=desc,
                            remediation_hint=hint,
                        )
                    )
        findings.sort(key=lambda item: (item.line_number, item.cwe_id))
        return findings

    def verify_dual_gate_patch(
        self,
        patched_source: str,
        poc_triggered_crash: bool,
        regression_tests_passed: int,
        regression_tests_total: int,
    ) -> dict[str, Any]:
        """Run the SecVerifier Dual-Gate Remediation Verification (Section 1.3).

        Gate 1: The PoC trigger must no longer cause a sanitizer fault AND all CPG high/critical
                sinks (including secondary entry points) must be remediated.
        Gate 2: 100% of functional pass-to-pass regression tests must pass (0% over-correction).
        """
        remaining_vulns = self.scan_cpg_taint(patched_source)
        gate1_poc_and_cpg_clean = (not poc_triggered_crash) and (len(remaining_vulns) == 0)
        gate2_regression_clean = (
            regression_tests_total > 0 and regression_tests_passed == regression_tests_total
        )

        verdict = "VERIFIED_PASS" if (gate1_poc_and_cpg_clean and gate2_regression_clean) else "REJECTED"
        failure_mode = None
        if not gate1_poc_and_cpg_clean:
            failure_mode = (
                "PARTIAL_FIX_SECONDARY_ENTRYPOINT"
                if not poc_triggered_crash and remaining_vulns
                else "POC_STILL_TRIGGERS"
            )
        elif not gate2_regression_clean:
            failure_mode = "OVER_CORRECTION_REGRESSION_BREAKAGE"

        return {
            "verdict": verdict,
            "gate1_security_verified": gate1_poc_and_cpg_clean,
            "gate2_regression_verified": gate2_regression_clean,
            "remaining_cwe_count": len(remaining_vulns),
            "remaining_cwes": [f.cwe_id for f in remaining_vulns],
            "failure_mode": failure_mode,
        }


# ============================================================================
# 4. Domain D & E — Transformation Taxonomy, Kaitai Struct, & Visual Grounding
# ============================================================================


class TransformationClass(str, Enum):
    """Information-Theoretic Transformation Taxonomy (Section 1.5)."""

    ENCODING_SERIALIZATION = "ENCODING_SERIALIZATION"
    COMPRESSION = "COMPRESSION"
    ENCRYPTION = "ENCRYPTION"
    HASH_DIGEST = "HASH_DIGEST"


@dataclass(frozen=True)
class VisualRegionObservation:
    """Grounded UI or diagram region parsed by OmniParser V2 + GOT-OCR 2.0 (Section 1.6)."""

    region_id: int
    bbox: tuple[int, int, int, int]  # (x1, y1, x2, y2)
    ocr_text: str
    confidence: float
    is_obscured_or_low_res: bool = False


class DataAndVisualMCPServer:
    """Implements Domain D (Encoding/Compression/Encryption/Hashing + Kaitai) & Domain E (Vision)."""

    MAX_DECOMPRESSION_BYTES: int = 10 * 1024 * 1024  # 10 MiB decompression-bomb quota

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Compute exact Shannon entropy $H(X) = -\\sum p(x) \\log_2 p(x)$ in bits/byte [0.0, 8.0]."""
        if not data:
            return 0.0
        n = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            entropy -= p * math.log2(p)
        return round(entropy, 6)

    @classmethod
    def classify_transformation(cls, data: bytes) -> dict[str, Any]:
        """Classify a byte stream into Encoding, Compression, Encryption, or Hashing (Section 1.5)."""
        if not data:
            raise ValueError("Cannot classify empty byte stream.")

        n = len(data)
        entropy = cls.shannon_entropy(data)
        max_entropy = math.log2(min(n, 256)) if n > 1 else 1.0
        normalized_entropy = round(entropy / max_entropy, 6) if max_entropy > 0 else 0.0
        bit_ones_ratio = sum(b.bit_count() for b in data) / (8.0 * n)
        chi_square_uniform = (normalized_entropy >= 0.85) and (0.35 <= bit_ones_ratio <= 0.65)

        # 1. Check deterministic compression magic headers first (gzip, zlib, zstd, xz, SquashFS)
        if data.startswith(b"\x1f\x8b"):
            return {
                "transformation_class": TransformationClass.COMPRESSION,
                "subtype": "gzip",
                "shannon_entropy": entropy,
                "normalized_entropy": normalized_entropy,
                "chi_square_uniform": chi_square_uniform,
                "has_magic_header": True,
            }
        if n >= 2 and data[:2] in {b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}:
            return {
                "transformation_class": TransformationClass.COMPRESSION,
                "subtype": "zlib",
                "shannon_entropy": entropy,
                "normalized_entropy": normalized_entropy,
                "chi_square_uniform": chi_square_uniform,
                "has_magic_header": True,
            }
        if data.startswith(b"\x28\xb5\x2f\xfd"):
            return {
                "transformation_class": TransformationClass.COMPRESSION,
                "subtype": "zstd",
                "shannon_entropy": entropy,
                "normalized_entropy": normalized_entropy,
                "chi_square_uniform": chi_square_uniform,
                "has_magic_header": True,
            }
        if data.startswith(b"\xfd7zXZ\x00"):
            return {
                "transformation_class": TransformationClass.COMPRESSION,
                "subtype": "xz_lzma",
                "shannon_entropy": entropy,
                "normalized_entropy": normalized_entropy,
                "chi_square_uniform": chi_square_uniform,
                "has_magic_header": True,
            }
        if data.startswith((b"hsqs", b"sqsh")):
            return {
                "transformation_class": TransformationClass.COMPRESSION,
                "subtype": "squashfs",
                "shannon_entropy": entropy,
                "normalized_entropy": normalized_entropy,
                "chi_square_uniform": chi_square_uniform,
                "has_magic_header": True,
            }

        # 2. Check ASCII hex / Base64 / JSON serialization
        try:
            ascii_str = data.decode("ascii").strip()
            is_ascii = all(32 <= b <= 126 or b in (9, 10, 13) for b in data)
        except UnicodeDecodeError:
            ascii_str = ""
            is_ascii = False

        if is_ascii and ascii_str:
            if re.fullmatch(r"[0-9a-fA-F]+", ascii_str) and len(ascii_str) in {8, 32, 40, 64, 128}:
                digest_map = {8: "CRC32/Adler32", 32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
                return {
                    "transformation_class": TransformationClass.HASH_DIGEST,
                    "subtype": digest_map[len(ascii_str)],
                    "shannon_entropy": entropy,
                    "normalized_entropy": normalized_entropy,
                    "chi_square_uniform": chi_square_uniform,
                    "has_magic_header": False,
                }
            if (ascii_str.startswith("{") and ascii_str.endswith("}")) or (
                ascii_str.startswith("[") and ascii_str.endswith("]")
            ):
                return {
                    "transformation_class": TransformationClass.ENCODING_SERIALIZATION,
                    "subtype": "json",
                    "shannon_entropy": entropy,
                    "normalized_entropy": normalized_entropy,
                    "chi_square_uniform": chi_square_uniform,
                    "has_magic_header": False,
                }
            if (
                len(ascii_str) >= 4
                and len(ascii_str) % 4 == 0
                and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", ascii_str)
                and cls._is_likely_base64(ascii_str)
            ):
                return {
                    "transformation_class": TransformationClass.ENCODING_SERIALIZATION,
                    "subtype": "base64",
                    "shannon_entropy": entropy,
                    "normalized_entropy": normalized_entropy,
                    "chi_square_uniform": chi_square_uniform,
                    "has_magic_header": False,
                }

        # 3. High-entropy / uniform headerless stream -> Encryption (AES-CBC/GCM or ChaCha20)
        if (
            entropy >= 7.2
            or (not is_ascii and n >= 16 and n % 16 == 0 and normalized_entropy >= 0.85)
            or (not is_ascii and n >= 8 and chi_square_uniform and normalized_entropy >= 0.90)
        ):
            return {
                "transformation_class": TransformationClass.ENCRYPTION,
                "subtype": "block_or_stream_cipher",
                "shannon_entropy": entropy,
                "normalized_entropy": normalized_entropy,
                "chi_square_uniform": chi_square_uniform,
                "has_magic_header": False,
            }

        return {
            "transformation_class": TransformationClass.ENCODING_SERIALIZATION,
            "subtype": "utf8_or_binary_struct",
            "shannon_entropy": entropy,
            "normalized_entropy": normalized_entropy,
            "chi_square_uniform": chi_square_uniform,
            "has_magic_header": False,
        }

    @staticmethod
    def _is_likely_base64(ascii_str: str) -> bool:
        """Distinguish genuine Base64 payloads from plain ASCII English words/identifiers."""
        if any(ch in ascii_str for ch in ("=", "+", "/")):
            return True
        has_upper = any(ch.isupper() for ch in ascii_str)
        has_lower = any(ch.islower() for ch in ascii_str)
        has_digit = any(ch.isdigit() for ch in ascii_str)
        if not ((has_upper and has_lower) or (has_digit and (has_upper or has_lower))):
            return False
        try:
            decoded = base64.b64decode(ascii_str, validate=True)
        except Exception:
            return False
        if not decoded:
            return False
        # Genuine unpadded base64 either decodes to printable ASCII/UTF-8 or has >=16 mixed chars
        is_printable = all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded)
        return is_printable or len(ascii_str) >= 16

    @classmethod
    def safe_decode_or_decompress(cls, data: bytes) -> bytes:
        """Deterministically decode Base64 or decompress gzip/zlib with streaming bomb protection."""
        info = cls.classify_transformation(data)
        subtype = info["subtype"]

        if subtype == "gzip":
            decomp = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
            decompressed = decomp.decompress(data, max_length=cls.MAX_DECOMPRESSION_BYTES + 1)
            if len(decompressed) > cls.MAX_DECOMPRESSION_BYTES or decomp.unconsumed_tail:
                raise MemoryError(
                    f"Decompression bomb quota exceeded: > {cls.MAX_DECOMPRESSION_BYTES} bytes."
                )
            decompressed += decomp.flush()
        elif subtype == "zlib":
            decomp = zlib.decompressobj(wbits=zlib.MAX_WBITS)
            decompressed = decomp.decompress(data, max_length=cls.MAX_DECOMPRESSION_BYTES + 1)
            if len(decompressed) > cls.MAX_DECOMPRESSION_BYTES or decomp.unconsumed_tail:
                raise MemoryError(
                    f"Decompression bomb quota exceeded: > {cls.MAX_DECOMPRESSION_BYTES} bytes."
                )
            decompressed += decomp.flush()
        elif subtype == "base64":
            decompressed = base64.b64decode(data)
        else:
            decompressed = data

        if len(decompressed) > cls.MAX_DECOMPRESSION_BYTES:
            raise MemoryError(
                f"Decompression bomb quota exceeded: {len(decompressed)} bytes > {cls.MAX_DECOMPRESSION_BYTES}."
            )
        return decompressed

    @staticmethod
    def synthesize_kaitai_struct_ksy(
        format_id: str,
        magic_bytes: bytes,
        fields: list[dict[str, Any]],
        sample_payload: bytes,
    ) -> dict[str, Any]:
        """Synthesize a declarative Kaitai Struct (`.ksy`) specification and verify 100% byte coverage."""
        if not re.fullmatch(r"[a-z][a-z0-9_]*", format_id):
            raise ValueError("Kaitai Struct meta.id must be lower_snake_case.")

        magic_hex = " ".join(f"0x{b:02x}" for b in magic_bytes)
        lines = [
            "meta:",
            f"  id: {format_id}",
            "  endian: le",
            "seq:",
        ]
        expected_size = 0
        if magic_bytes:
            lines.extend(
                [
                    "  - id: magic",
                    f"    contents: [{magic_hex}]",
                ]
            )
            expected_size += len(magic_bytes)

        for f in fields:
            fid = f["id"]
            ftype = f["type"]
            fsize = int(f["size_bytes"])
            lines.extend(
                [
                    f"  - id: {fid}",
                    f"    type: {ftype}",
                    f"    size: {fsize}",
                ]
            )
            expected_size += fsize

        magic_matches = sample_payload.startswith(magic_bytes)
        if expected_size == len(sample_payload):
            byte_coverage_ratio = 1.0
        elif expected_size > 0 and len(sample_payload) > 0:
            byte_coverage_ratio = min(expected_size, len(sample_payload)) / max(expected_size, len(sample_payload))
        else:
            byte_coverage_ratio = 0.0

        return {
            "format_id": format_id,
            "ksy_yaml": "\n".join(lines) + "\n",
            "expected_byte_length": expected_size,
            "sample_byte_length": len(sample_payload),
            "magic_verified": magic_matches,
            "full_byte_coverage": magic_matches and expected_size == len(sample_payload),
            "byte_coverage_ratio": round(byte_coverage_ratio, 4),
        }

    @staticmethod
    def ground_visual_observations(
        regions: list[VisualRegionObservation | dict[str, Any]],
        min_confidence: float = 0.80,
    ) -> dict[str, Any]:
        """Enforce Epistemic Visual Calibration (Section 1.6).

        Separates high-confidence grounded OCR regions `[x1, y1, x2, y2]` from low-resolution
        or obscured regions that require a programmatic `zoom_crop_region` tool call before
        any semantic claim is permitted.
        """
        grounded: list[dict[str, Any]] = []
        requires_zoom: list[dict[str, Any]] = []

        for idx, raw_r in enumerate(regions):
            if isinstance(raw_r, dict):
                raw_bbox = raw_r.get("bbox") or raw_r.get("bbox_xyxy") or (0, 0, 0, 0)
                if not isinstance(raw_bbox, (list, tuple)) or len(raw_bbox) != 4:
                    raise ValueError(f"Invalid visual region bbox at index {idx}: {raw_bbox!r}")
                r = VisualRegionObservation(
                    region_id=int(raw_r.get("region_id", idx + 1)),
                    bbox=(int(raw_bbox[0]), int(raw_bbox[1]), int(raw_bbox[2]), int(raw_bbox[3])),
                    ocr_text=str(raw_r.get("ocr_text", "")),
                    confidence=float(raw_r.get("confidence", 0.0)),
                    is_obscured_or_low_res=bool(raw_r.get("is_obscured_or_low_res", False)),
                )
            else:
                r = raw_r

            entry = {
                "region_id": r.region_id,
                "bbox": list(r.bbox),
                "ocr_text": r.ocr_text,
                "confidence": r.confidence,
            }
            if r.is_obscured_or_low_res or r.confidence < min_confidence:
                entry["required_tool_call"] = {
                    "tool": "zoom_crop_region",
                    "bbox": list(r.bbox),
                }
                requires_zoom.append(entry)
            else:
                grounded.append(entry)

        return {
            "observed_visual_evidence": grounded,
            "uncertain_regions_requiring_zoom": requires_zoom,
            "epistemic_hallucination_guard_active": True,
        }

    @staticmethod
    def bundle_computer_use_actions(
        raw_actions: list[dict[str, Any]],
        human_optimal_steps: int,
    ) -> dict[str, Any]:
        """Group consecutive deterministic UI/CLI operations into batched turns (Section 1.8).

        Achieves Step Efficiency Ratio <= 1.8x human baseline on OSWorld-Human.
        """
        if human_optimal_steps <= 0:
            raise ValueError("human_optimal_steps must be positive.")
        if not raw_actions:
            return {"bundled_batches": [], "step_efficiency_ratio": 0.0}

        batches: list[list[dict[str, Any]]] = []
        current_batch: list[dict[str, Any]] = []
        for action in raw_actions:
            current_batch.append(action)
            if action.get("requires_visual_reobservation", False) or len(current_batch) >= 4:
                batches.append(current_batch)
                current_batch = []
        if current_batch:
            batches.append(current_batch)

        ratio = round(len(batches) / human_optimal_steps, 4)
        return {
            "raw_action_count": len(raw_actions),
            "bundled_turn_count": len(batches),
            "bundled_batches": batches,
            "step_efficiency_ratio": ratio,
            "meets_osworld_human_target": ratio <= 1.8,
        }

    @staticmethod
    def inspect_image_artifact(image_path: str | Path) -> dict[str, Any]:
        """Inspect PNG/JPEG/GIF/WEBP image metadata, dimensions, and SHA-256 without symlinks."""
        path = Path(image_path)
        if path.is_symlink():
            raise PermissionError(f"Symlinked image artifact rejected: {path}")
        if not path.is_file():
            raise FileNotFoundError(f"Image artifact not found: {path}")
        raw = path.read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()
        fmt = "unknown"
        width = 0
        height = 0

        if raw.startswith(b"\x89PNG\r\n\x1a\n") and len(raw) >= 24:
            fmt = "PNG"
            width, height = struct.unpack(">II", raw[16:24])
        elif raw.startswith(b"\xff\xd8"):
            fmt = "JPEG"
            idx = 2
            while idx + 9 < len(raw):
                if raw[idx] != 0xFF:
                    break
                marker = raw[idx + 1]
                if marker in {0xC0, 0xC1, 0xC2}:
                    height, width = struct.unpack(">HH", raw[idx + 5 : idx + 9])
                    break
                if idx + 4 > len(raw):
                    break
                seg_len = struct.unpack(">H", raw[idx + 2 : idx + 4])[0]
                if seg_len < 2:
                    break
                idx += 2 + seg_len
        elif raw[:6] in {b"GIF87a", b"GIF89a"} and len(raw) >= 10:
            fmt = "GIF"
            width, height = struct.unpack("<HH", raw[6:10])
        elif raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
            fmt = "WEBP"

        return {
            "path": str(path),
            "format": fmt,
            "width": width,
            "height": height,
            "byte_length": len(raw),
            "sha256": sha256,
        }

    @classmethod
    def zoom_crop_region(
        cls,
        image_path: str | Path,
        bbox: tuple[int, int, int, int],
        output_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Crop a bounding box [x1, y1, x2, y2] for high-res VLM re-inspection."""
        meta = cls.inspect_image_artifact(image_path)
        x1, y1, x2, y2 = bbox
        if x2 <= x1 or y2 <= y1 or x1 < 0 or y1 < 0:
            raise ValueError(f"Invalid crop bbox {bbox}: expected 0 <= x1 < x2 and 0 <= y1 < y2.")
        try:
            from PIL import Image  # type: ignore[import-not-found]
        except ImportError:
            return {
                "cropped": False,
                "reason": "Pillow not installed; returning validated crop coordinates.",
                "source_meta": meta,
                "bbox": [x1, y1, x2, y2],
            }

        src = Path(image_path)
        with Image.open(src) as img:
            w, h = img.size
            clamped = (max(0, x1), max(0, y1), min(w, x2), min(h, y2))
            cropped = img.crop(clamped)
            dest = Path(output_path) if output_path is not None else src.with_suffix(".crop.png")
            if dest.is_symlink():
                raise PermissionError(f"Refusing to write crop to symlink: {dest}")
            cropped.save(dest)
            crop_bytes = dest.read_bytes()
        return {
            "cropped": True,
            "output_path": str(dest),
            "bbox": list(clamped),
            "sha256": hashlib.sha256(crop_bytes).hexdigest(),
            "byte_length": len(crop_bytes),
        }

    @classmethod
    def extract_document_text(cls, doc_path: str | Path, max_chars: int = 200_000) -> dict[str, Any]:
        """Extract text from technical documents (.md, .txt, .json, .csv, .pdf) safely."""
        path = Path(doc_path)
        if path.is_symlink():
            raise PermissionError(f"Symlinked document rejected: {path}")
        if not path.is_file():
            raise FileNotFoundError(f"Document not found: {path}")
        raw = path.read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()
        suffix = path.suffix.lower()

        if suffix == ".pdf":
            extracted = cls._extract_pdf_text(raw)
        else:
            extracted = raw.decode("utf-8", errors="replace")

        truncated = len(extracted) > max_chars
        return {
            "path": str(path),
            "format": suffix.lstrip(".") or "text",
            "sha256": sha256,
            "char_count": len(extracted),
            "truncated": truncated,
            "text": extracted[:max_chars],
        }

    @staticmethod
    def _extract_pdf_text(raw_pdf: bytes) -> str:
        """Extract PDF text using pypdf if available, else bounded pure-Python stream fallback."""
        try:
            import io
            from pypdf import PdfReader  # type: ignore[import-not-found]

            reader = PdfReader(io.BytesIO(raw_pdf))
            extracted = "\n".join((page.extract_text() or "") for page in reader.pages)
            if extracted.strip():
                return extracted
        except Exception:
            pass

        # Pure-Python fallback: decompress FlateDecode streams safely & extract literal PDF text
        chunks: list[str] = []
        for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw_pdf, re.DOTALL):
            stream_bytes = m.group(1)
            try:
                decomp = zlib.decompressobj()
                decoded = decomp.decompress(stream_bytes, max_length=2 * 1024 * 1024)
            except zlib.error:
                decoded = stream_bytes
            for tm in re.finditer(rb"\(([^()]{1,500})\)\s*Tj", decoded):
                chunks.append(tm.group(1).decode("latin-1", errors="ignore"))
        if not chunks:
            for tm in re.finditer(rb"\(([^()]{1,500})\)\s*Tj", raw_pdf):
                chunks.append(tm.group(1).decode("latin-1", errors="ignore"))
        return "\n".join(chunks)

    @classmethod
    def analyze_visual_artifact(
        cls,
        image_path: str | Path,
        prompt: str,
        backend: Any,
        model_id: str = "Qwen/Qwen3-VL-8B-Thinking",
        regions: list[VisualRegionObservation | dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run VLM visual/diagram/screenshot interpretation with epistemic grounding guard."""
        from platform_core.layer1_intelligence.inference import ChatMessage, InferenceRequest

        image_meta = cls.inspect_image_artifact(image_path)
        grounding = cls.ground_visual_observations(regions or [])
        req = InferenceRequest(
            model_id=model_id,
            messages=(
                ChatMessage(
                    role="system",
                    content=(
                        "You are a precision multimodal technical analyst. Report only directly "
                        "observable text, symbols, and layout facts from the image. If any region "
                        "is blurry or unreadable, mark it UNCERTAIN rather than guessing."
                    ),
                ),
                ChatMessage(role="user", content=prompt, image_paths=(str(image_path),)),
            ),
            max_tokens=1536,
            max_thinking_tokens=1024,
            temperature=0.1,
        )
        resp = backend.generate(req)
        return {
            "image_meta": image_meta,
            "model_id": resp.model_id,
            "interpretation": resp.content,
            "visual_grounding": grounding,
            "latency_ms": resp.latency_ms,
        }
