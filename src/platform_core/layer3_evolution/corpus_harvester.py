"""Layer 3 Corpus Harvester, PDF/Book Extractor, Rate-Limited Web Fetcher & Teacher Distiller.

Provides zero-dependency corpus acquisition and synthetic distillation into `HybridKnowledgeStore`
RAG and `TrainingTrajectoryRecord` JSONL datasets:
1. `PromptInjectionSanitizer`: Strips zero-width/control characters and redacts indirect prompt
   injection markers, chat delimiters, and shell exfiltration snippets.
2. `DomainChunker`: Splits technical books and web pages into overlapping chunks while preserving
   fenced code blocks.
3. `PDFBookExtractor`: Safely extracts `.pdf`, `.md`, `.txt`, and `.rst` documents with symlink
   rejection and path-traversal validation, delegating extraction to
   `DataAndVisualMCPServer.extract_document_text`.
4. `RateLimitedWebHarvester`: Enforces `CyberGymFirewall.evaluate_egress`, `session_tainted`
   lockdown, anti-SSRF IP blocking, `time.monotonic()` rate pacing, bounded streaming reads up to
   `MAX_RESPONSE_BYTES`, exponential backoff on HTTP 429/5xx, and `RateLimitError` on 429
   exhaustion.
5. `TeacherDistiller`: Distills harvested chunks using an `InferenceBackend` teacher gated by
   `LicenseComplianceAuditor` and `DatasetHygienePipeline`, exporting atomic JSONL.
6. `CorpusHarvesterPipeline`: End-to-end orchestrator into `HybridKnowledgeStore`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import time
from typing import TYPE_CHECKING, Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from platform_core.deploy_security.governance import (
    CyberGymFirewall,
    LicenseComplianceAuditor,
    LicenseVerdict,
)
from platform_core.data_ingestion.data_factory import (
    DatasetHygienePipeline,
    TrainingTrajectoryRecord,
)
from platform_core.layer3_evolution.memory import HybridKnowledgeStore

if TYPE_CHECKING:
    from platform_core.layer1_intelligence.inference import InferenceBackend


class RateLimitError(RuntimeError):
    """Raised when an upstream HTTP endpoint exceeds rate limits (HTTP 429)."""


@dataclass(frozen=True)
class HarvestedDocument:
    """Sanitized, chunked document harvested from a PDF/text book or web source."""

    doc_id: str
    source_uri: str
    source_type: str  # "pdf_book" | "web_page" | "local_code"
    domain: str
    title: str
    license_id: str
    sha256: str
    raw_char_count: int
    sanitized_text: str
    chunks: tuple[str, ...]
    injection_alerts: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HarvestReport:
    """Summary of a corpus harvesting and RAG ingestion run."""

    documents: tuple[HarvestedDocument, ...]
    total_chunks: int
    total_tokens_est: int
    rejected_sources: tuple[dict[str, str], ...]
    rag_ingestion_stats: dict[str, Any]


def _validate_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer, got {value!r}.")
    return value


def _validate_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer, got {value!r}.")
    return value


def _validate_positive_float(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or float(value) <= 0.0:
        raise ValueError(f"{field_name} must be a positive number, got {value!r}.")
    return float(value)


def _validate_safe_path(path: Path) -> None:
    """Reject '..' traversal components and symlinked target or ancestor directories."""
    if ".." in path.parts:
        raise PermissionError(f"Path traversal '..' rejected: {path}")
    if path.is_symlink():
        raise PermissionError(f"Symlinked path rejected: {path}")

    darwin_root_aliases = (
        {Path("/var"), Path("/tmp"), Path("/etc")} if sys.platform == "darwin" else set()
    )
    if path.is_absolute():
        for ancestor in path.parents:
            if ancestor == ancestor.parent:
                break
            if ancestor in darwin_root_aliases:
                continue
            if ancestor.is_symlink():
                raise PermissionError(f"Symlinked ancestor directory rejected: {ancestor}")
    else:
        cwd = Path.cwd().resolve()
        resolved = (cwd / path).resolve()
        if not resolved.is_relative_to(cwd):
            raise PermissionError(f"Relative path escapes working directory: {path}")
        cur = cwd
        for part in path.parts:
            cur = cur / part
            if cur.is_symlink():
                raise PermissionError(f"Symlinked ancestor directory rejected: {cur}")


class PromptInjectionSanitizer:
    """Strips invisible control characters and redacts indirect prompt-injection payloads."""

    _ZERO_WIDTH_AND_CONTROL_RE: re.Pattern[str] = re.compile(
        r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u00ad\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
    )

    INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"ignore\s+(?:all\s+|any\s+|the\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(
            r"disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions",
            re.IGNORECASE,
        ),
        re.compile(r"<\|(?:im_start|im_end|endoftext|system|assistant|user)\|>", re.IGNORECASE),
        re.compile(r"(?:^|\n)\s*#{1,6}\s*System\s*:", re.IGNORECASE),
        re.compile(r"system\s*:\s*override", re.IGNORECASE),
        re.compile(r"</?(?:system|instruction|tool_call|function_call)>", re.IGNORECASE),
        re.compile(
            r"(?:curl|wget)\s+[^\n]*\|\s*(?:ba|z)?sh\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:curl|wget)\s+[^\n]*(?:-d|--data(?:-binary)?|-F)\s+@?(?:/etc/passwd|~/\.ssh|\$\w+|\.env)",
            re.IGNORECASE,
        ),
        re.compile(r"bash\s+-i\s+>&\s+/dev/tcp/", re.IGNORECASE),
    )

    _ALERT_LABELS: tuple[str, ...] = (
        "ignore_previous_instructions",
        "disregard_previous_instructions",
        "chat_template_delimiter",
        "markdown_system_header",
        "system_override_directive",
        "xml_control_tag",
        "shell_pipe_execution",
        "shell_exfil_upload",
        "reverse_shell_snippet",
    )

    @classmethod
    def sanitize(cls, text: str) -> tuple[str, tuple[str, ...]]:
        """Return sanitized text and a tuple of triggered sanitization alert codes."""
        if not text:
            return "", ()

        alerts: list[str] = []
        cleaned = text.replace("\r\n", "\n").replace("\r", "\n")

        stripped, ctrl_count = cls._ZERO_WIDTH_AND_CONTROL_RE.subn("", cleaned)
        if ctrl_count > 0:
            alerts.append(f"stripped_control_chars:{ctrl_count}")
        cleaned = stripped

        for pattern, label in zip(cls.INJECTION_PATTERNS, cls._ALERT_LABELS):
            cleaned, match_count = pattern.subn("[REDACTED_PROMPT_INJECTION]", cleaned)
            if match_count > 0:
                alerts.append(f"redacted:{label}:{match_count}")

        return cleaned, tuple(alerts)


class DomainChunker:
    """Splits sanitized corpus text into overlapping chunks preserving fenced code blocks."""

    _FENCE_SPLIT_RE: re.Pattern[str] = re.compile(r"(```[\s\S]*?```|~~~[\s\S]*?~~~)")

    @classmethod
    def chunk_text(
        cls,
        text: str,
        chunk_chars: int = 2400,
        overlap_chars: int = 300,
        preserve_code_blocks: bool = True,
    ) -> list[str]:
        """Chunk `text` into bounded strings, keeping fenced code blocks intact when possible."""
        chunk_chars = _validate_positive_int(chunk_chars, "chunk_chars")
        overlap_chars = _validate_non_negative_int(overlap_chars, "overlap_chars")
        if overlap_chars >= chunk_chars:
            raise ValueError(
                f"overlap_chars ({overlap_chars}) must be smaller than chunk_chars ({chunk_chars})."
            )

        stripped = text.strip()
        if not stripped:
            return []
        if len(stripped) <= chunk_chars:
            return [stripped]

        if not preserve_code_blocks:
            return cls._sliding_window(stripped, chunk_chars, overlap_chars)

        segments = cls._split_into_segments(stripped, chunk_chars)
        chunks: list[str] = []
        current = ""

        for seg in segments:
            if not seg:
                continue
            if not current:
                current = seg
                continue
            candidate = f"{current}\n\n{seg}"
            if len(candidate) <= chunk_chars:
                current = candidate
                continue

            chunks.append(current.strip())
            overlap = cls._safe_overlap(current, overlap_chars)
            if overlap and len(overlap) + 2 + len(seg) <= chunk_chars:
                current = f"{overlap}\n\n{seg}"
            else:
                current = seg

        if current.strip():
            chunks.append(current.strip())
        return chunks

    @classmethod
    def _split_into_segments(cls, text: str, max_segment_chars: int) -> list[str]:
        segments: list[str] = []
        for part in cls._FENCE_SPLIT_RE.split(text):
            if not part or not part.strip():
                continue
            is_fenced = part.startswith("```") or part.startswith("~~~")
            if is_fenced:
                if len(part) <= max_segment_chars:
                    segments.append(part.strip())
                else:
                    segments.extend(cls._split_oversized_block(part, max_segment_chars))
            else:
                for para in re.split(r"\n{2,}", part):
                    para_clean = para.strip()
                    if not para_clean:
                        continue
                    if len(para_clean) <= max_segment_chars:
                        segments.append(para_clean)
                    else:
                        segments.extend(cls._split_oversized_block(para_clean, max_segment_chars))
        return segments

    @staticmethod
    def _split_oversized_block(block: str, max_chars: int) -> list[str]:
        lines = block.splitlines(keepends=True)
        out: list[str] = []
        buf = ""
        for line in lines:
            if len(line) > max_chars:
                if buf.strip():
                    out.append(buf.strip())
                    buf = ""
                for idx in range(0, len(line), max_chars):
                    piece = line[idx : idx + max_chars].strip()
                    if piece:
                        out.append(piece)
                continue
            if len(buf) + len(line) <= max_chars:
                buf += line
            else:
                if buf.strip():
                    out.append(buf.strip())
                buf = line
        if buf.strip():
            out.append(buf.strip())
        return out

    @staticmethod
    def _safe_overlap(previous_chunk: str, overlap_chars: int) -> str:
        if overlap_chars <= 0 or not previous_chunk:
            return ""
        tail = previous_chunk[-overlap_chars:].lstrip()
        # Avoid carrying over an unbalanced code fence into the next chunk
        if tail.count("```") % 2 == 1:
            last_fence = tail.rfind("```")
            tail = tail[last_fence + 3 :].lstrip()
        if tail.count("~~~") % 2 == 1:
            last_tilde = tail.rfind("~~~")
            tail = tail[last_tilde + 3 :].lstrip()
        return tail

    @staticmethod
    def _sliding_window(text: str, chunk_chars: int, overlap_chars: int) -> list[str]:
        step = max(1, chunk_chars - overlap_chars)
        chunks: list[str] = []
        for offset in range(0, len(text), step):
            piece = text[offset : offset + chunk_chars].strip()
            if piece:
                chunks.append(piece)
            if offset + chunk_chars >= len(text):
                break
        return chunks


class PDFBookExtractor:
    """Safely extracts and chunks local technical books (`.pdf`, `.md`, `.txt`, `.rst`)."""

    SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({".pdf", ".md", ".txt", ".rst"})

    def __init__(self, chunk_chars: int = 2400, overlap_chars: int = 300) -> None:
        self.chunk_chars = _validate_positive_int(chunk_chars, "chunk_chars")
        self.overlap_chars = _validate_non_negative_int(overlap_chars, "overlap_chars")
        if self.overlap_chars >= self.chunk_chars:
            raise ValueError("overlap_chars must be smaller than chunk_chars.")

    def extract_book(
        self,
        path: str | Path,
        domain: str = "swe",
        license_id: str = "Apache-2.0",
        max_chars: int = 2_000_000,
    ) -> HarvestedDocument:
        """Extract, sanitize, and chunk a single book or technical document."""
        max_chars = _validate_positive_int(max_chars, "max_chars")
        book_path = Path(path)
        _validate_safe_path(book_path)
        if not book_path.is_file():
            raise FileNotFoundError(f"Book file not found: {book_path}")

        suffix = book_path.suffix.lower()
        if suffix not in self.SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported book extension '{suffix}' for {book_path}. "
                f"Supported: {sorted(self.SUPPORTED_EXTENSIONS)}"
            )

        from platform_core.layer2_execution.mcp_tools import DataAndVisualMCPServer

        extracted = DataAndVisualMCPServer.extract_document_text(book_path, max_chars=max_chars)
        raw_text = str(extracted.get("text", ""))
        sha256 = str(extracted.get("sha256", ""))
        sanitized_text, alerts = PromptInjectionSanitizer.sanitize(raw_text)
        chunks = tuple(
            DomainChunker.chunk_text(
                sanitized_text,
                chunk_chars=self.chunk_chars,
                overlap_chars=self.overlap_chars,
                preserve_code_blocks=True,
            )
        )

        resolved_path = book_path.resolve()
        return HarvestedDocument(
            doc_id=f"book-{sha256[:12]}",
            source_uri=resolved_path.as_uri(),
            source_type="pdf_book",
            domain=domain.strip() or "swe",
            title=book_path.stem,
            license_id=license_id.strip(),
            sha256=sha256,
            raw_char_count=int(extracted.get("char_count", len(raw_text))),
            sanitized_text=sanitized_text,
            chunks=chunks,
            injection_alerts=alerts,
            metadata={
                "file_name": book_path.name,
                "format": str(extracted.get("format", suffix.lstrip("."))),
                "truncated": bool(extracted.get("truncated", False)),
            },
        )

    def extract_directory(
        self,
        root_dir: str | Path,
        domain: str = "swe",
        license_id: str = "Apache-2.0",
        max_files: int = 50,
    ) -> list[HarvestedDocument]:
        """Recursively extract non-symlink books inside `root_dir` without path escape."""
        max_files = _validate_positive_int(max_files, "max_files")
        root = Path(root_dir)
        if root.is_symlink():
            raise PermissionError(f"Symlinked directory rejected: {root}")
        if not root.is_dir():
            raise FileNotFoundError(f"Directory not found: {root}")

        resolved_root = root.resolve()
        documents: list[HarvestedDocument] = []

        for candidate in sorted(root.rglob("*")):
            if len(documents) >= max_files:
                break
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                rel_parts = candidate.relative_to(root).parts
            except ValueError:
                continue
            if any(part.startswith(".") or part == "__pycache__" for part in rel_parts):
                continue
            if self._has_symlink_component(root, candidate):
                continue
            if not candidate.resolve().is_relative_to(resolved_root):
                continue
            if candidate.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
                continue

            documents.append(
                self.extract_book(candidate, domain=domain, license_id=license_id)
            )

        return documents

    @staticmethod
    def _has_symlink_component(root: Path, candidate: Path) -> bool:
        current = candidate
        while current != root and current != current.parent:
            if current.is_symlink():
                return True
            current = current.parent
        return False


class _HTMLTextExtractor(HTMLParser):
    """Stdlib HTML-to-text extractor that drops `<script>`, `<style>`, and `<noscript>` blocks."""

    _SKIP_TAGS: frozenset[str] = frozenset({"script", "style", "noscript", "svg"})
    _BLOCK_TAGS: frozenset[str] = frozenset(
        {"p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "section", "article", "tr"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._skip_depth = 0
        self._in_title = False
        self._title_parts: list[str] = []
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower = tag.lower()
        if lower in self._SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth > 0:
            return
        if lower == "title":
            self._in_title = True
        elif lower in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lower = tag.lower()
        if lower in self._SKIP_TAGS:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if self._skip_depth > 0:
            return
        if lower == "title":
            self._in_title = False
        elif lower in self._BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        unescaped = html.unescape(data)
        if self._in_title:
            self._title_parts.append(unescaped)
        self._parts.append(unescaped)

    def handle_entityref(self, name: str) -> None:
        self.handle_data(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.handle_data(f"&#{name};")

    def get_title(self) -> str:
        return " ".join("".join(self._title_parts).split()).strip()

    def get_text(self) -> str:
        raw = "".join(self._parts)
        lines = [line.rstrip() for line in raw.splitlines()]
        collapsed = "\n".join(lines)
        return re.sub(r"\n{3,}", "\n\n", collapsed).strip()


class _FirewallRedirectHandler(HTTPRedirectHandler):
    """Validates HTTP redirect targets against `CyberGymFirewall` before following."""

    def __init__(self, firewall: CyberGymFirewall, session_tainted: bool) -> None:
        self._firewall = firewall
        self._session_tainted = session_tainted

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        decision = self._firewall.evaluate_egress(newurl, session_tainted=self._session_tainted)
        if not decision.allowed:
            raise PermissionError(f"Redirect blocked by CyberGymFirewall: {decision.reason}")
        RateLimitedWebHarvester._verify_resolved_host_not_private(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RateLimitedWebHarvester:
    """Firewall-gated, rate-limited HTTP/HTTPS corpus harvester with bounded reads."""

    DEFAULT_REQUESTS_PER_SECOND: float = 1.0
    MAX_RESPONSE_BYTES: int = 5 * 1024 * 1024

    def __init__(
        self,
        allowed_domains: set[str] | frozenset[str] | None = None,
        requests_per_second: float = 1.0,
        max_retries: int = 3,
        timeout_sec: float = 20.0,
        session_tainted: bool = False,
        opener: Callable[..., Any] | None = None,
        chunk_chars: int = 2400,
        overlap_chars: int = 300,
    ) -> None:
        self.requests_per_second = _validate_positive_float(
            requests_per_second, "requests_per_second"
        )
        self.max_retries = _validate_positive_int(max_retries, "max_retries")
        self.timeout_sec = _validate_positive_float(timeout_sec, "timeout_sec")
        self.session_tainted = bool(session_tainted)
        self.firewall = CyberGymFirewall(allowed_domains=allowed_domains)
        self._opener = opener
        self._min_interval = 1.0 / self.requests_per_second
        self._last_request_time: float | None = None
        self.chunk_chars = _validate_positive_int(chunk_chars, "chunk_chars")
        self.overlap_chars = _validate_non_negative_int(overlap_chars, "overlap_chars")
        if self.overlap_chars >= self.chunk_chars:
            raise ValueError("overlap_chars must be smaller than chunk_chars.")

    def _wait_for_rate_limit(self) -> None:
        if self._last_request_time is None:
            return
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)

    @staticmethod
    def _verify_resolved_host_not_private(url: str) -> None:
        """Reject DNS resolutions pointing to loopback, private, link-local, or reserved IPs."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip()
        if not host:
            return
        try:
            addr_infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return
        for info in addr_infos:
            ip_str = str(info[4][0]).split("%", 1)[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            ):
                raise PermissionError(
                    f"Blocked: Host '{host}' resolved to non-public IP '{ip_obj}' (anti-SSRF)."
                )

    def _default_open(self, req: Request, timeout: float) -> Any:
        opener = build_opener(_FirewallRedirectHandler(self.firewall, self.session_tainted))
        return opener.open(req, timeout=timeout)

    def _read_bounded_bytes(self, resp: Any) -> bytes:
        chunks: list[bytes] = []
        total = 0
        chunk_size = 65536
        while True:
            try:
                chunk = resp.read(chunk_size)
            except TypeError:
                # Support minimal mock response objects exposing zero-arg .read()
                chunk = resp.read()
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                total += len(chunk)
                if total > self.MAX_RESPONSE_BYTES:
                    raise ValueError(
                        f"Response exceeded MAX_RESPONSE_BYTES ({self.MAX_RESPONSE_BYTES} bytes)."
                    )
                chunks.append(chunk)
                break
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            total += len(chunk)
            if total > self.MAX_RESPONSE_BYTES:
                raise ValueError(
                    f"Response exceeded MAX_RESPONSE_BYTES ({self.MAX_RESPONSE_BYTES} bytes)."
                )
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _extract_response_content_type(resp: Any) -> str:
        headers = getattr(resp, "headers", None)
        if headers is None:
            return ""
        if hasattr(headers, "get"):
            return str(headers.get("Content-Type", "")).lower()
        return ""

    @staticmethod
    def _looks_like_html(text: str, content_type: str) -> bool:
        if "html" in content_type or "xhtml" in content_type:
            return True
        snippet = text[:2048].lower()
        return any(
            marker in snippet
            for marker in ("<!doctype html", "<html", "<head", "<body", "<script", "<div", "<p>")
        )

    def fetch_url(
        self,
        url: str,
        domain: str = "cyber",
        license_id: str = "Apache-2.0",
    ) -> HarvestedDocument:
        """Fetch, strip HTML/JS, sanitize, and chunk a firewall-approved URL."""
        decision = self.firewall.evaluate_egress(url, session_tainted=self.session_tainted)
        if not decision.allowed:
            raise PermissionError(decision.reason)

        if self._opener is None:
            self._verify_resolved_host_not_private(url)

        opener_fn = self._opener if self._opener is not None else self._default_open
        raw_bytes = b""
        content_type = ""

        last_backoff = 0.0
        for attempt in range(self.max_retries):
            if attempt == 0 or last_backoff < self._min_interval:
                self._wait_for_rate_limit()
            req = Request(
                url,
                headers={
                    "User-Agent": "platform-core-corpus-harvester/1.0",
                    "Accept": "text/html, text/plain, text/markdown, application/json",
                },
                method="GET",
            )
            try:
                with opener_fn(req, timeout=self.timeout_sec) as resp:
                    self._last_request_time = time.monotonic()
                    content_type = self._extract_response_content_type(resp)
                    raw_bytes = self._read_bounded_bytes(resp)
                break
            except HTTPError as exc:
                try:
                    if exc.code == 429:
                        wait = 2**attempt
                        print(
                            f"Rate limited (429) for {url}, retrying in {wait}s "
                            f"(attempt {attempt + 1}/{self.max_retries})...",
                            file=sys.stderr,
                        )
                        if attempt == self.max_retries - 1:
                            self._last_request_time = time.monotonic()
                            raise RateLimitError(
                                f"HTTP 429 Too Many Requests from {url} after {self.max_retries} retries."
                            ) from exc
                        time.sleep(wait)
                        last_backoff = float(wait)
                        self._last_request_time = time.monotonic()
                        continue
                    if exc.code >= 500:
                        wait = 2**attempt
                        print(
                            f"Server error {exc.code} for {url}, retrying in {wait}s "
                            f"(attempt {attempt + 1}/{self.max_retries})...",
                            file=sys.stderr,
                        )
                        if attempt == self.max_retries - 1:
                            self._last_request_time = time.monotonic()
                            raise RuntimeError(
                                f"Server error {exc.code} from {url} after {self.max_retries} retries."
                            ) from exc
                        time.sleep(wait)
                        last_backoff = float(wait)
                        self._last_request_time = time.monotonic()
                        continue

                    self._last_request_time = time.monotonic()
                    body = ""
                    try:
                        try:
                            raw_err = exc.read(1024)
                        except TypeError:
                            raw_err = exc.read()
                        if isinstance(raw_err, bytes):
                            body = raw_err[:1024].decode("utf-8", errors="replace")[:1000]
                        elif isinstance(raw_err, str):
                            body = raw_err[:1000]
                    except Exception:
                        body = ""
                    if not body:
                        body = str(getattr(exc, "reason", exc))
                    raise RuntimeError(f"HTTP {exc.code} from {url}: {body}") from exc
                finally:
                    close_fn = getattr(exc, "close", None)
                    if callable(close_fn):
                        close_fn()
            except (URLError, TimeoutError, OSError) as exc:
                if attempt == self.max_retries - 1:
                    self._last_request_time = time.monotonic()
                    raise RuntimeError(
                        f"Failed to connect to {url} after {self.max_retries} attempts: {exc}"
                    ) from exc
                wait = 2**attempt
                time.sleep(wait)
                last_backoff = float(wait)
                self._last_request_time = time.monotonic()

        decoded = raw_bytes.decode("utf-8", errors="replace")
        title = urlparse(url).path.rsplit("/", 1)[-1] or (urlparse(url).hostname or url)
        if self._looks_like_html(decoded, content_type):
            parser = _HTMLTextExtractor()
            parser.feed(decoded)
            parser.close()
            extracted_title = parser.get_title()
            if extracted_title:
                title = extracted_title
            plain_text = parser.get_text()
        else:
            plain_text = decoded

        sanitized_text, alerts = PromptInjectionSanitizer.sanitize(plain_text)
        chunks = tuple(
            DomainChunker.chunk_text(
                sanitized_text,
                chunk_chars=self.chunk_chars,
                overlap_chars=self.overlap_chars,
                preserve_code_blocks=True,
            )
        )
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        return HarvestedDocument(
            doc_id=f"web-{sha256[:12]}",
            source_uri=url,
            source_type="web_page",
            domain=domain.strip() or "cyber",
            title=title,
            license_id=license_id.strip(),
            sha256=sha256,
            raw_char_count=len(decoded),
            sanitized_text=sanitized_text,
            chunks=chunks,
            injection_alerts=alerts,
            metadata={"content_type": content_type or "text/plain"},
        )


class TeacherDistiller:
    """Synthesizes license-compliant, decontaminated training trajectories from harvested docs."""

    def __init__(
        self,
        backend: InferenceBackend,
        teacher_model_id: str = "Qwen/Qwen3.5-35B-A3B",
        teacher_license_id: str = "Apache-2.0",
    ) -> None:
        self.backend = backend
        self.teacher_model_id = teacher_model_id
        self.teacher_license_id = teacher_license_id
        self._auditor = LicenseComplianceAuditor()
        self._hygiene = DatasetHygienePipeline()

    def synthesize_trajectories(
        self,
        documents: list[HarvestedDocument],
        target_domain: str = "swe_fuse",
        max_samples_per_doc: int = 3,
        verifier: Callable[[TrainingTrajectoryRecord], bool] | None = None,
        allow_unexecuted_text_synthesis: bool = False,
    ) -> list[TrainingTrajectoryRecord]:
        """Generate `TrainingTrajectoryRecord` items filtered by license & hygiene.

        By default, unexecuted teacher completions are marked `execution_verified=False` and
        rejected by `DatasetHygienePipeline` Gate 3 unless `verifier` confirms execution or
        `allow_unexecuted_text_synthesis=True` is explicitly opted in (keeping
        `execution_verified=False`).
        """
        max_samples_per_doc = _validate_positive_int(max_samples_per_doc, "max_samples_per_doc")
        teacher_audit = self._auditor.audit(self.teacher_model_id, self.teacher_license_id)
        if teacher_audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
            raise PermissionError(
                f"Teacher model '{self.teacher_model_id}' rejected for distillation: "
                f"{teacher_audit.rationale}"
            )

        from platform_core.layer1_intelligence.inference import ChatMessage, InferenceRequest

        candidates: list[TrainingTrajectoryRecord] = []
        for doc in documents:
            doc_audit = self._auditor.audit(doc.source_uri, doc.license_id)
            if doc_audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
                continue

            sample_chunks = list(doc.chunks[:max_samples_per_doc])
            if not sample_chunks and doc.sanitized_text.strip():
                sample_chunks = [doc.sanitized_text[:2400]]

            for idx, chunk in enumerate(sample_chunks):
                req = InferenceRequest(
                    model_id=self.teacher_model_id,
                    messages=(
                        ChatMessage(
                            role="system",
                            content=(
                                "You are a sovereign technical distillation teacher. Produce a "
                                "precise, verifiable engineering or security solution grounded "
                                "strictly in the provided excerpt."
                            ),
                        ),
                        ChatMessage(
                            role="user",
                            content=(
                                f"Domain: {target_domain}\n"
                                f"Source Title: {doc.title}\n"
                                f"Excerpt:\n{chunk}"
                            ),
                        ),
                    ),
                    max_tokens=1024,
                    max_thinking_tokens=512,
                    temperature=0.2,
                )
                resp = self.backend.generate(req)
                clean_completion, _ = PromptInjectionSanitizer.sanitize(resp.content)
                clean_completion = clean_completion.strip()

                digest = hashlib.sha256(
                    f"{doc.doc_id}:{idx}:{chunk[:128]}".encode("utf-8")
                ).hexdigest()[:12]
                cve_id = doc.metadata.get("cve_id") if isinstance(doc.metadata, dict) else None
                base_metadata = {
                    "teacher_model_id": self.teacher_model_id,
                    "doc_id": doc.doc_id,
                    "chunk_index": idx,
                    "source_type": doc.source_type,
                    "sha256": doc.sha256,
                    "verification_status": (
                        "unexecuted_text_distillation"
                        if allow_unexecuted_text_synthesis and verifier is None
                        else "unexecuted_teacher_completion"
                    ),
                }
                candidate = TrainingTrajectoryRecord(
                    record_id=f"distill-{digest}",
                    domain=target_domain,
                    source_repo=doc.source_uri,
                    license_id=doc.license_id,
                    cve_id=str(cve_id) if cve_id else None,
                    prompt_context=f"[{target_domain.upper()}] Source: {doc.title}\n\n{chunk}",
                    target_completion=clean_completion,
                    execution_verified=False,
                    metadata=base_metadata,
                )
                if verifier is not None and clean_completion:
                    verified = bool(verifier(candidate))
                    candidate = TrainingTrajectoryRecord(
                        record_id=candidate.record_id,
                        domain=candidate.domain,
                        source_repo=candidate.source_repo,
                        license_id=candidate.license_id,
                        cve_id=candidate.cve_id,
                        prompt_context=candidate.prompt_context,
                        target_completion=candidate.target_completion,
                        execution_verified=verified,
                        metadata={
                            **base_metadata,
                            "verification_status": (
                                "oracle_verified" if verified else "oracle_rejected"
                            ),
                        },
                    )
                candidates.append(candidate)

        hygiene = self._filter_with_policy(
            candidates,
            allow_unexecuted_text_synthesis=allow_unexecuted_text_synthesis,
        )
        return list(hygiene["accepted_records"])

    def _filter_with_policy(
        self,
        records: list[TrainingTrajectoryRecord],
        allow_unexecuted_text_synthesis: bool = False,
    ) -> dict[str, Any]:
        if not allow_unexecuted_text_synthesis:
            return self._hygiene.filter_records(records)

        accepted: list[TrainingTrajectoryRecord] = []
        accepted_shingles: list[set[int]] = []
        rejected_counts = {
            "license_rejected": 0,
            "benchmark_contaminated": 0,
            "execution_unverified": 0,
            "near_duplicate": 0,
        }
        for rec in records:
            audit = self._auditor.audit(rec.source_repo, rec.license_id)
            if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
                rejected_counts["license_rejected"] += 1
                continue
            if rec.source_repo.lower().strip() in self._hygiene.blocked_repos:
                rejected_counts["benchmark_contaminated"] += 1
                continue
            if rec.cve_id and rec.cve_id.upper().strip() in self._hygiene.blocked_cves:
                rejected_counts["benchmark_contaminated"] += 1
                continue
            if not rec.target_completion.strip():
                rejected_counts["execution_unverified"] += 1
                continue
            shingles = self._hygiene._compute_shingle_hashes(
                f"{rec.prompt_context}\n{rec.target_completion}"
            )
            if any(
                self._hygiene._jaccard_similarity(shingles, existing)
                >= self._hygiene.jaccard_dedup_threshold
                for existing in accepted_shingles
            ):
                rejected_counts["near_duplicate"] += 1
                continue
            accepted.append(rec)
            accepted_shingles.append(shingles)

        return {
            "total_input": len(records),
            "accepted_count": len(accepted),
            "accepted_records": accepted,
            "rejected_breakdown": rejected_counts,
        }

    def export_distilled_jsonl(
        self,
        records: list[TrainingTrajectoryRecord],
        output_path: str | Path,
        allow_unexecuted_text_synthesis: bool = False,
    ) -> dict[str, Any]:
        """Filter trajectories through `DatasetHygienePipeline` and write atomic JSONL."""
        dest = Path(output_path)
        _validate_safe_path(dest)

        hygiene = self._filter_with_policy(
            records,
            allow_unexecuted_text_synthesis=allow_unexecuted_text_synthesis,
        )
        accepted: list[TrainingTrajectoryRecord] = list(hygiene["accepted_records"])

        dest.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = []
        for rec in accepted:
            payload = {
                "record_id": rec.record_id,
                "domain": rec.domain,
                "source_repo": rec.source_repo,
                "license_id": rec.license_id,
                "cve_id": rec.cve_id,
                "prompt_context": rec.prompt_context,
                "target_completion": rec.target_completion,
                "execution_verified": rec.execution_verified,
                "metadata": rec.metadata,
            }
            lines.append(json.dumps(payload, sort_keys=True))

        content = ("\n".join(lines) + "\n") if lines else ""
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=dest.parent,
                prefix=".distilled_",
                suffix=".tmp",
                delete=False,
            ) as tmp_fh:
                tmp_path = Path(tmp_fh.name)
                tmp_fh.write(content)
            os.replace(tmp_path, dest)
        except Exception:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

        file_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return {
            "output_path": str(dest),
            "exported_count": len(accepted),
            "rejected_count": len(records) - len(accepted),
            "rejected_breakdown": hygiene["rejected_breakdown"],
            "sha256": file_sha256,
        }


class CorpusHarvesterPipeline:
    """Orchestrates PDF/book and web corpus harvesting with optional `HybridKnowledgeStore` RAG."""

    def __init__(
        self,
        knowledge_store: HybridKnowledgeStore | None = None,
        web_harvester: RateLimitedWebHarvester | None = None,
        pdf_extractor: PDFBookExtractor | None = None,
    ) -> None:
        self._owns_store = knowledge_store is None
        self.knowledge_store = (
            knowledge_store if knowledge_store is not None else HybridKnowledgeStore(":memory:")
        )
        self.web_harvester = web_harvester
        self.pdf_extractor = pdf_extractor if pdf_extractor is not None else PDFBookExtractor()

    def __enter__(self) -> CorpusHarvesterPipeline:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def run_harvest(
        self,
        pdf_paths: list[str | Path] | None = None,
        book_dirs: list[str | Path] | None = None,
        urls: list[str] | None = None,
        domain: str = "swe",
        license_id: str = "Apache-2.0",
        session_tainted: bool = False,
        ingest_into_rag: bool = True,
    ) -> HarvestReport:
        """Harvest local books and approved web URLs, sanitize, chunk, and optionally index in RAG."""
        documents: list[HarvestedDocument] = []
        rejected_sources: list[dict[str, str]] = []

        for path in pdf_paths or []:
            try:
                documents.append(
                    self.pdf_extractor.extract_book(path, domain=domain, license_id=license_id)
                )
            except (PermissionError, FileNotFoundError, ValueError, OSError) as exc:
                rejected_sources.append({"source": str(path), "error": str(exc)})

        for book_dir in book_dirs or []:
            try:
                documents.extend(
                    self.pdf_extractor.extract_directory(
                        book_dir, domain=domain, license_id=license_id
                    )
                )
            except (PermissionError, FileNotFoundError, ValueError, OSError) as exc:
                rejected_sources.append({"source": str(book_dir), "error": str(exc)})

        if urls:
            harvester = self.web_harvester or RateLimitedWebHarvester(
                session_tainted=session_tainted
            )
            for url in urls:
                if session_tainted:
                    rejected_sources.append(
                        {
                            "source": url,
                            "error": "Blocked: Session is TAINTED_UNTRUSTED (internal=True bridge enforced; zero outbound egress).",
                        }
                    )
                    continue
                try:
                    documents.append(
                        harvester.fetch_url(url, domain=domain, license_id=license_id)
                    )
                except (PermissionError, RateLimitError, RuntimeError, ValueError, OSError) as exc:
                    rejected_sources.append({"source": url, "error": str(exc)})

        total_chunks = sum(len(doc.chunks) for doc in documents)
        total_tokens_est = sum(max(1, len(c) // 4) for doc in documents for c in doc.chunks)

        if ingest_into_rag:
            for doc in documents:
                for idx, chunk in enumerate(doc.chunks):
                    self.knowledge_store.ingest_document(
                        chunk_id=f"{doc.doc_id}#chunk-{idx}",
                        source_uri=doc.source_uri,
                        content=chunk,
                        metadata={
                            "doc_id": doc.doc_id,
                            "domain": doc.domain,
                            "license_id": doc.license_id,
                            "source_type": doc.source_type,
                            "title": doc.title,
                            "sha256": doc.sha256,
                            "chunk_index": idx,
                        },
                    )
            if total_chunks > 0:
                probe = self.knowledge_store.retrieve("corpus_probe", top_k=1)
                rag_stats: dict[str, Any] = {
                    "ingested_documents": len(documents),
                    "ingested_chunks": total_chunks,
                    "retrieval_mode": probe["retrieval_mode"],
                    "total_corpus_tokens": probe["total_corpus_tokens"],
                }
            else:
                rag_stats = {
                    "ingested_documents": 0,
                    "ingested_chunks": 0,
                    "retrieval_mode": "EMPTY",
                    "total_corpus_tokens": 0,
                }
        else:
            rag_stats = {
                "ingested_documents": 0,
                "ingested_chunks": 0,
                "retrieval_mode": "SKIPPED",
                "total_corpus_tokens": 0,
            }

        return HarvestReport(
            documents=tuple(documents),
            total_chunks=total_chunks,
            total_tokens_est=total_tokens_est,
            rejected_sources=tuple(rejected_sources),
            rag_ingestion_stats=rag_stats,
        )

    def close(self) -> None:
        """Close the owned `HybridKnowledgeStore` SQLite connection if owned by this pipeline."""
        if self._owns_store and getattr(self, "knowledge_store", None) is not None:
            self.knowledge_store.close()
