"""Layer 3 Bitemporal Episodic Memory (Graphiti + GAM), Persistent RAG & Project Context.

Implements Section 3.3 and Phase 2 persistence:
1. `BitemporalEpisodicMemory`: Thread-safe WAL SQLite-backed GAM Event Progression Graph
   and Topic Associative Network with Graphiti bitemporal edges (`valid_from`, `valid_to`,
   `invalid_at`) surviving restarts and supporting point-in-time queries.
2. `HybridKnowledgeStore`: Thread-safe WAL SQLite + FTS5 BM25 + dense vector store with
   200,000-token `DIRECT_PREFIX_CACHE` threshold, SHA-256 provenance tracking, indirect
   prompt-injection sanitization, and Reciprocal Rank Fusion (RRF).
3. `ProjectContextManager`: Token-budgeted assembly of repository skeletons, bitemporal
   facts, and retrieved knowledge chunks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any


@dataclass(frozen=True)
class ProgressionEvent:
    """Append-only node in the GAM Event Progression Graph."""

    event_id: str
    session_id: str
    timestamp: float
    event_type: str
    summary: str
    commit_sha: str | None = None


@dataclass
class BitemporalFactEdge:
    """Bitemporal edge in the Graphiti / GAM Topic Associative Network."""

    fact_id: str
    subject: str
    predicate: str
    object_val: str
    commit_sha: str
    valid_from: float
    ingested_at: float
    valid_to: float | None = None
    invalid_at: float | None = None

    @property
    def is_currently_valid(self) -> bool:
        return self.valid_to is None and self.invalid_at is None


class BitemporalEpisodicMemory:
    """Manages the GAM Event Progression Graph and Bitemporal Topic Associative Network."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        self._live_facts: dict[str, BitemporalFactEdge] = {}
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout = 30000")
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS progression_events (
                    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    commit_sha TEXT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bitemporal_facts (
                    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fact_id TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    object_val TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    valid_from REAL NOT NULL,
                    ingested_at REAL NOT NULL,
                    valid_to REAL,
                    invalid_at REAL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_session ON progression_events (session_id, seq_id)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_facts_subj_pred ON bitemporal_facts (subject, predicate)"
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

    def append_event(
        self,
        session_id: str,
        event_type: str,
        summary: str,
        commit_sha: str | None = None,
        timestamp: float | None = None,
    ) -> ProgressionEvent:
        """Append an immutable atomic event to the Event Progression Graph."""
        ts = timestamp if timestamp is not None else time.time()
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM progression_events").fetchone()
            next_idx = int(row[0]) + 1 if row else 1
            event_id = f"evt-{next_idx}"
            self._conn.execute(
                """
                INSERT INTO progression_events (event_id, session_id, timestamp, event_type, summary, commit_sha)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_id, session_id, ts, event_type, summary, commit_sha),
            )
            self._conn.commit()
        return ProgressionEvent(
            event_id=event_id,
            session_id=session_id,
            timestamp=ts,
            event_type=event_type,
            summary=summary,
            commit_sha=commit_sha,
        )

    def record_event(
        self,
        session_id: str,
        event_type: str,
        description: str = "",
        confidence: float = 1.0,
        commit_sha: str | None = None,
        summary: str | None = None,
        timestamp: float | None = None,
    ) -> ProgressionEvent:
        """Record an episodic event, mapping description/summary into progression event."""
        actual_summary = summary or description
        return self.append_event(
            session_id=session_id,
            event_type=event_type,
            summary=actual_summary,
            commit_sha=commit_sha,
            timestamp=timestamp,
        )

    def upsert_architectural_fact(
        self,
        subject: str,
        predicate: str,
        object_val: str,
        commit_sha: str,
        valid_from: float | None = None,
    ) -> BitemporalFactEdge:
        """Upsert a fact in the Topic Associative Network, superseding stale active edges."""
        now = time.time()
        v_from = valid_from if valid_from is not None else now

        with self._lock:
            active_rows = self._conn.execute(
                """
                SELECT fact_id, subject, predicate, object_val, commit_sha, valid_from, ingested_at, valid_to, invalid_at
                FROM bitemporal_facts
                WHERE subject = ? AND predicate = ? AND valid_to IS NULL AND invalid_at IS NULL
                ORDER BY seq_id ASC
                """,
                (subject, predicate),
            ).fetchall()

            for r in active_rows:
                if r[3] == object_val:
                    return self._live_facts.get(r[0]) or self._row_to_fact(r)
                self._conn.execute(
                    "UPDATE bitemporal_facts SET valid_to = ?, invalid_at = ? WHERE fact_id = ?",
                    (v_from, now, r[0]),
                )
                live_obj = self._live_facts.get(r[0])
                if live_obj is not None:
                    live_obj.valid_to = v_from
                    live_obj.invalid_at = now

            count_row = self._conn.execute("SELECT COUNT(*) FROM bitemporal_facts").fetchone()
            next_idx = int(count_row[0]) + 1 if count_row else 1
            fact_id = f"fact-{next_idx}"
            self._conn.execute(
                """
                INSERT INTO bitemporal_facts
                (fact_id, subject, predicate, object_val, commit_sha, valid_from, ingested_at, valid_to, invalid_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (fact_id, subject, predicate, object_val, commit_sha, v_from, now),
            )
            self._conn.commit()

        edge = BitemporalFactEdge(
            fact_id=fact_id,
            subject=subject,
            predicate=predicate,
            object_val=object_val,
            commit_sha=commit_sha,
            valid_from=v_from,
            ingested_at=now,
        )
        self._live_facts[fact_id] = edge
        return edge

    def query_active_facts(self, subject: str | None = None) -> list[BitemporalFactEdge]:
        """Return currently valid architectural facts."""
        with self._lock:
            if subject is None:
                rows = self._conn.execute(
                    """
                    SELECT fact_id, subject, predicate, object_val, commit_sha, valid_from, ingested_at, valid_to, invalid_at
                    FROM bitemporal_facts
                    WHERE valid_to IS NULL AND invalid_at IS NULL
                    ORDER BY seq_id ASC
                    """
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT fact_id, subject, predicate, object_val, commit_sha, valid_from, ingested_at, valid_to, invalid_at
                    FROM bitemporal_facts
                    WHERE subject = ? AND valid_to IS NULL AND invalid_at IS NULL
                    ORDER BY seq_id ASC
                    """,
                    (subject,),
                ).fetchall()
        return [self._row_to_fact(r) for r in rows]

    def query_facts_as_of(
        self,
        point_in_time: float,
        subject: str | None = None,
    ) -> list[BitemporalFactEdge]:
        """Point-in-time bitemporal query: return facts valid at `point_in_time`."""
        with self._lock:
            if subject is None:
                rows = self._conn.execute(
                    """
                    SELECT fact_id, subject, predicate, object_val, commit_sha, valid_from, ingested_at, valid_to, invalid_at
                    FROM bitemporal_facts
                    WHERE valid_from <= ? AND (valid_to IS NULL OR ? < valid_to)
                    ORDER BY seq_id ASC
                    """,
                    (point_in_time, point_in_time),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT fact_id, subject, predicate, object_val, commit_sha, valid_from, ingested_at, valid_to, invalid_at
                    FROM bitemporal_facts
                    WHERE subject = ? AND valid_from <= ? AND (valid_to IS NULL OR ? < valid_to)
                    ORDER BY seq_id ASC
                    """,
                    (subject, point_in_time, point_in_time),
                ).fetchall()
        return [self._row_to_fact(r) for r in rows]

    def list_events(self, session_id: str | None = None) -> list[ProgressionEvent]:
        with self._lock:
            if session_id is None:
                rows = self._conn.execute(
                    "SELECT event_id, session_id, timestamp, event_type, summary, commit_sha FROM progression_events ORDER BY seq_id ASC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT event_id, session_id, timestamp, event_type, summary, commit_sha
                    FROM progression_events WHERE session_id = ? ORDER BY seq_id ASC
                    """,
                    (session_id,),
                ).fetchall()
        return [
            ProgressionEvent(
                event_id=r[0],
                session_id=r[1],
                timestamp=r[2],
                event_type=r[3],
                summary=r[4],
                commit_sha=r[5],
            )
            for r in rows
        ]

    @staticmethod
    def _row_to_fact(row: tuple[Any, ...]) -> BitemporalFactEdge:
        return BitemporalFactEdge(
            fact_id=row[0],
            subject=row[1],
            predicate=row[2],
            object_val=row[3],
            commit_sha=row[4],
            valid_from=row[5],
            ingested_at=row[6],
            valid_to=row[7],
            invalid_at=row[8],
        )


class EmbeddingProvider(ABC):
    """Abstract text embedding provider for HybridKnowledgeStore."""

    @abstractmethod
    def embed_texts(self, texts: list[str]) -> list[tuple[float, ...]]:
        """Generate normalized embedding vectors for input texts."""


class DeterministicHashEmbedder(EmbeddingProvider):
    """Zero-dependency deterministic 16-dim token-bucket embedder for offline tests."""

    def __init__(self, dim: int = 16) -> None:
        self.dim = dim

    def embed_texts(self, texts: list[str]) -> list[tuple[float, ...]]:
        out: list[tuple[float, ...]] = []
        for text in texts:
            buckets = [0.0] * self.dim
            for token in re.findall(r"[a-z0-9_]+", text.lower()):
                h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
                buckets[h % self.dim] += 1.0
            norm = math.sqrt(sum(v * v for v in buckets)) or 1.0
            out.append(tuple(round(v / norm, 6) for v in buckets))
        return out


class InferenceBackendEmbedder(EmbeddingProvider):
    """Semantic embedding adapter delegating to an InferenceBackend (e.g., Qwen3-Embedding-0.6B)."""

    def __init__(self, backend: Any, model_id: str = "Qwen/Qwen3-Embedding-0.6B") -> None:
        self.backend = backend
        self.model_id = model_id

    def embed_texts(self, texts: list[str]) -> list[tuple[float, ...]]:
        raw_vecs = self.backend.embed(self.model_id, texts)
        return [tuple(float(x) for x in v) for v in raw_vecs]


@dataclass(frozen=True)
class KnowledgeDocumentChunk:
    """Provenance-tracked external technical document chunk in HybridKnowledgeStore."""

    chunk_id: str
    source_uri: str
    content: str
    token_count: int
    sha256_digest: str
    embedding: tuple[float, ...]


class HybridKnowledgeStore:
    """Hybrid Knowledge Store with SQLite persistence, FTS5 BM25 + vector RRF, and 200K-token rule."""

    DIRECT_PREFIX_CACHE_TOKEN_LIMIT: int = 200_000
    INJECTION_REGEX: re.Pattern[str] = re.compile(
        r"(?:ignore\s+(?:all\s+)?previous\s+instructions|<\|im_start\|>|system:\s*override)",
        re.IGNORECASE,
    )

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        embedder: EmbeddingProvider | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.embedder = embedder or DeterministicHashEmbedder()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        self._fts5_enabled = False
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout = 30000")
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS knowledge_chunks (
                    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chunk_id TEXT UNIQUE NOT NULL,
                    source_uri TEXT NOT NULL,
                    content TEXT NOT NULL,
                    token_count INTEGER NOT NULL,
                    sha256_digest TEXT NOT NULL,
                    embedding_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            try:
                self._conn.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                        chunk_id UNINDEXED,
                        content
                    )
                    """
                )
                self._fts5_enabled = True
            except sqlite3.OperationalError:
                self._fts5_enabled = False
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

    def ingest_document(
        self,
        chunk_id: str,
        source_uri: str,
        content: str,
        embedding: list[float] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> KnowledgeDocumentChunk:
        """Sanitize against indirect prompt injection, compute SHA-256 provenance, and persist."""
        sanitized = self.INJECTION_REGEX.sub("[REDACTED_PROMPT_INJECTION]", content)
        digest = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()
        tokens = max(1, len(sanitized) // 4)
        vec = tuple(embedding) if embedding is not None else self.embedder.embed_texts([sanitized])[0]

        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO knowledge_chunks
                (chunk_id, source_uri, content, token_count, sha256_digest, embedding_json, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chunk_id,
                    source_uri,
                    sanitized,
                    tokens,
                    digest,
                    json.dumps(list(vec)),
                    json.dumps(metadata or {}, sort_keys=True),
                ),
            )
            if self._fts5_enabled:
                self._conn.execute("DELETE FROM knowledge_fts WHERE chunk_id = ?", (chunk_id,))
                self._conn.execute(
                    "INSERT INTO knowledge_fts (chunk_id, content) VALUES (?, ?)",
                    (chunk_id, sanitized),
                )
            self._conn.commit()

        return KnowledgeDocumentChunk(
            chunk_id=chunk_id,
            source_uri=source_uri,
            content=sanitized,
            token_count=tokens,
            sha256_digest=digest,
            embedding=vec,
        )

    def ingest_directory(
        self,
        root_dir: str | Path,
        extensions: tuple[str, ...] = (".py", ".md", ".txt", ".json", ".yaml", ".yml", ".rs", ".go", ".ts"),
        chunk_size_chars: int = 2400,
        overlap_chars: int = 300,
    ) -> dict[str, Any]:
        """Recursively chunk and index safe non-symlink files inside `root_dir`."""
        root = Path(root_dir)
        if root.is_symlink() or not root.is_dir():
            raise FileNotFoundError(f"Invalid directory for RAG ingestion: {root}")
        resolved_root = root.resolve()
        files_indexed = 0
        chunks_indexed = 0

        for path in sorted(resolved_root.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            if not path.resolve().is_relative_to(resolved_root):
                continue
            if path.suffix.lower() not in extensions:
                continue
            if any(part.startswith(".") or part == "__pycache__" for part in path.relative_to(resolved_root).parts):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                continue
            rel = str(path.relative_to(resolved_root))
            files_indexed += 1
            step = max(1, chunk_size_chars - overlap_chars)
            for idx, offset in enumerate(range(0, len(text), step)):
                piece = text[offset : offset + chunk_size_chars]
                self.ingest_document(
                    chunk_id=f"{rel}#chunk-{idx}",
                    source_uri=f"file://{path}",
                    content=piece,
                    metadata={"relative_path": rel, "chunk_index": idx},
                )
                chunks_indexed += 1
                if offset + chunk_size_chars >= len(text):
                    break

        return {"files_indexed": files_indexed, "chunks_indexed": chunks_indexed}

    def retrieve(self, query: str, top_k: int = 5) -> dict[str, Any]:
        """Retrieve relevant knowledge using the 200K-token direct prefix-cache rule or hybrid RRF search."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT chunk_id, source_uri, content, token_count, sha256_digest, embedding_json
                FROM knowledge_chunks
                ORDER BY seq_id ASC
                """
            ).fetchall()

        chunks = [
            KnowledgeDocumentChunk(
                chunk_id=r[0],
                source_uri=r[1],
                content=r[2],
                token_count=int(r[3]),
                sha256_digest=r[4],
                embedding=tuple(json.loads(r[5])),
            )
            for r in rows
        ]
        total_tokens = sum(c.token_count for c in chunks)

        if 0 < total_tokens < self.DIRECT_PREFIX_CACHE_TOKEN_LIMIT:
            return {
                "retrieval_mode": "DIRECT_PREFIX_CACHE",
                "total_corpus_tokens": total_tokens,
                "results": [
                    {
                        "chunk_id": c.chunk_id,
                        "source_uri": c.source_uri,
                        "sha256_digest": c.sha256_digest,
                        "content": c.content,
                        "score": 1.0,
                    }
                    for c in chunks
                ],
            }

        query_vec = self.embedder.embed_texts([query])[0]
        query_terms = set(re.findall(r"[a-z0-9_]+", query.lower()))

        fts_ranks: dict[str, int] = {}
        if self._fts5_enabled and query_terms:
            fts_query = " OR ".join(sorted(query_terms)[:12])
            try:
                with self._lock:
                    fts_rows = self._conn.execute(
                        "SELECT chunk_id FROM knowledge_fts WHERE knowledge_fts MATCH ? ORDER BY rank LIMIT ?",
                        (fts_query, max(20, top_k * 4)),
                    ).fetchall()
                for rank_idx, (cid,) in enumerate(fts_rows, start=1):
                    fts_ranks[cid] = rank_idx
            except sqlite3.OperationalError:
                fts_ranks = {}

        vec_scored: list[tuple[float, KnowledgeDocumentChunk]] = []
        for chunk in chunks:
            cos_sim = self._cosine_similarity(query_vec, chunk.embedding)
            vec_scored.append((cos_sim, chunk))
        vec_scored.sort(key=lambda item: item[0], reverse=True)
        vec_ranks = {c.chunk_id: idx for idx, (_, c) in enumerate(vec_scored, start=1)}

        scored: list[tuple[float, KnowledgeDocumentChunk]] = []
        for cos_sim, chunk in vec_scored:
            chunk_terms = set(re.findall(r"[a-z0-9_]+", chunk.content.lower()))
            lexical_overlap = (
                len(query_terms & chunk_terms) / len(query_terms) if query_terms else 0.0
            )
            rrf_vec = 1.0 / (60.0 + vec_ranks[chunk.chunk_id])
            rrf_fts = (1.0 / (60.0 + fts_ranks[chunk.chunk_id])) if chunk.chunk_id in fts_ranks else 0.0
            hybrid_score = round(0.55 * cos_sim + 0.25 * lexical_overlap + 12.0 * (rrf_vec + rrf_fts), 6)
            scored.append((hybrid_score, chunk))

        scored.sort(key=lambda item: item[0], reverse=True)
        return {
            "retrieval_mode": "HYBRID_PGVECTORSCALE_SEARCH",
            "total_corpus_tokens": total_tokens,
            "results": [
                {
                    "chunk_id": c.chunk_id,
                    "source_uri": c.source_uri,
                    "sha256_digest": c.sha256_digest,
                    "content": c.content,
                    "score": score,
                }
                for score, c in scored[: max(1, top_k)]
            ],
        }

    @staticmethod
    def _deterministic_embed(text: str, dim: int = 16) -> tuple[float, ...]:
        return DeterministicHashEmbedder(dim=dim).embed_texts([text])[0]

    @staticmethod
    def _cosine_similarity(a: tuple[float, ...], b: tuple[float, ...]) -> float:
        if len(a) != len(b) or not a:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a)) or 1.0
        nb = math.sqrt(sum(y * y for y in b)) or 1.0
        return dot / (na * nb)


class ProjectContextManager:
    """Assembles token-budgeted project awareness packs from code graph, bitemporal facts, and RAG."""

    def __init__(
        self,
        knowledge_store: HybridKnowledgeStore,
        episodic_memory: BitemporalEpisodicMemory,
        max_context_tokens: int = 24_000,
    ) -> None:
        if max_context_tokens <= 0:
            raise ValueError("max_context_tokens must be positive.")
        self.knowledge_store = knowledge_store
        self.episodic_memory = episodic_memory
        self.max_context_tokens = max_context_tokens

    def build_context_pack(
        self,
        query: str,
        subject: str | None = None,
        code_skeletons: dict[str, Any] | None = None,
        top_k: int = 6,
    ) -> dict[str, Any]:
        active_facts = self.episodic_memory.query_active_facts(subject=subject)
        rag = self.knowledge_store.retrieve(query=query, top_k=top_k)

        used_tokens = 0
        selected_facts: list[dict[str, Any]] = []
        for f in active_facts:
            fact_text = f"{f.subject} {f.predicate} {f.object_val} (commit={f.commit_sha})"
            est = max(1, len(fact_text) // 4)
            if used_tokens + est > self.max_context_tokens:
                break
            used_tokens += est
            selected_facts.append(
                {
                    "fact_id": f.fact_id,
                    "subject": f.subject,
                    "predicate": f.predicate,
                    "object": f.object_val,
                    "commit_sha": f.commit_sha,
                }
            )

        selected_chunks: list[dict[str, Any]] = []
        for item in rag["results"]:
            est = max(1, len(item["content"]) // 4)
            if used_tokens + est > self.max_context_tokens:
                break
            used_tokens += est
            selected_chunks.append(item)

        return {
            "retrieval_mode": rag["retrieval_mode"],
            "estimated_tokens": used_tokens,
            "max_context_tokens": self.max_context_tokens,
            "active_facts": selected_facts,
            "knowledge_chunks": selected_chunks,
            "code_skeleton_files": sorted((code_skeletons or {}).keys()),
        }
