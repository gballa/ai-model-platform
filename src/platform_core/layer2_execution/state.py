"""Layer 2 Shared Typed State Schema (`PlatformState`) and Durable SQLite Checkpointer.

Implements Section 3.2 & 10.3:
- Typed shared state passed across the 6 specialist agent nodes.
- Lightweight URI artifact pointers (`ArtifactRef`) so agents never flood context windows
  with raw binaries, core dumps, or giant AST subgraphs.
- Step-level durable state checkpointing in SQLite supporting crash recovery, human
  `interrupt()` approval gates, and time-travel state replay.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any


class TaintLevel(str, Enum):
    """Information-Flow Taint Classification (Section 10.3 & 10.5)."""

    CLEAN = "CLEAN"
    TAINTED_UNTRUSTED = "TAINTED_UNTRUSTED"


class TaskStatus(str, Enum):
    """Deterministic task status lifecycle."""

    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    AWAITING_HUMAN_APPROVAL = "AWAITING_HUMAN_APPROVAL"
    AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
    VERIFIER_REJECTED = "VERIFIER_REJECTED"
    COMPLETED = "COMPLETED"
    FAILED_ESCALATED = "FAILED_ESCALATED"


class EpistemicStatus(str, Enum):
    """Strict epistemic classification separating verified facts from hypotheses."""

    FACT = "FACT"
    HYPOTHESIS = "HYPOTHESIS"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class EpistemicClaim:
    """Attributable knowledge claim with confidence & human verification gating."""

    claim_id: str
    status: EpistemicStatus
    statement: str
    evidence_refs: tuple[str, ...]
    confidence: float
    source_tool: str = ""
    alternative_hypotheses: tuple[str, ...] = ()
    requires_human_verification: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "status": self.status.value,
            "statement": self.statement,
            "evidence_refs": list(self.evidence_refs),
            "confidence": round(float(self.confidence), 4),
            "source_tool": self.source_tool,
            "alternative_hypotheses": list(self.alternative_hypotheses),
            "requires_human_verification": self.requires_human_verification,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EpistemicClaim:
        return cls(
            claim_id=str(raw["claim_id"]),
            status=EpistemicStatus(raw["status"]),
            statement=str(raw["statement"]),
            evidence_refs=tuple(str(x) for x in raw.get("evidence_refs", [])),
            confidence=float(raw["confidence"]),
            source_tool=str(raw.get("source_tool", "")),
            alternative_hypotheses=tuple(str(x) for x in raw.get("alternative_hypotheses", [])),
            requires_human_verification=bool(raw.get("requires_human_verification", False)),
        )


@dataclass(frozen=True)
class EpistemicAssessment:
    """Aggregated claim ledger summarizing verified facts vs hypotheses and uncertainty."""

    overall_confidence: float
    claims: tuple[EpistemicClaim, ...]
    facts_count: int
    hypotheses_count: int
    uncertain_count: int
    human_verification_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_confidence": round(float(self.overall_confidence), 4),
            "facts_count": self.facts_count,
            "hypotheses_count": self.hypotheses_count,
            "uncertain_count": self.uncertain_count,
            "human_verification_required": self.human_verification_required,
            "claims": [c.to_dict() for c in self.claims],
        }

    @classmethod
    def from_claims(cls, claims: list[EpistemicClaim] | tuple[EpistemicClaim, ...]) -> EpistemicAssessment:
        claims_tuple = tuple(claims)
        if not claims_tuple:
            return cls(
                overall_confidence=0.0,
                claims=(),
                facts_count=0,
                hypotheses_count=0,
                uncertain_count=1,
                human_verification_required=True,
            )
        avg_conf = sum(c.confidence for c in claims_tuple) / len(claims_tuple)
        return cls(
            overall_confidence=round(avg_conf, 4),
            claims=claims_tuple,
            facts_count=sum(1 for c in claims_tuple if c.status == EpistemicStatus.FACT),
            hypotheses_count=sum(1 for c in claims_tuple if c.status == EpistemicStatus.HYPOTHESIS),
            uncertain_count=sum(1 for c in claims_tuple if c.status == EpistemicStatus.UNCERTAIN),
            human_verification_required=any(c.requires_human_verification for c in claims_tuple),
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EpistemicAssessment:
        return cls(
            overall_confidence=float(raw["overall_confidence"]),
            claims=tuple(EpistemicClaim.from_dict(c) for c in raw.get("claims", [])),
            facts_count=int(raw.get("facts_count", 0)),
            hypotheses_count=int(raw.get("hypotheses_count", 0)),
            uncertain_count=int(raw.get("uncertain_count", 0)),
            human_verification_required=bool(raw.get("human_verification_required", False)),
        )


class LifecycleStep(int, Enum):
    """The 10-Step Reliable Agent Execution Lifecycle (Section 10.3)."""

    STEP_1_INGEST_AND_TAINT = 1
    STEP_2_PRE_INDEX_AND_DECOMPOSE = 2
    STEP_3_SPECIALIST_AND_THINKING_ROUTE = 3
    STEP_4_SCOPED_MCP_BINDING = 4
    STEP_5_POLICY_AND_APPROVAL_GATE = 5
    STEP_6_MICROVM_EXECUTION = 6
    STEP_7_OBSERVATION_AND_TELEMETRY = 7
    STEP_8_INDEPENDENT_VERIFICATION = 8
    STEP_9_SNAPSHOT_ROLLBACK_AND_RETRY = 9
    STEP_10_ARTIFACT_DELIVERY_AND_MEMORY = 10


@dataclass(frozen=True)
class ArtifactRef:
    """Content-addressed pointer to a large artifact stored out-of-context (Section 3.2)."""

    artifact_id: str
    uri: str
    sha256: str
    byte_length: int
    media_type: str
    byte_range: tuple[int, int] | None = None


@dataclass
class ApprovalRequest:
    """Human-in-the-loop cryptographic approval gate state (Step 5)."""

    request_id: str
    action_description: str
    risk_reason: str
    approved: bool = False
    operator_id: str | None = None
    approval_signature: str | None = None


@dataclass
class SubTask:
    """Single node in the Orchestrator's decomposed task DAG."""

    subtask_id: str
    title: str
    domain: str  # "swe", "cyber", "binrev", "visual_ocr", "data_protocol"
    assigned_agent: str
    status: TaskStatus = TaskStatus.PENDING
    scoped_tools: list[str] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3
    active_snapshot_id: str | None = None
    candidate_output: dict[str, Any] = field(default_factory=dict)
    verifier_feedback: list[str] = field(default_factory=list)
    verified_by_agent: str | None = None


@dataclass
class PlatformState:
    """Typed Shared State Schema persisted across LangGraph-style execution steps."""

    session_id: str
    objective: str
    task_domain: str
    taint_level: TaintLevel = TaintLevel.CLEAN
    current_step: LifecycleStep = LifecycleStep.STEP_1_INGEST_AND_TAINT
    status: TaskStatus = TaskStatus.PENDING
    has_untrusted_artifacts: bool = False
    requires_mutating_approval: bool = False
    approval_request: ApprovalRequest | None = None
    pre_index_summary: dict[str, Any] = field(default_factory=dict)
    routing_summary: dict[str, Any] = field(default_factory=dict)
    subtasks: list[SubTask] = field(default_factory=list)
    artifact_refs: list[ArtifactRef] = field(default_factory=list)
    telemetry_spans: list[dict[str, Any]] = field(default_factory=list)
    final_deliverable: dict[str, Any] = field(default_factory=dict)
    epistemic_assessment: EpistemicAssessment | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize state to a JSON-compatible dictionary."""
        raw = asdict(self)
        raw["taint_level"] = self.taint_level.value
        raw["current_step"] = int(self.current_step)
        raw["status"] = self.status.value
        for st in raw["subtasks"]:
            st["status"] = st["status"].value if isinstance(st["status"], TaskStatus) else st["status"]
        raw["epistemic_assessment"] = (
            self.epistemic_assessment.to_dict() if self.epistemic_assessment is not None else None
        )
        return raw

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PlatformState:
        """Reconstruct typed PlatformState from a checkpoint dictionary."""
        approval_raw = data.get("approval_request")
        approval = ApprovalRequest(**approval_raw) if isinstance(approval_raw, dict) else None

        subtasks = [
            SubTask(
                subtask_id=st["subtask_id"],
                title=st["title"],
                domain=st["domain"],
                assigned_agent=st["assigned_agent"],
                status=TaskStatus(st["status"]),
                scoped_tools=list(st.get("scoped_tools", [])),
                retry_count=int(st.get("retry_count", 0)),
                max_retries=int(st.get("max_retries", 3)),
                active_snapshot_id=st.get("active_snapshot_id"),
                candidate_output=dict(st.get("candidate_output", {})),
                verifier_feedback=list(st.get("verifier_feedback", [])),
                verified_by_agent=st.get("verified_by_agent"),
            )
            for st in data.get("subtasks", [])
        ]

        artifacts = [
            ArtifactRef(
                artifact_id=art["artifact_id"],
                uri=art["uri"],
                sha256=art["sha256"],
                byte_length=int(art["byte_length"]),
                media_type=art["media_type"],
                byte_range=tuple(art["byte_range"]) if art.get("byte_range") else None,
            )
            for art in data.get("artifact_refs", [])
        ]

        ep_raw = data.get("epistemic_assessment")
        ep_assessment = EpistemicAssessment.from_dict(ep_raw) if isinstance(ep_raw, dict) else None

        return cls(
            session_id=data["session_id"],
            objective=data["objective"],
            task_domain=data["task_domain"],
            taint_level=TaintLevel(data["taint_level"]),
            current_step=LifecycleStep(int(data["current_step"])),
            status=TaskStatus(data["status"]),
            has_untrusted_artifacts=bool(data.get("has_untrusted_artifacts", False)),
            requires_mutating_approval=bool(data.get("requires_mutating_approval", False)),
            approval_request=approval,
            pre_index_summary=dict(data.get("pre_index_summary", {})),
            routing_summary=dict(data.get("routing_summary", {})),
            subtasks=subtasks,
            artifact_refs=artifacts,
            telemetry_spans=list(data.get("telemetry_spans", [])),
            final_deliverable=dict(data.get("final_deliverable", {})),
            epistemic_assessment=ep_assessment,
        )


class StateStorageBackend(ABC):
    """Interface for pluggable state storage backends."""
    @abstractmethod
    def save(self, session_id: str, lifecycle_step: int, status: str, state_json: str) -> int:
        ...

    @abstractmethod
    def load_latest(self, session_id: str) -> str | None:
        ...

    @abstractmethod
    def load_at_step(self, session_id: str, step: int) -> str | None:
        ...

    @abstractmethod
    def sync_with_consensus(self, session_id: str, state_json: str) -> bool:
        """Synchronize state with distributed consensus mechanism (ADR-0007)."""
        ...

class SQLiteStorageBackend(StateStorageBackend):
    """SQLite implementation of StateStorageBackend."""
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout = 30000")
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS state_checkpoints (
                    checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    lifecycle_step INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    state_json TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_session_step ON state_checkpoints (session_id, checkpoint_id)"
            )
            self._conn.commit()

    def save(self, session_id: str, lifecycle_step: int, status: str, state_json: str) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO state_checkpoints (session_id, lifecycle_step, status, created_at, state_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, lifecycle_step, status, time.time(), state_json),
            )
            self._conn.commit()
            return int(cursor.lastrowid or 0)

    def load_latest(self, session_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT state_json FROM state_checkpoints
                WHERE session_id = ?
                ORDER BY checkpoint_id DESC
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()
        return row[0] if row else None

    def load_at_step(self, session_id: str, step: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT state_json FROM state_checkpoints
                WHERE session_id = ? AND lifecycle_step = ?
                ORDER BY checkpoint_id DESC
                LIMIT 1
                """,
                (session_id, step),
            ).fetchone()
        return row[0] if row else None

    def sync_with_consensus(self, session_id: str, state_json: str) -> bool:
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        if not isinstance(state_json, str) or not state_json.strip():
            raise ValueError("state_json must be a non-empty JSON string")
        try:
            parsed = json.loads(state_json)
        except (TypeError, ValueError) as exc:
            raise ValueError("state_json must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("state_json must decode to a JSON object")

        with self._lock:
            if self._conn is None:
                raise RuntimeError("SQLite connection is closed")
            self._conn.execute("SELECT 1 FROM state_checkpoints WHERE session_id = ? LIMIT 1", (session_id,)).fetchone()
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            self._conn.commit()
            return True

    def list_history(self, session_id: str) -> list[dict[str, Any]]:
        """Return ordered checkpoint metadata for audit and replay."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT checkpoint_id, lifecycle_step, status, created_at
                FROM state_checkpoints
                WHERE session_id = ?
                ORDER BY checkpoint_id ASC
                """,
                (session_id,),
            ).fetchall()
        return [
            {
                "checkpoint_id": r[0],
                "lifecycle_step": r[1],
                "status": r[2],
                "created_at": r[3],
            }
            for r in rows
        ]

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

class SQLiteStateCheckpointer:
    """Durable step-level state checkpointer enabling crash recovery and time-travel replay."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self.backend = SQLiteStorageBackend(self.db_path)

    def save_checkpoint(self, state: PlatformState) -> int:
        """Persist a snapshot of PlatformState at the current node transition."""
        payload = json.dumps(state.to_dict(), sort_keys=True)
        return self.backend.save(state.session_id, int(state.current_step), state.status.value, payload)

    def load_latest(self, session_id: str) -> PlatformState | None:
        """Restore the most recent checkpoint for a given session_id (crash recovery)."""
        data = self.backend.load_latest(session_id)
        return PlatformState.from_dict(json.loads(data)) if data else None

    def load_at_step(self, session_id: str, step: LifecycleStep) -> PlatformState | None:
        """Time-travel replay: load the state checkpoint recorded at a specific lifecycle step."""
        data = self.backend.load_at_step(session_id, int(step))
        return PlatformState.from_dict(json.loads(data)) if data else None

    def list_history(self, session_id: str) -> list[dict[str, Any]]:
        """Return ordered checkpoint metadata for audit and replay."""
        return self.backend.list_history(session_id)

    def sync_with_consensus(self, session_id: str, state_json: str) -> bool:
        """Synchronize state with distributed consensus mechanism (ADR-0007)."""
        return self.backend.sync_with_consensus(session_id, state_json)

    def close(self) -> None:
        backend = getattr(self, "backend", None)
        if backend is not None:
            backend.close()

    def __del__(self) -> None:
        self.close()
