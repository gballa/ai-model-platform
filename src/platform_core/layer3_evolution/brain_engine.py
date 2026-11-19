"""Layer 3 Project Brain Knowledge Graph Synchronization, Querying, and Heretic Model Training Pipeline.

Implements:
1. `BrainSyncReport`: Summary metrics after synchronizing `.agents/brain/` into `HybridKnowledgeStore`
   and `BitemporalEpisodicMemory`.
2. `BrainQueryResult`: Unified query response combining 200K-token hybrid RAG retrieval, active or
   point-in-time bitemporal facts, and ontology graph nodes/invariants.
3. `BrainPipelineReport`: End-to-end execution report for training domain-specialized micro SLMs on the
   Project Brain corpus, running GAIN per-sample scheduling, Heretic rank-k refusal abliteration,
   Cold-Fusion DARE-TIES multi-model merging, and IMatrix GGUF/MLX quantization calibration.
4. `ProjectBrainEngine`: Orchestrates `.agents/brain/` synchronization, querying, and Heretic + Cold-Fusion
   model creation verified by `SafetensorsValidator`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
import json
from pathlib import Path
import re
from typing import Any

from platform_core.deploy_security.governance import SafetensorsValidator
from platform_core.layer1_intelligence.scratch_trainer import (
    CompactTransformerSLMTrainer,
    ScratchSLMConfig,
)
from platform_core.layer3_evolution.memory import (
    BitemporalEpisodicMemory,
    HybridKnowledgeStore,
)


def _serialize_value(val: Any) -> Any:
    """Recursively convert dataclasses, tuples, and Paths into JSON-serializable primitives."""
    if is_dataclass(val) and not isinstance(val, type):
        if hasattr(val, "to_dict") and callable(val.to_dict):
            return val.to_dict()
        return {k: _serialize_value(v) for k, v in asdict(val).items()}
    if isinstance(val, Path):
        return str(val)
    if isinstance(val, dict):
        return {str(k): _serialize_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_serialize_value(v) for v in val]
    return val


def _validate_positive_int(val: Any, name: str) -> int:
    if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
        raise ValueError(f"{name} must be a positive integer (got {val!r}).")
    return val


@dataclass(frozen=True)
class BrainSyncReport:
    """Report produced when synchronizing `.agents/brain/` into RAG and Bitemporal Memory."""

    nodes_loaded: int
    edges_loaded: int
    invariants_loaded: int
    facts_upserted: int
    chunks_indexed: int
    total_tokens: int
    retrieval_mode: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes_loaded": self.nodes_loaded,
            "edges_loaded": self.edges_loaded,
            "invariants_loaded": self.invariants_loaded,
            "facts_upserted": self.facts_upserted,
            "chunks_indexed": self.chunks_indexed,
            "total_tokens": self.total_tokens,
            "retrieval_mode": self.retrieval_mode,
        }


@dataclass(frozen=True)
class BrainQueryResult:
    """Structured result from querying the synchronized Project Brain."""

    query: str
    retrieval_mode: str
    top_chunks: list[dict[str, Any]]
    matching_nodes: list[dict[str, Any]]
    matching_invariants: list[dict[str, Any]]
    active_facts: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "retrieval_mode": self.retrieval_mode,
            "top_chunks": _serialize_value(self.top_chunks),
            "matching_nodes": _serialize_value(self.matching_nodes),
            "matching_invariants": _serialize_value(self.matching_invariants),
            "active_facts": _serialize_value(self.active_facts),
        }


@dataclass(frozen=True)
class BrainPipelineReport:
    """End-to-end report from the Project Brain Heretic + GAIN + Cold-Fusion training pipeline."""

    model_id: str
    domain: str
    brain_sync: BrainSyncReport
    gain_sample_count: int
    gain_mean_effective_lr: float
    gain_mean_advantage_multiplier: float
    specialist_a_safetensors: str
    specialist_b_safetensors: str
    abliterated_safetensors: str
    merged_safetensors: str
    merged_safetensors_sha256: str
    abliteration_report: dict[str, Any]
    cold_fusion_report: dict[str, Any]
    imatrix_report: dict[str, Any]
    safetensors_validation: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "domain": self.domain,
            "brain_sync": self.brain_sync.to_dict(),
            "gain_sample_count": self.gain_sample_count,
            "gain_mean_effective_lr": self.gain_mean_effective_lr,
            "gain_mean_advantage_multiplier": self.gain_mean_advantage_multiplier,
            "specialist_a_safetensors": self.specialist_a_safetensors,
            "specialist_b_safetensors": self.specialist_b_safetensors,
            "abliterated_safetensors": self.abliterated_safetensors,
            "merged_safetensors": self.merged_safetensors,
            "merged_safetensors_sha256": self.merged_safetensors_sha256,
            "abliteration_report": _serialize_value(self.abliteration_report),
            "cold_fusion_report": _serialize_value(self.cold_fusion_report),
            "imatrix_report": _serialize_value(self.imatrix_report),
            "safetensors_validation": _serialize_value(self.safetensors_validation),
        }


class ProjectBrainEngine:
    """Synchronizes `.agents/brain/` with Bitemporal Memory, Hybrid RAG, and Heretic SLM pipelines."""

    GRAPH_FILENAME: str = "brain-knowledge-graph.json"

    def __init__(
        self,
        brain_dir: str | Path = ".agents/brain",
        memory_db_path: str | Path = ":memory:",
        rag_db_path: str | Path = ":memory:",
    ) -> None:
        raw_path = Path(brain_dir)
        if raw_path.is_symlink():
            raise PermissionError(f"Symlinked brain_dir rejected: {raw_path}")
        if not raw_path.exists() or not raw_path.is_dir():
            raise FileNotFoundError(f"Project brain directory not found: {raw_path}")

        self.brain_dir: Path = raw_path.resolve()
        self.memory = BitemporalEpisodicMemory(memory_db_path)
        self.knowledge_store = HybridKnowledgeStore(rag_db_path)
        self._graph_data: dict[str, Any] = {}
        self._synced: bool = False
        self._last_sync_report: BrainSyncReport | None = None

    def close(self) -> None:
        """Close underlying SQLite connections."""
        self.memory.close()
        self.knowledge_store.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def sync_brain(self) -> BrainSyncReport:
        """Synchronize `brain-knowledge-graph.json` and `.md` files into RAG and Bitemporal Memory."""
        graph_path = self.brain_dir / self.GRAPH_FILENAME
        if graph_path.is_symlink():
            raise PermissionError(f"Symlinked brain knowledge graph rejected: {graph_path}")
        if not graph_path.is_file():
            raise FileNotFoundError(f"Brain knowledge graph file not found: {graph_path}")

        raw_graph = json.loads(graph_path.read_text(encoding="utf-8"))
        if not isinstance(raw_graph, dict):
            raise ValueError(f"Invalid JSON object in {graph_path}")
        self._graph_data = raw_graph

        nodes: list[dict[str, Any]] = list(raw_graph.get("nodes", []))
        edges: list[dict[str, Any]] = list(raw_graph.get("edges", []))
        invariants: list[dict[str, Any]] = list(raw_graph.get("invariants", []))
        bitemporal_facts: list[dict[str, Any]] = list(raw_graph.get("bitemporal_facts", []))

        chunks_indexed = 0

        for node in nodes:
            node_id = str(node.get("id", "")).strip()
            if not node_id:
                continue
            exports_str = ", ".join(str(x) for x in node.get("exports", []))
            content = (
                f"Node {node_id} ({node.get('label', '')}) [{node.get('layer', '')} / {node.get('category', '')}]\n"
                f"Path: {node.get('path', '')}\n"
                f"Summary: {node.get('summary', '')}\n"
                f"Exports: {exports_str}"
            )
            self.knowledge_store.ingest_document(
                chunk_id=f"brain-node:{node_id}",
                source_uri=f"brain://{self.GRAPH_FILENAME}#node/{node_id}",
                content=content,
                metadata={"type": "node", "id": node_id, "path": node.get("path", "")},
            )
            chunks_indexed += 1

        for inv in invariants:
            inv_id = str(inv.get("id", "")).strip()
            if not inv_id:
                continue
            enforced_str = ", ".join(str(x) for x in inv.get("enforced_in", []))
            content = (
                f"Invariant {inv_id}: {inv.get('title', '')}\n"
                f"Rule: {inv.get('rule', '')}\n"
                f"Enforced in: {enforced_str}"
            )
            self.knowledge_store.ingest_document(
                chunk_id=f"brain-invariant:{inv_id}",
                source_uri=f"brain://{self.GRAPH_FILENAME}#invariant/{inv_id}",
                content=content,
                metadata={"type": "invariant", "id": inv_id},
            )
            chunks_indexed += 1

        dir_stats = self.knowledge_store.ingest_directory(
            self.brain_dir,
            extensions=(".md",),
        )
        chunks_indexed += int(dir_stats.get("chunks_indexed", 0))

        facts_upserted = 0
        for fact in bitemporal_facts:
            subject = str(fact.get("subject", "")).strip()
            predicate = str(fact.get("predicate", "")).strip()
            object_val = str(fact.get("object_val", "")).strip()
            commit_sha = str(fact.get("commit_sha", "v1.0.0")).strip()
            valid_from_raw = fact.get("valid_from")
            valid_from = float(valid_from_raw) if valid_from_raw is not None else None
            if subject and predicate and object_val:
                self.memory.upsert_architectural_fact(
                    subject=subject,
                    predicate=predicate,
                    object_val=object_val,
                    commit_sha=commit_sha,
                    valid_from=valid_from,
                )
                facts_upserted += 1

        self.memory.append_event(
            session_id="project-brain",
            event_type="BRAIN_SYNC",
            summary=(
                f"Synchronized {len(nodes)} nodes, {len(edges)} edges, "
                f"{len(invariants)} invariants, and {facts_upserted} bitemporal facts."
            ),
            commit_sha=str(raw_graph.get("project_version", "v1.0.0")),
        )

        rag_probe = self.knowledge_store.retrieve("platform_core architecture invariants", top_k=5)
        total_tokens = int(rag_probe.get("total_corpus_tokens", 0))
        retrieval_mode = str(rag_probe.get("retrieval_mode", "DIRECT_PREFIX_CACHE"))

        report = BrainSyncReport(
            nodes_loaded=len(nodes),
            edges_loaded=len(edges),
            invariants_loaded=len(invariants),
            facts_upserted=facts_upserted,
            chunks_indexed=chunks_indexed,
            total_tokens=total_tokens,
            retrieval_mode=retrieval_mode,
        )
        self._synced = True
        self._last_sync_report = report
        return report

    def query_brain(
        self,
        query: str,
        top_k: int = 5,
        as_of: float | None = None,
    ) -> BrainQueryResult:
        """Query the Project Brain across Hybrid RAG, Bitemporal Memory, and Ontology Nodes/Invariants."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be a non-empty string.")
        _validate_positive_int(top_k, "top_k")
        if as_of is not None:
            if isinstance(as_of, bool) or not isinstance(as_of, (int, float)):
                raise ValueError("as_of must be a float timestamp or None.")

        if not self._synced:
            self.sync_brain()

        rag_result = self.knowledge_store.retrieve(query, top_k=top_k)
        retrieval_mode = str(rag_result.get("retrieval_mode", "DIRECT_PREFIX_CACHE"))
        all_results = list(rag_result.get("results", []))
        top_chunks = all_results[:top_k]

        if as_of is not None:
            fact_edges = self.memory.query_facts_as_of(float(as_of))
        else:
            fact_edges = self.memory.query_active_facts()

        active_facts = [
            {
                "fact_id": f.fact_id,
                "subject": f.subject,
                "predicate": f.predicate,
                "object_val": f.object_val,
                "commit_sha": f.commit_sha,
                "valid_from": f.valid_from,
                "valid_to": f.valid_to,
                "invalid_at": f.invalid_at,
            }
            for f in fact_edges
        ]

        keywords = [
            tok
            for tok in re.findall(r"[a-z0-9_]+", query.lower())
            if len(tok) >= 2
        ]

        nodes: list[dict[str, Any]] = list(self._graph_data.get("nodes", []))
        invariants: list[dict[str, Any]] = list(self._graph_data.get("invariants", []))

        matching_nodes: list[dict[str, Any]] = []
        for node in nodes:
            blob = json.dumps(node, sort_keys=True).lower()
            if not keywords or any(kw in blob for kw in keywords):
                matching_nodes.append(dict(node))

        matching_invariants: list[dict[str, Any]] = []
        for inv in invariants:
            blob = json.dumps(inv, sort_keys=True).lower()
            if not keywords or any(kw in blob for kw in keywords):
                matching_invariants.append(dict(inv))

        return BrainQueryResult(
            query=query,
            retrieval_mode=retrieval_mode,
            top_chunks=top_chunks,
            matching_nodes=matching_nodes,
            matching_invariants=matching_invariants,
            active_facts=active_facts,
        )

    def _collect_brain_corpus_texts(self) -> list[str]:
        """Extract training & calibration texts from the synchronized `.agents/brain/` store."""
        if not self._synced:
            self.sync_brain()

        rag_dump = self.knowledge_store.retrieve("platform_core architecture security", top_k=64)
        texts: list[str] = [
            str(item["content"]).strip()
            for item in rag_dump.get("results", [])
            if str(item.get("content", "")).strip()
        ]
        if not texts:
            for md_file in sorted(self.brain_dir.glob("*.md")):
                if not md_file.is_symlink() and md_file.is_file():
                    content = md_file.read_text(encoding="utf-8", errors="replace").strip()
                    if content:
                        texts.append(content)
        return texts

    def run_brain_training_pipeline(
        self,
        output_dir: str | Path,
        model_id: str = "heretic-brain-slm",
        domain: str = "swe",
        steps: int = 10,
        abliteration_rank: int = 2,
        dare_drop_rate: float = 0.5,
        quant_type: str = "Q5_K_M",
    ) -> BrainPipelineReport:
        """Train two domain SLMs on `.agents/brain/`, run GAIN + Heretic abliteration + Cold-Fusion + IMatrix."""
        if not isinstance(model_id, str) or not model_id.strip():
            raise ValueError("model_id must be a non-empty string.")
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("domain must be a non-empty string.")
        _validate_positive_int(steps, "steps")
        _validate_positive_int(abliteration_rank, "abliteration_rank")
        if isinstance(dare_drop_rate, bool) or not isinstance(dare_drop_rate, (int, float)):
            raise ValueError("dare_drop_rate must be a float in [0.0, 1.0).")

        out_path = Path(output_dir)
        if out_path.is_symlink():
            raise PermissionError(f"Symlinked output_dir rejected: {out_path}")
        resolved_out = out_path.resolve()
        resolved_out.mkdir(parents=True, exist_ok=True)

        from platform_core.layer1_intelligence.heretic import (
            ColdFusionMergeConfig,
            ColdFusionModelMerger,
            GAINAdaptiveScheduler,
            HereticAbliterator,
            HereticConfig,
            ImatrixQuantizationCalibrator,
        )

        sync_report = self.sync_brain()
        corpus_texts = self._collect_brain_corpus_texts()

        # 1. GAIN dynamic per-sample learning rate & GRPO advantage scheduling
        gain_scheduler = GAINAdaptiveScheduler()
        gain_weights = gain_scheduler.compute_sample_weights(corpus_texts, base_lr=3e-4)
        if gain_weights:
            mean_lr = round(
                sum(float(w.effective_lr) for w in gain_weights) / len(gain_weights),
                8,
            )
            mean_adv = round(
                sum(float(w.grpo_advantage_multiplier) for w in gain_weights) / len(gain_weights),
                6,
            )
        else:
            mean_lr = 3e-4
            mean_adv = 1.0

        # 2. Train two domain-specialized micro SLMs on the Brain corpus with different seeds
        clean_model_id = model_id.strip()
        clean_domain = domain.strip().lower()
        model_a_id = f"{clean_model_id}-{clean_domain}-a"
        model_b_id = f"{clean_model_id}-cyber-b"

        trainer = CompactTransformerSLMTrainer()
        cfg_a = ScratchSLMConfig(
            model_id=model_a_id,
            vocab_size=320,
            d_model=32,
            n_layers=2,
            n_heads=4,
            d_ff=64,
            max_seq_len=64,
            learning_rate=0.05,
            steps=steps,
            batch_size=2,
            seed=42,
            domain=clean_domain,
            execution_backend="stdlib",
        )
        cfg_b = ScratchSLMConfig(
            model_id=model_b_id,
            vocab_size=320,
            d_model=32,
            n_layers=2,
            n_heads=4,
            d_ff=64,
            max_seq_len=64,
            learning_rate=0.05,
            steps=steps,
            batch_size=2,
            seed=1337,
            domain="cyber",
            execution_backend="stdlib",
        )

        artifact_a = trainer.train_and_export(cfg_a, corpus_texts, resolved_out)
        artifact_b = trainer.train_and_export(cfg_b, corpus_texts, resolved_out)

        # 3. Heretic Rank-k Refusal Subspace Abliteration on Specialist A
        abliterated_a_path = resolved_out / f"{model_a_id}-abliterated.safetensors"
        heretic_cfg = HereticConfig(rank=abliteration_rank)
        abliteration_report = HereticAbliterator().abliterate_safetensors(
            artifact_a.safetensors_path,
            abliterated_a_path,
            config=heretic_cfg,
        )

        # 4. Cold-Fusion DARE-TIES Merge of Abliterated Specialist A + Cyber Specialist B
        final_merged_safetensors_path = resolved_out / f"{clean_model_id}-cold-fusion.safetensors"
        merge_cfg = ColdFusionMergeConfig(method="dare_ties", drop_rate=float(dare_drop_rate))
        cold_fusion_report = ColdFusionModelMerger().merge_safetensors(
            [abliterated_a_path, artifact_b.safetensors_path],
            final_merged_safetensors_path,
            config=merge_cfg,
        )

        # 5. IMatrix Activation-Aware GGUF & MLX Quantization Calibration Plan
        calibration_texts = corpus_texts[:16]
        imatrix_report = ImatrixQuantizationCalibrator().calibrate_and_build_gguf_plan(
            final_merged_safetensors_path,
            calibration_texts,
            resolved_out,
            quant_type=quant_type,
        )

        # 6. Cryptographic & structural Safetensors verification
        st_validation = SafetensorsValidator().validate_file(final_merged_safetensors_path)

        return BrainPipelineReport(
            model_id=clean_model_id,
            domain=clean_domain,
            brain_sync=sync_report,
            gain_sample_count=len(gain_weights),
            gain_mean_effective_lr=mean_lr,
            gain_mean_advantage_multiplier=mean_adv,
            specialist_a_safetensors=str(artifact_a.safetensors_path),
            specialist_b_safetensors=str(artifact_b.safetensors_path),
            abliterated_safetensors=str(abliterated_a_path),
            merged_safetensors=str(final_merged_safetensors_path),
            merged_safetensors_sha256=str(st_validation["sha256"]),
            abliteration_report=_serialize_value(abliteration_report),
            cold_fusion_report=_serialize_value(cold_fusion_report),
            imatrix_report=_serialize_value(imatrix_report),
            safetensors_validation={
                "artifact_name": st_validation["artifact_name"],
                "sha256": st_validation["sha256"],
                "header_size": st_validation["header_size"],
                "data_bytes": st_validation["data_bytes"],
                "tensor_count": st_validation["tensor_count"],
            },
        )
