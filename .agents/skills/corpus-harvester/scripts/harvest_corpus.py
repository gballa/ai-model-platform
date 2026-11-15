#!/usr/bin/env python3
"""CLI wrapper for corpus harvesting, RAG querying, and teacher trajectory distillation."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time
from typing import Any


def _ensure_src_on_path() -> None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "src"
        if (candidate / "platform_core").is_dir():
            src_str = str(candidate)
            if src_str not in sys.path:
                sys.path.insert(0, src_str)
            return


_ensure_src_on_path()


class RateLimitError(RuntimeError):
    """Raised when an external HTTP source exceeds its configured rate limit (HTTP 429)."""


def _positive_int(raw: str) -> int:
    try:
        val = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected positive integer, got {raw!r}.") from exc
    if val <= 0:
        raise argparse.ArgumentTypeError(f"Value must be > 0, got {val}.")
    return val


def _positive_float(raw: str) -> float:
    try:
        val = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected positive float, got {raw!r}.") from exc
    if val <= 0.0:
        raise argparse.ArgumentTypeError(f"Value must be > 0, got {val}.")
    return val


def _validate_safe_input_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if ".." in path.parts:
        raise PermissionError(f"Path traversal '..' rejected in input path: {raw_path}")
    if path.is_symlink():
        raise PermissionError(f"Symlinked input path rejected: {path}")
    return path


def _validate_safe_output_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if not raw_path.strip():
        raise ValueError("Output path must not be empty.")
    if ".." in path.parts:
        raise PermissionError(f"Path traversal '..' rejected in output path: {raw_path}")
    if path.is_symlink():
        raise PermissionError(f"Refusing to write to symlinked output path: {path}")
    if not path.is_absolute():
        cwd = Path.cwd().resolve()
        resolved = (cwd / path).resolve()
        if not resolved.is_relative_to(cwd):
            raise PermissionError(f"Relative output path escapes working directory: {raw_path}")
        cur = cwd
        for part in path.parts[:-1]:
            cur = cur / part
            if cur.is_symlink():
                raise PermissionError(f"Symlinked parent directory rejected: {cur}")
    if path.exists() and path.is_dir():
        raise IsADirectoryError(f"Output path is a directory: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_output(data: Any, output_file: str) -> None:
    """Write JSON result to `--output` after symlink and path-escape validation."""
    try:
        dest = _validate_safe_output_path(output_file)
        with dest.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"Success! Data written to: {dest}")
    except (OSError, PermissionError, ValueError, TypeError) as exc:
        print(f"Error writing output to {output_file}: {exc}", file=sys.stderr)
        sys.exit(1)


def _collect_directory_files(dirs: list[str], supported_exts: frozenset[str], limit: int) -> list[Path]:
    collected: list[Path] = []
    for raw_dir in dirs:
        dpath = _validate_safe_input_path(raw_dir)
        if not dpath.is_dir():
            raise FileNotFoundError(f"Book directory not found: {dpath}")
        resolved_root = dpath.resolve()
        for item in sorted(resolved_root.rglob("*")):
            if len(collected) >= limit:
                return collected
            if item.is_symlink() or not item.is_file():
                continue
            if not item.resolve().is_relative_to(resolved_root):
                continue
            if item.suffix.lower() in supported_exts:
                collected.append(item)
    return collected


def _handle_harvest_pdfs(args: argparse.Namespace) -> dict[str, Any]:
    import platform_core.layer1_intelligence  # noqa: F401 - avoid pre-existing layer3->layer1 cycle
    from platform_core.layer3_evolution.corpus_harvester import (
        CorpusHarvesterPipeline,
        PDFBookExtractor,
    )
    from platform_core.layer3_evolution.memory import HybridKnowledgeStore

    if not args.paths and not args.dirs:
        raise ValueError("Provide at least one --paths or --dirs argument.")

    selected_paths: list[Path] = []
    for raw_p in args.paths:
        if len(selected_paths) >= args.limit:
            break
        p = _validate_safe_input_path(raw_p)
        if not p.is_file():
            raise FileNotFoundError(f"Book file not found: {p}")
        selected_paths.append(p)

    if args.dirs and len(selected_paths) < args.limit:
        remaining = args.limit - len(selected_paths)
        selected_paths.extend(
            _collect_directory_files(args.dirs, PDFBookExtractor.SUPPORTED_EXTENSIONS, remaining)
        )

    rag_db = args.rag_db
    if rag_db != ":memory:":
        _validate_safe_output_path(rag_db) if not Path(rag_db).exists() else _validate_safe_input_path(rag_db)

    store = None if args.no_rag else HybridKnowledgeStore(db_path=rag_db)
    extractor = PDFBookExtractor()
    pipeline = CorpusHarvesterPipeline(knowledge_store=store, pdf_extractor=extractor)
    try:
        # Process directly when max_chars differs from default, otherwise via run_harvest
        docs = []
        rejected: list[dict[str, str]] = []
        for path in selected_paths[: args.limit]:
            try:
                docs.append(
                    extractor.extract_book(
                        path,
                        domain=args.domain,
                        license_id=args.license,
                        max_chars=args.max_chars,
                    )
                )
            except Exception as exc:
                rejected.append({"source": str(path), "reason": str(exc)})

        rag_stats: dict[str, Any] = {"ingested": False}
        if store is not None and not args.no_rag:
            chunks_ingested = 0
            for doc in docs:
                for idx, chunk in enumerate(doc.chunks):
                    store.ingest_document(
                        chunk_id=f"{doc.doc_id}#chunk-{idx}",
                        source_uri=doc.source_uri,
                        content=chunk,
                        metadata={
                            "domain": doc.domain,
                            "license_id": doc.license_id,
                            "source_type": doc.source_type,
                            "title": doc.title,
                        },
                    )
                    chunks_ingested += 1
            probe = store.retrieve("corpus status", top_k=1)
            rag_stats = {
                "ingested": True,
                "chunks_ingested": chunks_ingested,
                "retrieval_mode": probe["retrieval_mode"],
                "total_corpus_tokens": probe["total_corpus_tokens"],
                "rag_db": rag_db,
            }

        total_chunks = sum(len(d.chunks) for d in docs)
        total_tokens_est = sum(max(1, len(d.sanitized_text) // 4) for d in docs)
        return {
            "command": "harvest-pdfs",
            "limit": args.limit,
            "document_count": len(docs),
            "total_chunks": total_chunks,
            "total_tokens_est": total_tokens_est,
            "rejected_sources": rejected,
            "rag_ingestion_stats": rag_stats,
            "documents": [
                {
                    **asdict(d),
                    "chunks": list(d.chunks),
                    "injection_alerts": list(d.injection_alerts),
                }
                for d in docs
            ],
        }
    finally:
        pipeline.close()


def _handle_harvest_web(args: argparse.Namespace) -> dict[str, Any]:
    import platform_core.layer1_intelligence  # noqa: F401 - avoid pre-existing layer3->layer1 cycle
    from platform_core.layer3_evolution.corpus_harvester import (
        CorpusHarvesterPipeline,
        RateLimitError as HarvesterRateLimitError,
        RateLimitedWebHarvester,
    )
    from platform_core.layer3_evolution.memory import HybridKnowledgeStore

    urls = args.urls[: args.limit]
    rag_db = args.rag_db
    if rag_db != ":memory:":
        _validate_safe_output_path(rag_db) if not Path(rag_db).exists() else _validate_safe_input_path(rag_db)

    store = None if args.no_rag else HybridKnowledgeStore(db_path=rag_db)
    harvester = RateLimitedWebHarvester(
        allowed_domains=set(args.allowed_domains),
        requests_per_second=args.requests_per_second,
        max_retries=args.max_retries,
        session_tainted=args.session_tainted,
    )
    pipeline = CorpusHarvesterPipeline(knowledge_store=store, web_harvester=harvester)

    min_interval = 1.0 / args.requests_per_second
    last_ts = 0.0
    docs = []
    rejected: list[dict[str, str]] = []
    try:
        for url in urls:
            elapsed = time.monotonic() - last_ts
            if last_ts > 0.0 and elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            try:
                doc = harvester.fetch_url(url, domain=args.domain, license_id=args.license)
                last_ts = time.monotonic()
                docs.append(doc)
            except HarvesterRateLimitError as exc:
                raise RateLimitError(str(exc)) from exc
            except PermissionError as exc:
                last_ts = time.monotonic()
                rejected.append({"source": url, "reason": str(exc)})
            except Exception as exc:
                last_ts = time.monotonic()
                rejected.append({"source": url, "reason": str(exc)})

        rag_stats: dict[str, Any] = {"ingested": False}
        if store is not None and not args.no_rag and docs:
            chunks_ingested = 0
            for doc in docs:
                for idx, chunk in enumerate(doc.chunks):
                    store.ingest_document(
                        chunk_id=f"{doc.doc_id}#chunk-{idx}",
                        source_uri=doc.source_uri,
                        content=chunk,
                        metadata={
                            "domain": doc.domain,
                            "license_id": doc.license_id,
                            "source_type": doc.source_type,
                            "title": doc.title,
                        },
                    )
                    chunks_ingested += 1
            probe = store.retrieve("corpus status", top_k=1)
            rag_stats = {
                "ingested": True,
                "chunks_ingested": chunks_ingested,
                "retrieval_mode": probe["retrieval_mode"],
                "total_corpus_tokens": probe["total_corpus_tokens"],
                "rag_db": rag_db,
            }

        return {
            "command": "harvest-web",
            "limit": args.limit,
            "requests_per_second": args.requests_per_second,
            "session_tainted": bool(args.session_tainted),
            "document_count": len(docs),
            "total_chunks": sum(len(d.chunks) for d in docs),
            "total_tokens_est": sum(max(1, len(d.sanitized_text) // 4) for d in docs),
            "rejected_sources": rejected,
            "rag_ingestion_stats": rag_stats,
            "documents": [
                {
                    **asdict(d),
                    "chunks": list(d.chunks),
                    "injection_alerts": list(d.injection_alerts),
                }
                for d in docs
            ],
        }
    finally:
        pipeline.close()


def _handle_distill(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer1_intelligence.inference import (
        DeterministicMockBackend,
        OpenAICompatibleClient,
    )
    from platform_core.layer3_evolution.corpus_harvester import (
        HarvestedDocument,
        TeacherDistiller,
    )

    in_path = _validate_safe_input_path(args.input)
    if not in_path.is_file():
        raise FileNotFoundError(f"Harvest JSON input not found: {in_path}")
    payload = json.loads(in_path.read_text(encoding="utf-8"))
    raw_docs = payload.get("documents", [])
    if not isinstance(raw_docs, list):
        raise ValueError(f"Expected 'documents' list in {in_path}")

    docs: list[HarvestedDocument] = []
    for item in raw_docs[: args.limit]:
        docs.append(
            HarvestedDocument(
                doc_id=str(item["doc_id"]),
                source_uri=str(item["source_uri"]),
                source_type=str(item["source_type"]),
                domain=str(item["domain"]),
                title=str(item["title"]),
                license_id=str(item["license_id"]),
                sha256=str(item["sha256"]),
                raw_char_count=int(item["raw_char_count"]),
                sanitized_text=str(item["sanitized_text"]),
                chunks=tuple(str(c) for c in item.get("chunks", [])),
                injection_alerts=tuple(str(a) for a in item.get("injection_alerts", [])),
                metadata=dict(item.get("metadata") or {}),
            )
        )

    backend = (
        OpenAICompatibleClient(base_url=args.endpoint)
        if args.endpoint
        else DeterministicMockBackend()
    )
    distiller = TeacherDistiller(
        backend=backend,
        teacher_model_id=args.teacher_model,
        teacher_license_id=args.teacher_license,
    )
    records = distiller.synthesize_trajectories(
        documents=docs,
        target_domain=args.target_domain,
        max_samples_per_doc=3,
    )

    export_info: dict[str, Any] | None = None
    if args.jsonl_out:
        jsonl_path = _validate_safe_output_path(args.jsonl_out)
        export_info = distiller.export_distilled_jsonl(records, jsonl_path)

    return {
        "command": "distill",
        "limit": args.limit,
        "input_documents": len(docs),
        "teacher_model": args.teacher_model,
        "teacher_license": args.teacher_license,
        "backend_mode": "openai_compatible" if args.endpoint else "deterministic_mock",
        "synthesized_count": len(records),
        "export_info": export_info,
        "sample_record_ids": [r.record_id for r in records[:10]],
    }


def _handle_query_rag(args: argparse.Namespace) -> dict[str, Any]:
    import platform_core.layer1_intelligence  # noqa: F401 - avoid pre-existing layer3->layer1 cycle
    from platform_core.layer3_evolution.memory import HybridKnowledgeStore

    db_path = _validate_safe_input_path(args.rag_db)
    if not db_path.is_file():
        raise FileNotFoundError(f"RAG SQLite database not found: {db_path}")

    store = HybridKnowledgeStore(db_path=db_path)
    try:
        res = store.retrieve(args.query, top_k=args.limit)
        return {
            "command": "query-rag",
            "rag_db": str(db_path),
            "query": args.query,
            "limit": args.limit,
            "retrieval_mode": res["retrieval_mode"],
            "total_corpus_tokens": res["total_corpus_tokens"],
            "result_count": len(res["results"]),
            "results": res["results"][: args.limit],
        }
    finally:
        store.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Harvest PDFs/books/web pages, query HybridKnowledgeStore RAG, and distill trajectories."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_pdfs = sub.add_parser("harvest-pdfs", help="Extract & sanitize local PDF/MD/TXT/RST books")
    p_pdfs.add_argument("--paths", nargs="+", default=[], help="Explicit book/document file paths")
    p_pdfs.add_argument("--dirs", nargs="+", default=[], help="Directories to recursively scan for books")
    p_pdfs.add_argument("--domain", default="swe", help="Target corpus domain tag")
    p_pdfs.add_argument("--license", default="Apache-2.0", help="SPDX license identifier")
    p_pdfs.add_argument("--max-chars", type=_positive_int, default=2_000_000, help="Max chars per document")
    p_pdfs.add_argument("--rag-db", default=":memory:", help="SQLite DB path for HybridKnowledgeStore")
    p_pdfs.add_argument("--no-rag", action="store_true", help="Skip HybridKnowledgeStore ingestion")
    p_pdfs.add_argument("--limit", type=_positive_int, required=True, help="Maximum documents to harvest")
    p_pdfs.add_argument("--output", required=True, help="Output JSON report path")

    p_web = sub.add_parser("harvest-web", help="Rate-limited, firewall-gated public web harvesting")
    p_web.add_argument("--urls", nargs="+", required=True, help="Public URLs to harvest")
    p_web.add_argument("--allowed-domains", nargs="+", required=True, help="Explicit allowed hostnames")
    p_web.add_argument("--domain", default="cyber", help="Target corpus domain tag")
    p_web.add_argument("--license", default="Apache-2.0", help="SPDX license identifier")
    p_web.add_argument("--requests-per-second", type=_positive_float, default=1.0, help="Max requests/second")
    p_web.add_argument("--max-retries", type=_positive_int, default=3, help="Max retry attempts on 429/5xx")
    p_web.add_argument("--session-tainted", action="store_true", help="Mark session tainted (fail-closed egress)")
    p_web.add_argument("--rag-db", default=":memory:", help="SQLite DB path for HybridKnowledgeStore")
    p_web.add_argument("--no-rag", action="store_true", help="Skip HybridKnowledgeStore ingestion")
    p_web.add_argument("--limit", type=_positive_int, required=True, help="Maximum URLs to harvest")
    p_web.add_argument("--output", required=True, help="Output JSON report path")

    p_distill = sub.add_parser("distill", help="Synthesize hygiene-filtered training trajectories via TeacherDistiller")
    p_distill.add_argument("--input", required=True, help="Harvest JSON file from harvest-pdfs or harvest-web")
    p_distill.add_argument("--target-domain", default="swe_fuse", help="Target trajectory domain")
    p_distill.add_argument("--teacher-model", default="Qwen/Qwen3.5-35B-A3B", help="Teacher model ID")
    p_distill.add_argument("--teacher-license", default="Apache-2.0", help="Teacher SPDX license ID")
    p_distill.add_argument("--endpoint", default=None, help="Optional OpenAI-compatible teacher endpoint URL")
    p_distill.add_argument("--jsonl-out", default=None, help="Optional JSONL path for TrainingTrajectoryRecord export")
    p_distill.add_argument("--limit", type=_positive_int, required=True, help="Maximum harvested documents to distill")
    p_distill.add_argument("--output", required=True, help="Output JSON summary path")

    p_rag = sub.add_parser("query-rag", help="Query persisted HybridKnowledgeStore SQLite database")
    p_rag.add_argument("--rag-db", required=True, help="Path to HybridKnowledgeStore SQLite database")
    p_rag.add_argument("--query", required=True, help="Search query text")
    p_rag.add_argument("--limit", type=_positive_int, required=True, help="Maximum chunks (top_k) to return")
    p_rag.add_argument("--output", required=True, help="Output JSON result path")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "harvest-pdfs":
            data = _handle_harvest_pdfs(args)
        elif args.command == "harvest-web":
            data = _handle_harvest_web(args)
        elif args.command == "distill":
            data = _handle_distill(args)
        elif args.command == "query-rag":
            data = _handle_query_rag(args)
        else:
            print(f"Unknown command: {args.command}", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"Error ({args.command}): {exc}", file=sys.stderr)
        return 1

    write_output(data, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
