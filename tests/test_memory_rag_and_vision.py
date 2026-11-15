"""Tests for Layer 3 persistent RAG, bitemporal memory, project context, and visual/doc inspection."""

from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from platform_core.layer1_intelligence import DeterministicMockBackend
from platform_core.layer2_execution import DataAndVisualMCPServer
from platform_core.layer3_evolution import (
    BitemporalEpisodicMemory,
    DeterministicHashEmbedder,
    HybridKnowledgeStore,
    ProjectContextManager,
)


def _make_minimal_rgba_png(width: int, height: int) -> bytes:
    """Create a valid minimal RGBA PNG image using pure stdlib zlib + struct."""
    sig = b"\x89PNG\r\n\x1a\n"

    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw_scanlines = b"".join(b"\x00" + (b"\x10\x20\x30\xff" * width) for _ in range(height))
    idat = zlib.compress(raw_scanlines)
    return sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


class TestMemoryRagAndVision(unittest.TestCase):
    def test_persistent_sqlite_episodic_memory_and_rag_directory_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            mem_db = root / "episodic.db"
            rag_db = root / "knowledge.db"
            corpus_dir = root / "corpus"
            corpus_dir.mkdir()
            (corpus_dir / "auth_notes.md").write_text(
                "# Authentication Hardening\nUse Ed25519 signatures for MCP manifests.\n",
                encoding="utf-8",
            )
            (corpus_dir / "binary_notes.py").write_text(
                "def check_elf_magic(b: bytes) -> bool:\n    return b.startswith(b'\\x7fELF')\n",
                encoding="utf-8",
            )
            # Symlink inside corpus must be rejected/skipped cleanly without escaping root
            outside = root / "secret.txt"
            outside.write_text("TOP_SECRET_OUTSIDE", encoding="utf-8")
            (corpus_dir / "escape.txt").symlink_to(outside)

            mem = BitemporalEpisodicMemory(db_path=mem_db)
            mem.append_event("sess-1", "architecture_decision", "Adopted Ed25519 MCP signing")
            f1 = mem.upsert_architectural_fact("auth", "algorithm", "HMAC-SHA256", "c1")
            f2 = mem.upsert_architectural_fact("auth", "algorithm", "Ed25519", "c2")
            self.assertFalse(f1.is_currently_valid)
            self.assertTrue(f2.is_currently_valid)
            mem.close()

            # Reopen persistent DB to confirm WAL durability
            mem2 = BitemporalEpisodicMemory(db_path=mem_db)
            current = mem2.query_active_facts(subject="auth")
            self.assertEqual(len(current), 1)
            self.assertEqual(current[0].object_val, "Ed25519")

            embedder = DeterministicHashEmbedder(dim=64)
            store = HybridKnowledgeStore(db_path=rag_db, embedder=embedder)
            stats = store.ingest_directory(corpus_dir)
            self.assertGreaterEqual(stats["files_indexed"], 2)
            self.assertGreaterEqual(stats["chunks_indexed"], 2)

            # <200,000 token invariant enforces DIRECT_PREFIX_CACHE
            small_res = store.retrieve("Ed25519 MCP manifest signature", top_k=2)
            self.assertEqual(small_res["retrieval_mode"], "DIRECT_PREFIX_CACHE")

            # Test ProjectContextManager packing with bitemporal facts + RAG
            ctx_mgr = ProjectContextManager(knowledge_store=store, episodic_memory=mem2, max_context_tokens=8000)
            pack = ctx_mgr.build_context_pack(query="Ed25519 MCP", subject="auth", code_skeletons={"auth.py": "def verify(): ..."})
            self.assertEqual(pack["active_facts"][0]["object"], "Ed25519")
            self.assertEqual(pack["code_skeleton_files"], ["auth.py"])

            # Exceed >= 200,000 tokens -> HYBRID_PGVECTORSCALE_SEARCH (SQLite FTS5 + Cosine RRF)
            store.ingest_document(
                chunk_id="huge_doc",
                source_uri="file://docs/big.md",
                content="word " * 210_000,
            )
            hybrid_res = store.retrieve("Ed25519 MCP signatures", top_k=2)
            self.assertEqual(hybrid_res["retrieval_mode"], "HYBRID_PGVECTORSCALE_SEARCH")
            self.assertGreaterEqual(len(hybrid_res["results"]), 1)
            self.assertNotIn("TOP_SECRET_OUTSIDE", str(hybrid_res))
            store.close()
            mem2.close()

    def test_visual_and_document_inspection_and_symlink_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            png_path = root / "diagram.png"
            png_path.write_bytes(_make_minimal_rgba_png(64, 32))

            img_meta = DataAndVisualMCPServer.inspect_image_artifact(png_path)
            self.assertEqual(img_meta["format"], "PNG")
            self.assertEqual(img_meta["width"], 64)
            self.assertEqual(img_meta["height"], 32)
            self.assertTrue(len(img_meta["sha256"]) == 64)

            txt_path = root / "advisory.md"
            txt_path.write_text("# CVE-2026-1000\nPatch available.\n", encoding="utf-8")
            doc_info = DataAndVisualMCPServer.extract_document_text(txt_path)
            self.assertIn("CVE-2026-1000", doc_info["text"])

            mock_vlm = DeterministicMockBackend()
            unified_png = DataAndVisualMCPServer.analyze_visual_artifact(
                png_path,
                prompt="Describe observed diagram components",
                backend=mock_vlm,
            )
            self.assertEqual(unified_png["image_meta"]["format"], "PNG")
            self.assertTrue(unified_png["visual_grounding"]["epistemic_hallucination_guard_active"])

            bad_link = root / "evil.png"
            bad_link.symlink_to(png_path)
            with self.assertRaises(PermissionError):
                DataAndVisualMCPServer.inspect_image_artifact(bad_link)


if __name__ == "__main__":
    unittest.main()
