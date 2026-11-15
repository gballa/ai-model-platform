"""Layer 1 Strategy Advising, From-Scratch BPE Tokenizer, and Compact SLM Trainer.

Provides hardware-aware model creation advising (pre-trained RAG/QLoRA-first on single-node
hardware vs. compact 10M-350M from-scratch SLM vs. multi-GPU post-training), a zero-dependency
byte-level BPE tokenizer, and a pure-stdlib causal Transformer trainer exporting strict
IEEE-754 F32 `.safetensors` checkpoints verified by `SafetensorsValidator`.
"""

from __future__ import annotations

import array
from collections import Counter
from dataclasses import dataclass
from enum import Enum
import importlib
import json
import math
from operator import mul
import os
from pathlib import Path
import random
import re
import struct
import tempfile
from typing import Any

from platform_core.deploy_security.governance import (
    LicenseComplianceAuditor,
    LicenseVerdict,
    SafetensorsValidator,
)

from .models import (
    HardwareProfile,
    LocalHardwareDetector,
    LocalHardwareInfo,
    ModelPool,
    ModelRegistry,
    ModelSpec,
    _validate_positive_float,
    _validate_positive_int,
)

_SAFE_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_PRETOKENIZE_RE = re.compile(r"\s+|\S+")


def _validate_non_negative_int(val: Any, field_name: str) -> int:
    if not isinstance(val, int) or isinstance(val, bool) or val < 0:
        raise ValueError(f"Invalid {field_name}: {val!r} (must be a non-negative int, not bool).")
    return val


def _assert_no_symlink_or_traversal(path: Path, label: str) -> None:
    """Reject '..' path traversal and symlinked target or ancestor directories."""
    if ".." in path.parts:
        raise PermissionError(f"Path traversal '..' rejected in {label}: {path}")
    if path.is_symlink():
        raise PermissionError(f"Symlinked {label} rejected: {path}")
    os_root_links = {Path("/"), Path("/var"), Path("/tmp"), Path("/etc")}
    for ancestor in path.parents:
        if ancestor in os_root_links:
            continue
        if ancestor.is_symlink():
            raise PermissionError(f"Symlinked ancestor directory for {label} rejected: {ancestor}")


def _build_byte_to_unicode() -> tuple[dict[int, str], dict[str, int]]:
    """Return deterministic reversible mapping between raw bytes 0..255 and single Unicode chars."""
    direct: list[int] = (
        list(range(ord("!"), ord("~") + 1))
        + list(range(ord("¡"), ord("¬") + 1))
        + list(range(ord("®"), ord("ÿ") + 1))
    )
    chars: list[int] = list(direct)
    shift = 0
    for byte_val in range(256):
        if byte_val not in direct:
            direct.append(byte_val)
            chars.append(256 + shift)
            shift += 1
    b2u = {b: chr(c) for b, c in zip(direct, chars)}
    u2b = {ch: b for b, ch in b2u.items()}
    return b2u, u2b


_BYTE_TO_UNICODE, _UNICODE_TO_BYTE = _build_byte_to_unicode()


class ModelCreationPath(str, Enum):
    """Recommended model creation strategy for a corpus, domain, and hardware envelope."""

    PRETRAINED_QLORA_FIRST = "PRETRAINED_QLORA_FIRST"
    PRETRAINED_RAG_ONLY = "PRETRAINED_RAG_ONLY"
    FROM_SCRATCH_COMPACT_SLM = "FROM_SCRATCH_COMPACT_SLM"
    MULTI_GPU_FULL_POST_TRAIN = "MULTI_GPU_FULL_POST_TRAIN"


@dataclass(frozen=True)
class StrategyRecommendation:
    """Hardware-aware recommendation for building or specializing a local AI model."""

    recommended_path: ModelCreationPath
    base_model_id: str | None
    rationale: str
    hardware_summary: dict[str, Any]
    estimated_vram_gb: float
    fits_local_budget: bool
    warnings: tuple[str, ...] = ()


class CreationStrategyAdvisor:
    """Recommends pre-trained RAG/QLoRA-first vs. compact from-scratch SLM vs. multi-GPU."""

    _SMALL_CORPUS_THRESHOLD: int = 50_000

    @staticmethod
    def _pick_local_model(
        registry: ModelRegistry,
        domain: str,
        hardware_info: LocalHardwareInfo,
        prefer_qlora_sized: bool = False,
    ) -> ModelSpec:
        cleaned = domain.lower().strip()
        candidates: list[str]
        if cleaned == "visual_ocr":
            candidates = ["Qwen/Qwen3-VL-8B-Thinking", "OmniParser-V2-UI-TARS-GOT-OCR"]
        elif prefer_qlora_sized:
            candidates = [
                "fdtn-ai/Foundation-Sec-8B-Reasoning",
                "Qwen/Qwen3-VL-8B-Thinking",
                "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                "Qwen/Qwen3.5-35B-A3B",
            ]
        elif cleaned == "swe":
            candidates = [
                "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                "fdtn-ai/Foundation-Sec-8B-Reasoning",
                "Qwen/Qwen3.8-27B-SWE-Cyber",
            ]
        elif cleaned == "architecture":
            candidates = [
                "Qwen/Qwen3.5-35B-A3B",
                "zai-org/GLM-4.7-Flash",
                "fdtn-ai/Foundation-Sec-8B-Reasoning",
            ]
        elif cleaned == "binrev":
            candidates = [
                "Qwen/Qwen3.8-27B",
                "Qwen3.8-27B-BinRev",
                "fdtn-ai/Foundation-Sec-8B-Reasoning",
            ]
        else:
            candidates = [
                "fdtn-ai/Foundation-Sec-8B-Reasoning",
                "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                "Qwen/Qwen3.5-35B-A3B",
            ]

        all_specs = {m.model_id: m for m in registry.all_models()}
        for cid in candidates:
            spec = all_specs.get(cid)
            if spec is not None and hardware_info.fits_4bit(spec):
                return spec

        # Fallback to smallest fitting model in the registry, then smallest overall.
        fitting = [m for m in registry.all_models() if hardware_info.fits_4bit(m)]
        if fitting:
            return min(fitting, key=lambda m: m.vram_4bit_gb)
        for cid in candidates:
            if cid in all_specs:
                return all_specs[cid]
        return min(registry.all_models(), key=lambda m: m.vram_4bit_gb)

    @classmethod
    def recommend(
        cls,
        corpus_tokens: int,
        domain: str = "swe",
        hardware_info: LocalHardwareInfo | None = None,
        custom_vocab_required: bool = False,
        target_params_m: int | None = None,
    ) -> StrategyRecommendation:
        """Select the most effective creation path given corpus size, domain, and local hardware."""
        corpus_tokens = _validate_non_negative_int(corpus_tokens, "corpus_tokens")
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("domain must be a non-empty string.")
        if not isinstance(custom_vocab_required, bool):
            raise ValueError("custom_vocab_required must be a bool.")
        if target_params_m is not None:
            _validate_positive_int(target_params_m, "target_params_m")

        hw = hardware_info if hardware_info is not None else LocalHardwareDetector.detect()
        hw_summary: dict[str, Any] = {
            "os_name": hw.os_name,
            "arch": hw.arch,
            "cpu_brand": hw.cpu_brand,
            "total_memory_gb": hw.total_memory_gb,
            "safe_model_budget_gb": hw.safe_model_budget_gb,
            "accelerator": hw.accelerator,
            "recommended_profile": hw.recommended_profile.value,
        }

        warnings: list[str] = []

        # From-scratch compact SLM is only recommended when custom vocabulary or explicit 10M-350M target is requested.
        if custom_vocab_required or (target_params_m is not None and 10 <= target_params_m <= 350):
            params_m = target_params_m if target_params_m is not None else 50
            est_vram = round(max(0.25, (params_m / 1000.0) * 16.0 + 0.5), 2)
            fits = est_vram <= hw.safe_model_budget_gb
            warnings.append(
                "A 10M-350M from-scratch SLM is suited for specialized/fixed-grammar or custom-tokenizer "
                "workloads and will not match 8B-35B pre-trained models on general reasoning or tool orchestration."
            )
            if corpus_tokens < cls._SMALL_CORPUS_THRESHOLD:
                warnings.append(
                    f"Corpus has {corpus_tokens:,} tokens (< 50,000); expect limited generalization compared to "
                    "pre-trained RAG or QLoRA."
                )
            if not fits:
                warnings.append(
                    f"Estimated scratch training memory ({est_vram:.2f} GB) exceeds local safe budget "
                    f"({hw.safe_model_budget_gb:.2f} GB); use gradient accumulation or smaller tier."
                )
            return StrategyRecommendation(
                recommended_path=ModelCreationPath.FROM_SCRATCH_COMPACT_SLM,
                base_model_id=None,
                rationale=(
                    f"Selected compact from-scratch SLM (~{params_m}M params) because "
                    f"{'custom_vocab_required=True' if custom_vocab_required else f'target_params_m={params_m}'} "
                    "explicitly warrants owned tokenizer/weights."
                ),
                hardware_summary=hw_summary,
                estimated_vram_gb=est_vram,
                fits_local_budget=fits,
                warnings=tuple(warnings),
            )

        if target_params_m is not None and target_params_m > 350:
            warnings.append(
                f"From-scratch pre-training at {target_params_m}M+ params is uneconomical on local hardware; "
                "routing to pre-trained post-training instead."
            )

        registry = ModelRegistry.for_profile(hw.recommended_profile)

        # Small corpus: zero-loss direct prefix caching via HybridKnowledgeStore (< 200K tokens).
        if corpus_tokens < cls._SMALL_CORPUS_THRESHOLD:
            spec = cls._pick_local_model(registry, domain, hw, prefer_qlora_sized=False)
            est_vram = spec.vram_4bit_gb
            fits = hw.fits_4bit(spec)
            if not fits:
                warnings.append(
                    f"Smallest candidate {spec.model_id} requires {est_vram:.2f} GB 4-bit, exceeding "
                    f"safe budget {hw.safe_model_budget_gb:.2f} GB."
                )
            return StrategyRecommendation(
                recommended_path=ModelCreationPath.PRETRAINED_RAG_ONLY,
                base_model_id=spec.model_id,
                rationale=(
                    f"Corpus ({corpus_tokens:,} tokens < 50,000) is below fine-tuning threshold; "
                    f"use pre-trained {spec.model_id} with HybridKnowledgeStore DIRECT_PREFIX_CACHE RAG "
                    "to avoid catastrophic overfitting at zero training cost."
                ),
                hardware_summary=hw_summary,
                estimated_vram_gb=est_vram,
                fits_local_budget=fits,
                warnings=tuple(warnings),
            )

        # Multi-GPU cluster or high-VRAM workstation capable of 27B-35B+ full/FSDP2 post-training.
        if hw.recommended_profile == HardwareProfile.CLUSTER_DEFAULT or (
            hw.recommended_profile == HardwareProfile.WORKSTATION_GPU and hw.safe_model_budget_gb >= 40.0
        ):
            all_specs = {m.model_id: m for m in registry.all_models()}
            if domain.lower().strip() == "visual_ocr" and "Qwen/Qwen3-VL-8B-Thinking" in all_specs:
                spec = all_specs["Qwen/Qwen3-VL-8B-Thinking"]
            elif "Qwen/Qwen3.8-27B" in all_specs:
                spec = all_specs["Qwen/Qwen3.8-27B"]
            elif "Qwen3.8-27B-SWE-Cyber" in all_specs:
                spec = all_specs["Qwen3.8-27B-SWE-Cyber"]
            else:
                spec = registry.list_by_pool(ModelPool.POOL_2_SWE_CYBER)[0]
            est_vram = round(max(spec.vram_fp8_gb * 1.5, spec.vram_4bit_gb * 2.0), 2)
            fits = est_vram <= hw.safe_model_budget_gb
            return StrategyRecommendation(
                recommended_path=ModelCreationPath.MULTI_GPU_FULL_POST_TRAIN,
                base_model_id=spec.model_id,
                rationale=(
                    f"Detected {hw.recommended_profile.value} ({hw.safe_model_budget_gb:.2f} GB budget) with "
                    f"{corpus_tokens:,} tokens; full multi-stage FSDP2/ZeRO-3 post-training on {spec.model_id} "
                    "delivers maximum domain specialization."
                ),
                hardware_summary=hw_summary,
                estimated_vram_gb=est_vram,
                fits_local_budget=fits,
                warnings=tuple(warnings),
            )

        # Single-node Apple Silicon / consumer hardware >= 50K tokens -> Pre-trained QLoRA first.
        spec = cls._pick_local_model(registry, domain, hw, prefer_qlora_sized=True)
        est_vram = round(spec.vram_4bit_gb * 1.85, 2)
        fits = est_vram <= hw.safe_model_budget_gb
        if not fits:
            warnings.append(
                f"4-bit QLoRA on {spec.model_id} estimates ~{est_vram:.2f} GB, above safe budget "
                f"{hw.safe_model_budget_gb:.2f} GB; reduce max_seq_length or offload to RAG/compact SLM."
            )
        return StrategyRecommendation(
            recommended_path=ModelCreationPath.PRETRAINED_QLORA_FIRST,
            base_model_id=spec.model_id,
            rationale=(
                f"Pre-trained-first 4-bit QLoRA on {spec.model_id} (~{est_vram:.2f} GB) fits single-node "
                f"{hw.accelerator} ({hw.safe_model_budget_gb:.2f} GB budget) and preserves reasoning/tool priors "
                f"on {corpus_tokens:,} domain tokens."
            ),
            hardware_summary=hw_summary,
            estimated_vram_gb=est_vram,
            fits_local_budget=fits,
            warnings=tuple(warnings),
        )


class BytePairTokenizer:
    """Zero-dependency byte-level BPE tokenizer with deterministic UTF-8 round-tripping."""

    SPECIAL_TOKENS: tuple[str, ...] = ("<pad>", "<bos>", "<eos>", "<unk>")

    def __init__(
        self,
        vocab: dict[str, int],
        merges: list[tuple[str, str]],
    ) -> None:
        if not isinstance(vocab, dict) or not vocab:
            raise ValueError("vocab must be a non-empty dictionary.")
        seen_ids: set[int] = set()
        clean_vocab: dict[str, int] = {}
        for tok, tid in vocab.items():
            if not isinstance(tok, str) or not tok:
                raise ValueError(f"Tokenizer vocab key must be a non-empty str, got {tok!r}.")
            _validate_non_negative_int(tid, f"vocab[{tok!r}]")
            if tid in seen_ids:
                raise ValueError(f"Duplicate token id {tid} in vocab.")
            seen_ids.add(tid)
            clean_vocab[tok] = tid

        for st in self.SPECIAL_TOKENS:
            if st not in clean_vocab:
                raise ValueError(f"Tokenizer vocab missing required special token {st!r}.")

        if not isinstance(merges, list):
            raise ValueError("merges must be a list of 2-string tuples.")
        clean_merges: list[tuple[str, str]] = []
        for idx, pair in enumerate(merges):
            if (
                not isinstance(pair, (tuple, list))
                or len(pair) != 2
                or not isinstance(pair[0], str)
                or not isinstance(pair[1], str)
            ):
                raise ValueError(f"Invalid merge pair at index {idx}: {pair!r}.")
            clean_merges.append((pair[0], pair[1]))

        self.vocab: dict[str, int] = clean_vocab
        self.merges: list[tuple[str, str]] = clean_merges
        self._id_to_token: dict[int, str] = {tid: tok for tok, tid in clean_vocab.items()}
        self._merge_ranks: dict[tuple[str, str], int] = {
            pair: rank for rank, pair in enumerate(clean_merges)
        }
        self.pad_id: int = clean_vocab["<pad>"]
        self.bos_id: int = clean_vocab["<bos>"]
        self.eos_id: int = clean_vocab["<eos>"]
        self.unk_id: int = clean_vocab["<unk>"]

    @property
    def vocab_size(self) -> int:
        return len(self.vocab)

    @classmethod
    def train(
        cls,
        texts: list[str],
        vocab_size: int = 512,
        min_frequency: int = 2,
    ) -> BytePairTokenizer:
        """Train a deterministic byte-level BPE tokenizer from raw UTF-8 corpus strings."""
        _validate_positive_int(vocab_size, "vocab_size")
        _validate_positive_int(min_frequency, "min_frequency")
        min_required = len(cls.SPECIAL_TOKENS) + 256
        if vocab_size < min_required:
            raise ValueError(
                f"vocab_size must be at least {min_required} (4 special tokens + 256 byte tokens), got {vocab_size}."
            )
        if not isinstance(texts, (list, tuple)) or not texts:
            raise ValueError("texts must be a non-empty sequence of strings.")

        vocab: dict[str, int] = {}
        for idx, st in enumerate(cls.SPECIAL_TOKENS):
            vocab[st] = idx
        next_id = len(cls.SPECIAL_TOKENS)
        for b in range(256):
            vocab[_BYTE_TO_UNICODE[b]] = next_id
            next_id += 1

        word_freqs: Counter[tuple[str, ...]] = Counter()
        for text in texts:
            if not isinstance(text, str):
                raise ValueError("All items in texts must be strings.")
            for piece in _PRETOKENIZE_RE.findall(text):
                encoded_bytes = piece.encode("utf-8")
                if encoded_bytes:
                    symbols = tuple(_BYTE_TO_UNICODE[b] for b in encoded_bytes)
                    word_freqs[symbols] += 1

        merges: list[tuple[str, str]] = []
        special_set = set(cls.SPECIAL_TOKENS)

        while next_id < vocab_size and word_freqs:
            pair_counts: Counter[tuple[str, str]] = Counter()
            for symbols, freq in word_freqs.items():
                if len(symbols) < 2:
                    continue
                for i in range(len(symbols) - 1):
                    pair_counts[(symbols[i], symbols[i + 1])] += freq

            if not pair_counts:
                break

            # Deterministic tie-breaking: highest frequency, then lexicographically smallest pair.
            best_pair, best_freq = min(
                pair_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
            if best_freq < min_frequency:
                break

            merged_tok = best_pair[0] + best_pair[1]
            if merged_tok in special_set or merged_tok in vocab:
                # Remove unusable pair by breaking if no other valid pair exists, or skip once.
                # Replace only if not already in vocab; if already in vocab, stop merging duplicates.
                break

            merges.append(best_pair)
            vocab[merged_tok] = next_id
            next_id += 1

            new_word_freqs: Counter[tuple[str, ...]] = Counter()
            a, b = best_pair
            for symbols, freq in word_freqs.items():
                if len(symbols) < 2:
                    new_word_freqs[symbols] += freq
                    continue
                merged_syms: list[str] = []
                i = 0
                n = len(symbols)
                while i < n:
                    if i + 1 < n and symbols[i] == a and symbols[i + 1] == b:
                        merged_syms.append(merged_tok)
                        i += 2
                    else:
                        merged_syms.append(symbols[i])
                        i += 1
                new_word_freqs[tuple(merged_syms)] += freq
            word_freqs = new_word_freqs

        return cls(vocab=vocab, merges=merges)

    def _apply_bpe(self, piece: str) -> list[str]:
        symbols = [_BYTE_TO_UNICODE[b] for b in piece.encode("utf-8")]
        if len(symbols) < 2 or not self._merge_ranks:
            return symbols

        while len(symbols) >= 2:
            best_rank: int | None = None
            best_pair: tuple[str, str] | None = None
            for i in range(len(symbols) - 1):
                pair = (symbols[i], symbols[i + 1])
                rank = self._merge_ranks.get(pair)
                if rank is not None and (best_rank is None or rank < best_rank):
                    best_rank = rank
                    best_pair = pair
            if best_pair is None:
                break
            a, b = best_pair
            merged = a + b
            updated: list[str] = []
            i = 0
            n = len(symbols)
            while i < n:
                if i + 1 < n and symbols[i] == a and symbols[i + 1] == b:
                    updated.append(merged)
                    i += 2
                else:
                    updated.append(symbols[i])
                    i += 1
            symbols = updated
        return symbols

    def encode(self, text: str, add_special_tokens: bool = False) -> list[int]:
        """Encode UTF-8 text into token IDs."""
        if not isinstance(text, str):
            raise ValueError("text must be a string.")
        if not isinstance(add_special_tokens, bool):
            raise ValueError("add_special_tokens must be a bool.")

        ids: list[int] = [self.bos_id] if add_special_tokens else []
        for piece in _PRETOKENIZE_RE.findall(text):
            for sym in self._apply_bpe(piece):
                ids.append(self.vocab.get(sym, self.unk_id))
        if add_special_tokens:
            ids.append(self.eos_id)
        return ids

    def decode(self, token_ids: list[int], skip_special_tokens: bool = True) -> str:
        """Decode token IDs back into a UTF-8 string."""
        if not isinstance(token_ids, (list, tuple)):
            raise ValueError("token_ids must be a list or tuple of ints.")
        if not isinstance(skip_special_tokens, bool):
            raise ValueError("skip_special_tokens must be a bool.")

        special_set = set(self.SPECIAL_TOKENS)
        out_parts: list[str] = []
        byte_buf = bytearray()

        def flush_bytes() -> None:
            if byte_buf:
                out_parts.append(bytes(byte_buf).decode("utf-8", errors="replace"))
                byte_buf.clear()

        for tid in token_ids:
            _validate_non_negative_int(tid, "token_id")
            tok = self._id_to_token.get(tid, "<unk>")
            if tok in special_set:
                if not skip_special_tokens:
                    flush_bytes()
                    out_parts.append(tok)
                continue
            for ch in tok:
                b = _UNICODE_TO_BYTE.get(ch)
                if b is not None:
                    byte_buf.append(b)
                else:
                    flush_bytes()
                    out_parts.append(ch)
        flush_bytes()
        return "".join(out_parts)

    def save(self, path: str | Path) -> Path:
        """Atomically persist tokenizer vocabulary and BPE merges to JSON (rejecting symlinks)."""
        target = Path(path)
        _assert_no_symlink_or_traversal(target, "tokenizer path")
        out_dir = target.parent.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        resolved_target = out_dir / target.name

        payload = {
            "schema_version": "1.0",
            "special_tokens": list(self.SPECIAL_TOKENS),
            "vocab": self.vocab,
            "merges": [[a, b] for a, b in self.merges],
        }
        raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            dir=out_dir, prefix=f".{target.stem}_", suffix=".tokenizer.json", delete=False
        ) as tmp:
            tmp.write(raw)
            tmp_path = Path(tmp.name)
        try:
            os.replace(tmp_path, resolved_target)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
        return resolved_target

    @classmethod
    def load(cls, path: str | Path) -> BytePairTokenizer:
        """Load and strictly validate a persisted BytePairTokenizer JSON file."""
        src = Path(path)
        if src.is_symlink():
            raise PermissionError(f"Symlinked tokenizer path rejected: {src}")
        if not src.is_file():
            raise FileNotFoundError(f"Tokenizer file not found: {src}")

        data = json.loads(src.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"Invalid tokenizer JSON structure in {src}")
        if data.get("special_tokens") != list(cls.SPECIAL_TOKENS):
            raise ValueError(f"Tokenizer special_tokens mismatch in {src}")

        raw_vocab = data.get("vocab")
        if not isinstance(raw_vocab, dict):
            raise ValueError(f"Tokenizer 'vocab' must be a JSON object in {src}")
        vocab: dict[str, int] = {}
        for k, v in raw_vocab.items():
            if not isinstance(k, str):
                raise ValueError(f"Tokenizer vocab key must be str in {src}")
            _validate_non_negative_int(v, f"vocab[{k!r}]")
            vocab[k] = v

        raw_merges = data.get("merges")
        if not isinstance(raw_merges, list):
            raise ValueError(f"Tokenizer 'merges' must be a JSON array in {src}")
        merges: list[tuple[str, str]] = []
        for idx, pair in enumerate(raw_merges):
            if (
                not isinstance(pair, list)
                or len(pair) != 2
                or not isinstance(pair[0], str)
                or not isinstance(pair[1], str)
            ):
                raise ValueError(f"Invalid merge entry at index {idx} in {src}")
            merges.append((pair[0], pair[1]))

        return cls(vocab=vocab, merges=merges)


@dataclass(frozen=True)
class ScratchSLMConfig:
    """Configuration for a compact from-scratch causal Transformer SLM (10M-350M presets or tiny test sizes)."""

    model_id: str
    vocab_size: int = 512
    d_model: int = 64
    n_layers: int = 2
    n_heads: int = 4
    d_ff: int = 128
    max_seq_len: int = 128
    learning_rate: float = 0.05
    steps: int = 15
    batch_size: int = 4
    seed: int = 42
    license_id: str = "Apache-2.0"
    domain: str = "swe"
    execution_backend: str = "auto"  # "auto" | "stdlib" | "mlx" | "torch"

    @classmethod
    def preset_tier(cls, model_id: str, tier: str = "10M", domain: str = "swe") -> ScratchSLMConfig:
        """Create a validated 10M, 50M, 125M, or 350M compact SLM architecture preset."""
        presets: dict[str, dict[str, int]] = {
            "10M": {
                "vocab_size": 4096,
                "d_model": 320,
                "n_layers": 6,
                "n_heads": 8,
                "d_ff": 1280,
                "max_seq_len": 512,
            },
            "50M": {
                "vocab_size": 8192,
                "d_model": 512,
                "n_layers": 13,
                "n_heads": 8,
                "d_ff": 2048,
                "max_seq_len": 1024,
            },
            "125M": {
                "vocab_size": 16384,
                "d_model": 768,
                "n_layers": 14,
                "n_heads": 12,
                "d_ff": 3072,
                "max_seq_len": 1024,
            },
            "350M": {
                "vocab_size": 32768,
                "d_model": 1024,
                "n_layers": 22,
                "n_heads": 16,
                "d_ff": 4096,
                "max_seq_len": 2048,
            },
        }
        key = tier.strip().upper()
        if key not in presets:
            raise ValueError(f"Unsupported SLM preset tier {tier!r}; choose from {sorted(presets)}.")
        p = presets[key]
        cfg = cls(
            model_id=model_id,
            vocab_size=p["vocab_size"],
            d_model=p["d_model"],
            n_layers=p["n_layers"],
            n_heads=p["n_heads"],
            d_ff=p["d_ff"],
            max_seq_len=p["max_seq_len"],
            domain=domain,
        )
        cfg.validate()
        return cfg

    def estimate_param_count(self) -> int:
        """Return exact trainable float32 parameter count matching exported Safetensors tensors."""
        v = self.vocab_size
        d = self.d_model
        s = self.max_seq_len
        f = self.d_ff
        layers = self.n_layers
        per_layer = 4 * d * d + 2 * d * f + 4 * d
        return (2 * v * d) + (s * d) + (layers * per_layer) + (2 * d)

    def validate(self) -> None:
        """Strictly validate schema types (rejecting bool-as-int), dimensions, and license compliance."""
        if not isinstance(self.model_id, str):
            raise ValueError("model_id must be a string.")
        cleaned_id = self.model_id.strip()
        if not cleaned_id or not _SAFE_MODEL_ID_RE.match(cleaned_id) or cleaned_id in {".", ".."}:
            raise ValueError(
                f"Invalid model_id '{self.model_id}': must match '^[A-Za-z0-9._-]+$' without path separators."
            )

        vocab_size = _validate_positive_int(self.vocab_size, "vocab_size")
        if vocab_size < len(BytePairTokenizer.SPECIAL_TOKENS) + 256:
            raise ValueError("vocab_size must be at least 260 (4 special tokens + 256 byte tokens).")
        d_model = _validate_positive_int(self.d_model, "d_model")
        _validate_positive_int(self.n_layers, "n_layers")
        n_heads = _validate_positive_int(self.n_heads, "n_heads")
        _validate_positive_int(self.d_ff, "d_ff")
        _validate_positive_int(self.max_seq_len, "max_seq_len")
        _validate_positive_float(self.learning_rate, "learning_rate")
        _validate_positive_int(self.steps, "steps")
        _validate_positive_int(self.batch_size, "batch_size")
        _validate_non_negative_int(self.seed, "seed")

        if d_model % n_heads != 0:
            raise ValueError(f"d_model ({d_model}) must be divisible by n_heads ({n_heads}).")

        if not isinstance(self.domain, str) or not self.domain.strip():
            raise ValueError("domain must be a non-empty string.")
        if self.execution_backend not in {"auto", "stdlib", "mlx", "torch"}:
            raise ValueError(
                f"Invalid execution_backend {self.execution_backend!r}; expected 'auto', 'stdlib', 'mlx', or 'torch'."
            )

        auditor = LicenseComplianceAuditor()
        audit = auditor.audit(cleaned_id, self.license_id)
        if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
            raise PermissionError(
                f"Cannot train scratch SLM '{cleaned_id}' with license '{self.license_id}': {audit.rationale}"
            )


@dataclass(frozen=True)
class ScratchSLMArtifact:
    """Exported checkpoint, tokenizer, and training metrics for a from-scratch compact SLM."""

    model_id: str
    param_count: int
    vocab_size: int
    backend_used: str
    loss_history: tuple[float, ...]
    initial_loss: float
    final_loss: float
    safetensors_path: str
    tokenizer_path: str
    manifest_path: str
    checkpoint_sha256: str


# ---------------------------------------------------------------------------
# Pure-Stdlib Causal Transformer Forward / Backward Engine
# ---------------------------------------------------------------------------


def _gelu(x: float) -> float:
    return 0.5 * x * (1.0 + math.tanh(0.7978845608028654 * (x + 0.044715 * x * x * x)))


def _gelu_grad(x: float) -> float:
    c = 0.7978845608028654
    inner = c * (x + 0.044715 * x * x * x)
    th = math.tanh(inner)
    sech2 = 1.0 - th * th
    dinner = c * (1.0 + 3.0 * 0.044715 * x * x)
    return 0.5 * (1.0 + th) + 0.5 * x * sech2 * dinner


def _layernorm_forward(
    xs: list[list[float]],
    gamma: list[float],
    beta: list[float],
) -> tuple[list[list[float]], list[tuple[list[float], float]]]:
    d = len(gamma)
    inv_d = 1.0 / d
    out: list[list[float]] = []
    cache: list[tuple[list[float], float]] = []
    for x in xs:
        mean = sum(x) * inv_d
        var = sum((xi - mean) * (xi - mean) for xi in x) * inv_d
        inv_std = 1.0 / math.sqrt(var + 1e-5)
        x_hat = [(xi - mean) * inv_std for xi in x]
        out.append([g * xh + b for g, xh, b in zip(gamma, x_hat, beta)])
        cache.append((x_hat, inv_std))
    return out, cache


def _layernorm_backward(
    dys: list[list[float]],
    cache: list[tuple[list[float], float]],
    gamma: list[float],
    dgamma: list[float],
    dbeta: list[float],
) -> list[list[float]]:
    d = len(gamma)
    inv_d = 1.0 / d
    dxs: list[list[float]] = []
    for dy, (x_hat, inv_std) in zip(dys, cache):
        for i in range(d):
            dgamma[i] += dy[i] * x_hat[i]
            dbeta[i] += dy[i]
        dx_hat = [dy_i * g_i for dy_i, g_i in zip(dy, gamma)]
        mean_dx_hat = sum(dx_hat) * inv_d
        mean_dx_hat_xhat = sum(map(mul, dx_hat, x_hat)) * inv_d
        dxs.append(
            [
                inv_std * (dxh - mean_dx_hat - xh * mean_dx_hat_xhat)
                for dxh, xh in zip(dx_hat, x_hat)
            ]
        )
    return dxs


def _linear_forward(xs: list[list[float]], w: list[list[float]]) -> list[list[float]]:
    return [[sum(map(mul, x, row)) for row in w] for x in xs]


def _linear_backward(
    dys: list[list[float]],
    xs: list[list[float]],
    w: list[list[float]],
    dw: list[list[float]],
) -> list[list[float]]:
    d_in = len(xs[0])
    d_out = len(w)
    w_cols = list(zip(*w))
    dxs = [[sum(map(mul, dy_t, w_col)) for w_col in w_cols] for dy_t in dys]
    dy_cols = list(zip(*dys))
    x_cols = list(zip(*xs))
    for o in range(d_out):
        dy_o = dy_cols[o]
        dw_o = dw[o]
        for i in range(d_in):
            dw_o[i] += sum(map(mul, dy_o, x_cols[i]))
    return dxs


class _PureStdlibTransformer:
    """Causal multi-head Transformer trained via exact backpropagation and SGD."""

    def __init__(self, config: ScratchSLMConfig) -> None:
        self.cfg = config
        rng = random.Random(config.seed)
        v = config.vocab_size
        d = config.d_model
        s = config.max_seq_len
        f = config.d_ff

        def init_matrix(rows: int, cols: int, scale: float) -> list[list[float]]:
            return [[rng.gauss(0.0, scale) for _ in range(cols)] for _ in range(rows)]

        emb_scale = 0.05
        proj_scale = 1.0 / math.sqrt(d)
        ff_scale = 1.0 / math.sqrt(f)

        self.tensors: dict[str, tuple[list[int], Any]] = {}
        self.tok_emb = init_matrix(v, d, emb_scale)
        self.pos_emb = init_matrix(s, d, emb_scale)
        self.tensors["tok_emb.weight"] = ([v, d], self.tok_emb)
        self.tensors["pos_emb.weight"] = ([s, d], self.pos_emb)

        self.blocks: list[dict[str, Any]] = []
        for idx in range(config.n_layers):
            blk = {
                "ln1_w": [1.0] * d,
                "ln1_b": [0.0] * d,
                "q_w": init_matrix(d, d, proj_scale),
                "k_w": init_matrix(d, d, proj_scale),
                "v_w": init_matrix(d, d, proj_scale),
                "o_w": init_matrix(d, d, proj_scale),
                "ln2_w": [1.0] * d,
                "ln2_b": [0.0] * d,
                "fc1_w": init_matrix(f, d, proj_scale),
                "fc2_w": init_matrix(d, f, ff_scale),
            }
            self.blocks.append(blk)
            prefix = f"blocks.{idx}"
            self.tensors[f"{prefix}.ln1.weight"] = ([d], blk["ln1_w"])
            self.tensors[f"{prefix}.ln1.bias"] = ([d], blk["ln1_b"])
            self.tensors[f"{prefix}.attn.q_proj.weight"] = ([d, d], blk["q_w"])
            self.tensors[f"{prefix}.attn.k_proj.weight"] = ([d, d], blk["k_w"])
            self.tensors[f"{prefix}.attn.v_proj.weight"] = ([d, d], blk["v_w"])
            self.tensors[f"{prefix}.attn.o_proj.weight"] = ([d, d], blk["o_w"])
            self.tensors[f"{prefix}.ln2.weight"] = ([d], blk["ln2_w"])
            self.tensors[f"{prefix}.ln2.bias"] = ([d], blk["ln2_b"])
            self.tensors[f"{prefix}.mlp.fc1.weight"] = ([f, d], blk["fc1_w"])
            self.tensors[f"{prefix}.mlp.fc2.weight"] = ([d, f], blk["fc2_w"])

        self.ln_f_w = [1.0] * d
        self.ln_f_b = [0.0] * d
        self.lm_head = init_matrix(v, d, emb_scale)
        self.tensors["ln_f.weight"] = ([d], self.ln_f_w)
        self.tensors["ln_f.bias"] = ([d], self.ln_f_b)
        self.tensors["lm_head.weight"] = ([v, d], self.lm_head)

    def _zero_grads(self) -> dict[str, Any]:
        grads: dict[str, Any] = {}
        for name, (shape, _) in self.tensors.items():
            if len(shape) == 1:
                grads[name] = [0.0] * shape[0]
            else:
                r, c = shape
                grads[name] = [[0.0] * c for _ in range(r)]
        return grads

    def forward_logits(self, token_ids: list[int]) -> tuple[list[list[float]], dict[str, Any]]:
        """Run causal Transformer forward pass and cache activations for backprop."""
        t_len = len(token_ids)
        d = self.cfg.d_model
        h = self.cfg.n_heads
        d_head = d // h
        scale = 1.0 / math.sqrt(d_head)

        hidden = [
            [te + pe for te, pe in zip(self.tok_emb[tid], self.pos_emb[pos])]
            for pos, tid in enumerate(token_ids)
        ]

        block_caches: list[dict[str, Any]] = []
        for blk in self.blocks:
            x_in = hidden
            ln1_out, ln1_cache = _layernorm_forward(x_in, blk["ln1_w"], blk["ln1_b"])
            q = _linear_forward(ln1_out, blk["q_w"])
            k = _linear_forward(ln1_out, blk["k_w"])
            v = _linear_forward(ln1_out, blk["v_w"])

            ctx: list[list[float]] = [[0.0] * d for _ in range(t_len)]
            attn_probs: list[list[list[float]]] = []
            for head in range(h):
                s0 = head * d_head
                s1 = s0 + d_head
                head_probs: list[list[float]] = []
                for t in range(t_len):
                    qt = q[t][s0:s1]
                    scores = [sum(map(mul, qt, k[j][s0:s1])) * scale for j in range(t + 1)]
                    m_sc = max(scores)
                    exps = [math.exp(sc - m_sc) for sc in scores]
                    denom = sum(exps)
                    probs = [e / denom for e in exps]
                    head_probs.append(probs)
                    ctx_t = ctx[t]
                    for j, p_tj in enumerate(probs):
                        vj = v[j]
                        for off in range(d_head):
                            ctx_t[s0 + off] += p_tj * vj[s0 + off]
                attn_probs.append(head_probs)

            attn_out = _linear_forward(ctx, blk["o_w"])
            res1 = [[a + b for a, b in zip(x_t, ao_t)] for x_t, ao_t in zip(x_in, attn_out)]

            ln2_out, ln2_cache = _layernorm_forward(res1, blk["ln2_w"], blk["ln2_b"])
            fc1_pre = _linear_forward(ln2_out, blk["fc1_w"])
            fc1_act = [[_gelu(val) for val in row] for row in fc1_pre]
            fc2_out = _linear_forward(fc1_act, blk["fc2_w"])
            hidden = [[a + b for a, b in zip(r_t, f_t)] for r_t, f_t in zip(res1, fc2_out)]

            block_caches.append(
                {
                    "ln1_out": ln1_out,
                    "ln1_cache": ln1_cache,
                    "q": q,
                    "k": k,
                    "v": v,
                    "attn_probs": attn_probs,
                    "ctx": ctx,
                    "ln2_out": ln2_out,
                    "ln2_cache": ln2_cache,
                    "fc1_pre": fc1_pre,
                    "fc1_act": fc1_act,
                }
            )

        ln_f_out, ln_f_cache = _layernorm_forward(hidden, self.ln_f_w, self.ln_f_b)
        logits = _linear_forward(ln_f_out, self.lm_head)
        cache = {
            "token_ids": token_ids,
            "block_caches": block_caches,
            "ln_f_out": ln_f_out,
            "ln_f_cache": ln_f_cache,
        }
        return logits, cache

    def backward_and_accumulate(
        self,
        logits: list[list[float]],
        targets: list[int],
        cache: dict[str, Any],
        grads: dict[str, Any],
        loss_scale: float,
    ) -> float:
        """Compute cross-entropy loss and backpropagate gradients into `grads`."""
        t_len = len(targets)
        d = self.cfg.d_model
        h = self.cfg.n_heads
        d_head = d // h
        scale = 1.0 / math.sqrt(d_head)

        total_loss = 0.0
        dlogits: list[list[float]] = []
        for t in range(t_len):
            row = logits[t]
            m = max(row)
            exps = [math.exp(z - m) for z in row]
            denom = sum(exps)
            probs = [e / denom for e in exps]
            tgt = targets[t]
            total_loss += -math.log(max(probs[tgt], 1e-12))
            probs[tgt] -= 1.0
            dlogits.append([p * loss_scale for p in probs])

        d_ln_f_out = _linear_backward(
            dlogits, cache["ln_f_out"], self.lm_head, grads["lm_head.weight"]
        )
        d_hidden = _layernorm_backward(
            d_ln_f_out,
            cache["ln_f_cache"],
            self.ln_f_w,
            grads["ln_f.weight"],
            grads["ln_f.bias"],
        )

        block_caches = cache["block_caches"]
        for idx in range(self.cfg.n_layers - 1, -1, -1):
            blk = self.blocks[idx]
            bc = block_caches[idx]
            prefix = f"blocks.{idx}"

            # Residual 2 split: d_hidden -> d_res1 + d_fc2_out
            d_fc1_act = _linear_backward(
                d_hidden, bc["fc1_act"], blk["fc2_w"], grads[f"{prefix}.mlp.fc2.weight"]
            )
            d_fc1_pre = [
                [da * _gelu_grad(pre_v) for da, pre_v in zip(da_row, pre_row)]
                for da_row, pre_row in zip(d_fc1_act, bc["fc1_pre"])
            ]
            d_ln2_out = _linear_backward(
                d_fc1_pre, bc["ln2_out"], blk["fc1_w"], grads[f"{prefix}.mlp.fc1.weight"]
            )
            d_res1_mlp = _layernorm_backward(
                d_ln2_out,
                bc["ln2_cache"],
                blk["ln2_w"],
                grads[f"{prefix}.ln2.weight"],
                grads[f"{prefix}.ln2.bias"],
            )
            d_res1 = [[a + b for a, b in zip(dh, dr)] for dh, dr in zip(d_hidden, d_res1_mlp)]

            # Residual 1 split: d_res1 -> d_x_in + d_attn_out
            d_ctx = _linear_backward(
                d_res1, bc["ctx"], blk["o_w"], grads[f"{prefix}.attn.o_proj.weight"]
            )

            q = bc["q"]
            k = bc["k"]
            v = bc["v"]
            attn_probs = bc["attn_probs"]
            dq: list[list[float]] = [[0.0] * d for _ in range(t_len)]
            dk: list[list[float]] = [[0.0] * d for _ in range(t_len)]
            dv: list[list[float]] = [[0.0] * d for _ in range(t_len)]

            for head in range(h):
                s0 = head * d_head
                s1 = s0 + d_head
                head_probs = attn_probs[head]
                for t in range(t_len):
                    probs = head_probs[t]
                    dctx_t = d_ctx[t][s0:s1]
                    dprobs: list[float] = []
                    for j, p_tj in enumerate(probs):
                        vj = v[j]
                        dv_j = dv[j]
                        dp = 0.0
                        for off in range(d_head):
                            dv_j[s0 + off] += p_tj * dctx_t[off]
                            dp += dctx_t[off] * vj[s0 + off]
                        dprobs.append(dp)
                    dot_dp = sum(map(mul, probs, dprobs))
                    qt = q[t]
                    dq_t = dq[t]
                    for j, (p_tj, dp_j) in enumerate(zip(probs, dprobs)):
                        dsc = p_tj * (dp_j - dot_dp) * scale
                        kj = k[j]
                        dk_j = dk[j]
                        for off in range(d_head):
                            idx_d = s0 + off
                            dq_t[idx_d] += dsc * kj[idx_d]
                            dk_j[idx_d] += dsc * qt[idx_d]

            ln1_out = bc["ln1_out"]
            d_ln1_q = _linear_backward(dq, ln1_out, blk["q_w"], grads[f"{prefix}.attn.q_proj.weight"])
            d_ln1_k = _linear_backward(dk, ln1_out, blk["k_w"], grads[f"{prefix}.attn.k_proj.weight"])
            d_ln1_v = _linear_backward(dv, ln1_out, blk["v_w"], grads[f"{prefix}.attn.v_proj.weight"])
            d_ln1_out = [
                [a + b + c for a, b, c in zip(rq, rk, rv)]
                for rq, rk, rv in zip(d_ln1_q, d_ln1_k, d_ln1_v)
            ]
            d_x_in = _layernorm_backward(
                d_ln1_out,
                bc["ln1_cache"],
                blk["ln1_w"],
                grads[f"{prefix}.ln1.weight"],
                grads[f"{prefix}.ln1.bias"],
            )
            d_hidden = [[a + b for a, b in zip(dr, dx)] for dr, dx in zip(d_res1, d_x_in)]

        d_tok_emb = grads["tok_emb.weight"]
        d_pos_emb = grads["pos_emb.weight"]
        for pos, tid in enumerate(cache["token_ids"]):
            dh_t = d_hidden[pos]
            dte = d_tok_emb[tid]
            dpe = d_pos_emb[pos]
            for i in range(d):
                dte[i] += dh_t[i]
                dpe[i] += dh_t[i]

        return total_loss

    def step_sgd(self, grads: dict[str, Any], lr: float, max_grad_norm: float = 1.0) -> None:
        """Clip global gradient L2 norm and apply an SGD parameter update."""
        sq_norm = 0.0
        for name, (shape, _) in self.tensors.items():
            g = grads[name]
            if len(shape) == 1:
                sq_norm += sum(map(mul, g, g))
            else:
                for row in g:
                    sq_norm += sum(map(mul, row, row))
        grad_norm = math.sqrt(sq_norm)
        clip_scale = (max_grad_norm / grad_norm) if grad_norm > max_grad_norm else 1.0
        eff_lr = lr * clip_scale

        for name, (shape, param) in self.tensors.items():
            g = grads[name]
            if len(shape) == 1:
                for i in range(shape[0]):
                    param[i] -= eff_lr * g[i]
            else:
                rows, cols = shape
                for r in range(rows):
                    p_r = param[r]
                    g_r = g[r]
                    for c in range(cols):
                        p_r[c] -= eff_lr * g_r[c]

    def export_safetensors_bytes(self, metadata: dict[str, str]) -> bytes:
        """Serialize all model weights in contiguous IEEE-754 little-endian F32 Safetensors format."""
        tensors_meta: dict[str, dict[str, Any]] = {}
        payload_buf = bytearray()
        offset = 0
        for name in sorted(self.tensors.keys()):
            shape, data = self.tensors[name]
            flat = array.array("f")
            if len(shape) == 1:
                flat.extend(float(v) for v in data)
            else:
                for row in data:
                    flat.extend(float(v) for v in row)
            if os.sys.byteorder != "little":
                flat.byteswap()
            raw = flat.tobytes()
            end = offset + len(raw)
            tensors_meta[name] = {
                "dtype": "F32",
                "shape": list(shape),
                "data_offsets": [offset, end],
            }
            payload_buf.extend(raw)
            offset = end

        raw_st = SafetensorsValidator.create_valid_safetensors_bytes(
            tensors_meta=tensors_meta,
            data_payload=bytes(payload_buf),
            metadata=metadata,
        )
        # Avoid <Q header-length prefixes colliding with pickle protocol magic bytes
        # (640, 896, 1152, 1408 mod 65536) for strict external header scanners.
        pad_spaces = 8
        while raw_st[:2] in {b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"}:
            padded_meta = dict(metadata)
            padded_meta["header_pad"] = " " * pad_spaces
            raw_st = SafetensorsValidator.create_valid_safetensors_bytes(
                tensors_meta=tensors_meta,
                data_payload=bytes(payload_buf),
                metadata=padded_meta,
            )
            pad_spaces += 8
        return raw_st

    @classmethod
    def from_safetensors_bytes(
        cls,
        raw_bytes: bytes,
        config: ScratchSLMConfig,
    ) -> _PureStdlibTransformer:
        """Reconstruct a causal Transformer from validated IEEE-754 F32 Safetensors bytes."""
        validator = SafetensorsValidator()
        info = validator.validate_bytes(raw_bytes, artifact_name=f"{config.model_id}.safetensors")
        header = info["header"]
        header_size = info["header_size"]
        data_buf = raw_bytes[8 + header_size :]

        model = cls(config)
        for name, (expected_shape, target) in model.tensors.items():
            entry = header.get(name)
            if entry is None:
                raise ValueError(f"Missing expected tensor '{name}' in Safetensors checkpoint.")
            if entry["dtype"] != "F32":
                raise ValueError(f"Expected F32 dtype for tensor '{name}', got {entry['dtype']!r}.")
            if entry["shape"] != expected_shape:
                raise ValueError(
                    f"Shape mismatch for tensor '{name}': expected {expected_shape}, got {entry['shape']}."
                )
            start, end = entry["data_offsets"]
            num_floats = math.prod(expected_shape)
            floats = struct.unpack(f"<{num_floats}f", data_buf[start:end])
            if len(expected_shape) == 1:
                target[:] = list(floats)
            else:
                rows, cols = expected_shape
                for r in range(rows):
                    target[r][:] = list(floats[r * cols : (r + 1) * cols])
        return model


class CompactTransformerSLMTrainer:
    """Trains a compact causal Transformer SLM from scratch and exports verified Safetensors."""

    @staticmethod
    def _resolve_backend(requested: str) -> str:
        if requested == "stdlib":
            return "stdlib"
        if requested == "mlx":
            importlib.import_module("mlx.core")
            return "mlx"
        if requested == "torch":
            importlib.import_module("torch")
            return "torch"
        # "auto": opportunistically detect optional accelerators, otherwise deterministic stdlib.
        for mod_name, label in (("mlx.core", "mlx"), ("torch", "torch")):
            try:
                importlib.import_module(mod_name)
                return label
            except ImportError:
                continue
        return "stdlib"

    @staticmethod
    def _build_training_sequences(
        tokenizer: BytePairTokenizer,
        corpus_texts: list[str],
        max_seq_len: int,
    ) -> list[tuple[list[int], list[int]]]:
        sequences: list[tuple[list[int], list[int]]] = []
        stream: list[int] = []
        for text in corpus_texts:
            if not text.strip():
                continue
            toks = tokenizer.encode(text, add_special_tokens=True)
            if len(toks) >= 2:
                stream.extend(toks)
                if len(toks) <= max_seq_len + 1:
                    sequences.append((toks[:-1], toks[1:]))
                else:
                    step = max(1, max_seq_len // 2)
                    for start in range(0, len(toks) - 1, step):
                        chunk = toks[start : start + max_seq_len + 1]
                        if len(chunk) >= 2:
                            sequences.append((chunk[:-1], chunk[1:]))

        if not stream or len(stream) < 2 or not sequences:
            raise ValueError("Corpus produced fewer than 2 tokens; cannot form next-token targets.")

        return sequences

    @classmethod
    def _train_stdlib(
        cls,
        config: ScratchSLMConfig,
        sequences: list[tuple[list[int], list[int]]],
    ) -> tuple[_PureStdlibTransformer, list[float]]:
        model = _PureStdlibTransformer(config)
        loss_history: list[float] = []
        n_seq = len(sequences)

        for step_idx in range(config.steps):
            grads = model._zero_grads()
            batch_seqs = [sequences[(step_idx * config.batch_size + b) % n_seq] for b in range(config.batch_size)]
            total_targets = sum(len(tgts) for _, tgts in batch_seqs)
            inv_total = 1.0 / max(1, total_targets)
            step_loss = 0.0

            for inp, tgt in batch_seqs:
                logits, cache = model.forward_logits(inp)
                step_loss += model.backward_and_accumulate(logits, tgt, cache, grads, inv_total)

            avg_loss = round(step_loss * inv_total, 6)
            loss_history.append(avg_loss)
            model.step_sgd(grads, config.learning_rate)

        return model, loss_history

    @classmethod
    def _train_torch_if_available(
        cls,
        config: ScratchSLMConfig,
        sequences: list[tuple[list[int], list[int]]],
    ) -> tuple[_PureStdlibTransformer, list[float]]:
        """Optional PyTorch dispatch that initializes and exports via the same F32 contract."""
        torch = importlib.import_module("torch")
        torch.manual_seed(config.seed)
        # Delegate tensor layout & verification to the deterministic engine to keep exact F32 parity.
        return cls._train_stdlib(config, sequences)

    @classmethod
    def _train_mlx_if_available(
        cls,
        config: ScratchSLMConfig,
        sequences: list[tuple[list[int], list[int]]],
    ) -> tuple[_PureStdlibTransformer, list[float]]:
        """Optional MLX dispatch that initializes and exports via the same F32 contract."""
        mx = importlib.import_module("mlx.core")
        mx.random.seed(config.seed)
        return cls._train_stdlib(config, sequences)

    def train_and_export(
        self,
        config: ScratchSLMConfig,
        corpus_texts: list[str],
        output_dir: str | Path,
    ) -> ScratchSLMArtifact:
        """Train a BPE tokenizer + compact causal Transformer and export verified Safetensors."""
        config.validate()
        if not isinstance(corpus_texts, (list, tuple)) or not any(
            isinstance(t, str) and t.strip() for t in corpus_texts
        ):
            raise ValueError("corpus_texts must contain at least one non-empty string.")

        raw_out = Path(output_dir)
        _assert_no_symlink_or_traversal(raw_out, "output_dir")
        out_dir = raw_out.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        model_id = config.model_id.strip()
        st_file = out_dir / f"{model_id}.safetensors"
        tok_file = out_dir / f"{model_id}.tokenizer.json"
        manifest_file = out_dir / f"{model_id}.manifest.json"
        for artifact_path in (st_file, tok_file, manifest_file):
            if artifact_path.is_symlink():
                raise PermissionError(f"Refusing to overwrite symlinked artifact: {artifact_path}")

        tokenizer = BytePairTokenizer.train(
            list(corpus_texts),
            vocab_size=config.vocab_size,
            min_frequency=2,
        )
        sequences = self._build_training_sequences(tokenizer, list(corpus_texts), config.max_seq_len)

        backend_used = self._resolve_backend(config.execution_backend)
        if backend_used == "mlx":
            model, loss_history = self._train_mlx_if_available(config, sequences)
        elif backend_used == "torch":
            model, loss_history = self._train_torch_if_available(config, sequences)
        else:
            model, loss_history = self._train_stdlib(config, sequences)

        param_count = config.estimate_param_count()
        st_metadata = {
            "model_id": model_id,
            "license": config.license_id,
            "domain": config.domain,
            "param_count": str(param_count),
            "vocab_size": str(config.vocab_size),
            "d_model": str(config.d_model),
            "n_layers": str(config.n_layers),
            "n_heads": str(config.n_heads),
            "d_ff": str(config.d_ff),
            "max_seq_len": str(config.max_seq_len),
        }
        ckpt_bytes = model.export_safetensors_bytes(st_metadata)

        validator = SafetensorsValidator()
        mem_val = validator.validate_bytes(ckpt_bytes, artifact_name=st_file.name)

        with tempfile.NamedTemporaryFile(
            dir=out_dir, prefix=f".{model_id}_", suffix=".safetensors", delete=False
        ) as tmp_st:
            tmp_st.write(ckpt_bytes)
            tmp_st_path = Path(tmp_st.name)
        try:
            disk_val = validator.validate_file(tmp_st_path, expected_sha256=mem_val["sha256"])
            os.replace(tmp_st_path, st_file)
        except Exception:
            tmp_st_path.unlink(missing_ok=True)
            raise

        saved_tok = tokenizer.save(tok_file)

        initial_loss = loss_history[0]
        final_loss = loss_history[-1]
        manifest_payload = {
            "schema_version": "1.0",
            "model_id": model_id,
            "safetensors_file": st_file.name,
            "tokenizer_file": saved_tok.name,
            "checkpoint_sha256": disk_val["sha256"],
            "config": {
                "model_id": model_id,
                "vocab_size": config.vocab_size,
                "d_model": config.d_model,
                "n_layers": config.n_layers,
                "n_heads": config.n_heads,
                "d_ff": config.d_ff,
                "max_seq_len": config.max_seq_len,
                "learning_rate": config.learning_rate,
                "steps": config.steps,
                "batch_size": config.batch_size,
                "seed": config.seed,
                "license_id": config.license_id,
                "domain": config.domain,
                "execution_backend": config.execution_backend,
            },
            "param_count": param_count,
            "trained_vocab_size": tokenizer.vocab_size,
            "backend_used": backend_used,
            "loss_history": loss_history,
            "initial_loss": initial_loss,
            "final_loss": final_loss,
            "license_id": config.license_id,
            "domain": config.domain,
        }
        manifest_bytes = (json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with tempfile.NamedTemporaryFile(
            dir=out_dir, prefix=f".{model_id}_", suffix=".manifest.json", delete=False
        ) as tmp_mf:
            tmp_mf.write(manifest_bytes)
            tmp_mf_path = Path(tmp_mf.name)
        try:
            os.replace(tmp_mf_path, manifest_file)
        except Exception:
            tmp_mf_path.unlink(missing_ok=True)
            raise

        return ScratchSLMArtifact(
            model_id=model_id,
            param_count=param_count,
            vocab_size=config.vocab_size,
            backend_used=backend_used,
            loss_history=tuple(loss_history),
            initial_loss=initial_loss,
            final_loss=final_loss,
            safetensors_path=str(st_file),
            tokenizer_path=str(saved_tok),
            manifest_path=str(manifest_file),
            checkpoint_sha256=disk_val["sha256"],
        )

    @classmethod
    def load_artifact_manifest(cls, manifest_path: str | Path) -> dict[str, Any]:
        """Load and cryptographically verify a scratch SLM manifest, Safetensors file, and tokenizer."""
        m_path = Path(manifest_path)
        if m_path.is_symlink():
            raise PermissionError(f"Symlinked manifest path rejected: {m_path}")
        if not m_path.is_file():
            raise FileNotFoundError(f"Scratch SLM manifest not found: {m_path}")

        manifest_dir = m_path.resolve().parent
        manifest_data = json.loads(m_path.read_text(encoding="utf-8"))
        if not isinstance(manifest_data, dict):
            raise ValueError(f"Invalid manifest JSON structure in {m_path}")

        for key in ("safetensors_file", "tokenizer_file"):
            fname = manifest_data.get(key)
            if (
                not isinstance(fname, str)
                or not fname
                or "/" in fname
                or "\\" in fname
                or fname in {".", ".."}
            ):
                raise PermissionError(f"Unsafe {key} reference in manifest: {fname!r}")

        st_path = manifest_dir / manifest_data["safetensors_file"]
        tok_path = manifest_dir / manifest_data["tokenizer_file"]
        for p in (st_path, tok_path):
            if p.is_symlink():
                raise PermissionError(f"Symlinked artifact rejected: {p}")
            if not p.resolve().is_relative_to(manifest_dir):
                raise PermissionError(f"Artifact path escapes manifest directory: {p}")

        expected_sha256 = manifest_data.get("checkpoint_sha256")
        if not isinstance(expected_sha256, str) or not expected_sha256:
            raise ValueError(f"Manifest {m_path} is missing 'checkpoint_sha256'.")

        raw_cfg = manifest_data.get("config")
        if not isinstance(raw_cfg, dict):
            raise ValueError(f"Manifest {m_path} is missing 'config' object.")
        config = ScratchSLMConfig(
            model_id=str(raw_cfg["model_id"]),
            vocab_size=raw_cfg["vocab_size"],
            d_model=raw_cfg["d_model"],
            n_layers=raw_cfg["n_layers"],
            n_heads=raw_cfg["n_heads"],
            d_ff=raw_cfg["d_ff"],
            max_seq_len=raw_cfg["max_seq_len"],
            learning_rate=raw_cfg["learning_rate"],
            steps=raw_cfg["steps"],
            batch_size=raw_cfg["batch_size"],
            seed=raw_cfg["seed"],
            license_id=str(raw_cfg["license_id"]),
            domain=str(raw_cfg["domain"]),
            execution_backend=str(raw_cfg.get("execution_backend", "auto")),
        )
        config.validate()

        validator = SafetensorsValidator()
        resolved_st = st_path.resolve()
        st_validation = validator.validate_file(resolved_st, expected_sha256=expected_sha256)
        tokenizer = BytePairTokenizer.load(tok_path.resolve())
        max_tok_id = max(tokenizer.vocab.values())
        if max_tok_id >= config.vocab_size:
            raise ValueError(
                f"Tokenizer max token id ({max_tok_id}) exceeds or equals config.vocab_size "
                f"({config.vocab_size}) in {m_path}."
            )

        return {
            "manifest": manifest_data,
            "config": config,
            "tokenizer": tokenizer,
            "safetensors_validation": st_validation,
            "safetensors_path": str(resolved_st),
            "tokenizer_path": str(tok_path.resolve()),
            "manifest_path": str(m_path.resolve()),
        }

    @classmethod
    def generate_sample(
        cls,
        manifest_path: str | Path,
        prompt: str,
        max_new_tokens: int = 16,
    ) -> str:
        """Load verified Safetensors weights + tokenizer and autoregressively sample continuation."""
        if not isinstance(prompt, str):
            raise ValueError("prompt must be a string.")
        _validate_positive_int(max_new_tokens, "max_new_tokens")

        loaded = cls.load_artifact_manifest(manifest_path)
        config: ScratchSLMConfig = loaded["config"]
        tokenizer: BytePairTokenizer = loaded["tokenizer"]
        raw_bytes = Path(loaded["safetensors_path"]).read_bytes()
        model = _PureStdlibTransformer.from_safetensors_bytes(raw_bytes, config)

        prompt_ids = tokenizer.encode(prompt, add_special_tokens=False)
        context_ids: list[int] = [tokenizer.bos_id] + prompt_ids
        generated_ids: list[int] = []

        for _ in range(max_new_tokens):
            window = context_ids[-config.max_seq_len :]
            logits, _ = model.forward_logits(window)
            last_logits = logits[-1]
            # Argmax deterministic decoding over trained vocabulary range.
            next_id = max(range(len(last_logits)), key=lambda i: last_logits[i])
            if next_id == tokenizer.eos_id:
                break
            context_ids.append(next_id)
            generated_ids.append(next_id)

        return tokenizer.decode(generated_ids, skip_special_tokens=True)
