#!/usr/bin/env python3
"""CLI wrapper for from-scratch BPE tokenization, compact SLM training, and generation."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys
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


def _validate_safe_output_path(raw_path: str, is_dir: bool = False) -> Path:
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
    if is_dir:
        if path.exists() and not path.is_dir():
            raise NotADirectoryError(f"Expected directory path, got file: {path}")
        path.mkdir(parents=True, exist_ok=True)
    else:
        if path.exists() and path.is_dir():
            raise IsADirectoryError(f"Output path is a directory: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_output(data: Any, output_file: str) -> None:
    """Write JSON result to `--output` after symlink and path-escape validation."""
    try:
        dest = _validate_safe_output_path(output_file, is_dir=False)
        with dest.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"Success! Data written to: {dest}")
    except (OSError, PermissionError, ValueError, TypeError) as exc:
        print(f"Error writing output to {output_file}: {exc}", file=sys.stderr)
        sys.exit(1)


def _load_corpus_texts(corpus_files: list[str], limit: int) -> list[str]:
    texts: list[str] = []
    for raw_file in corpus_files:
        path = _validate_safe_input_path(raw_file)
        if not path.is_file():
            raise FileNotFoundError(f"Corpus file not found: {path}")
        content = path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            stripped = line.strip()
            if stripped:
                texts.append(stripped)
                if len(texts) >= limit:
                    return texts
        if not texts and content.strip():
            texts.append(content.strip())
            if len(texts) >= limit:
                return texts
    if not texts:
        raise ValueError("No non-empty corpus texts found in provided --corpus-files.")
    return texts


def _handle_train_tokenizer(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer1_intelligence.scratch_trainer import BytePairTokenizer

    texts = _load_corpus_texts(args.corpus_files, limit=args.limit)
    tok_out = _validate_safe_output_path(args.tokenizer_out, is_dir=False)
    tok = BytePairTokenizer.train(
        texts=texts,
        vocab_size=args.vocab_size,
        min_frequency=args.min_frequency,
    )
    saved_path = tok.save(tok_out)
    sample_text = texts[0][:120]
    encoded = tok.encode(sample_text, add_special_tokens=True)
    decoded = tok.decode(encoded, skip_special_tokens=True)
    return {
        "command": "train-tokenizer",
        "limit": args.limit,
        "corpus_texts_used": len(texts),
        "requested_vocab_size": args.vocab_size,
        "tokenizer_path": str(saved_path),
        "roundtrip_ok": decoded == sample_text,
        "sample_token_count": len(encoded),
    }


def _handle_train_slm(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.deploy_security.governance import SafetensorsValidator
    from platform_core.layer1_intelligence.scratch_trainer import (
        CompactTransformerSLMTrainer,
        ScratchSLMConfig,
    )

    texts = _load_corpus_texts(args.corpus_files, limit=args.limit)
    out_dir = _validate_safe_output_path(args.output_dir, is_dir=True)

    if args.tier != "custom":
        base_cfg = ScratchSLMConfig.preset_tier(
            model_id=args.model_id,
            tier=args.tier,
            domain=args.domain,
        )
        cfg = replace(
            base_cfg,
            learning_rate=args.learning_rate,
            steps=args.steps,
            batch_size=args.batch_size,
            seed=args.seed,
            license_id=args.license,
            execution_backend=args.backend,
        )
    else:
        cfg = ScratchSLMConfig(
            model_id=args.model_id,
            vocab_size=args.vocab_size,
            d_model=args.d_model,
            n_layers=args.n_layers,
            n_heads=args.n_heads,
            d_ff=args.d_ff,
            max_seq_len=args.max_seq_len,
            learning_rate=args.learning_rate,
            steps=args.steps,
            batch_size=args.batch_size,
            seed=args.seed,
            license_id=args.license,
            domain=args.domain,
            execution_backend=args.backend,
        )

    cfg.validate()
    trainer = CompactTransformerSLMTrainer()
    artifact = trainer.train_and_export(cfg, corpus_texts=texts, output_dir=out_dir)

    st_validation = SafetensorsValidator().validate_file(
        artifact.safetensors_path,
        expected_sha256=artifact.checkpoint_sha256,
    )
    return {
        "command": "train-slm",
        "limit": args.limit,
        "steps": args.steps,
        "tier": args.tier,
        "corpus_texts_used": len(texts),
        "model_id": artifact.model_id,
        "param_count": artifact.param_count,
        "estimated_param_count": cfg.estimate_param_count(),
        "vocab_size": artifact.vocab_size,
        "backend_used": artifact.backend_used,
        "initial_loss": artifact.initial_loss,
        "final_loss": artifact.final_loss,
        "loss_improved": artifact.final_loss < artifact.initial_loss,
        "loss_history": list(artifact.loss_history),
        "safetensors_path": artifact.safetensors_path,
        "tokenizer_path": artifact.tokenizer_path,
        "manifest_path": artifact.manifest_path,
        "checkpoint_sha256": artifact.checkpoint_sha256,
        "safetensors_tensor_count": st_validation["tensor_count"],
    }


def _handle_generate(args: argparse.Namespace) -> dict[str, Any]:
    from platform_core.layer1_intelligence.scratch_trainer import CompactTransformerSLMTrainer

    manifest_path = _validate_safe_input_path(args.manifest)
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
    manifest = CompactTransformerSLMTrainer.load_artifact_manifest(manifest_path)
    generated = CompactTransformerSLMTrainer.generate_sample(
        manifest_path=manifest_path,
        prompt=args.prompt,
        max_new_tokens=args.limit,
    )
    return {
        "command": "generate",
        "manifest_path": str(manifest_path),
        "model_id": manifest["config"].model_id,
        "prompt": args.prompt,
        "limit": args.limit,
        "generated_text": generated,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train custom byte-level BPE tokenizers and compact from-scratch Transformer SLMs."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_tok = sub.add_parser("train-tokenizer", help="Train and save a BytePairTokenizer JSON file")
    p_tok.add_argument("--corpus-files", nargs="+", required=True, help="Non-symlink corpus text files")
    p_tok.add_argument("--vocab-size", type=_positive_int, default=512, help="Target BPE vocabulary size (>= 260)")
    p_tok.add_argument("--min-frequency", type=_positive_int, default=2, help="Minimum pair frequency for merge")
    p_tok.add_argument("--limit", type=_positive_int, required=True, help="Maximum corpus lines/texts to read")
    p_tok.add_argument("--tokenizer-out", required=True, help="Output .tokenizer.json file path")
    p_tok.add_argument("--output", required=True, help="Output JSON report path")

    p_slm = sub.add_parser("train-slm", help="Train a compact causal Transformer SLM and export .safetensors")
    p_slm.add_argument("--model-id", required=True, help="Custom model identifier")
    p_slm.add_argument("--corpus-files", nargs="+", required=True, help="Non-symlink corpus text files")
    p_slm.add_argument("--output-dir", required=True, help="Directory for .safetensors, tokenizer, and manifest")
    p_slm.add_argument("--tier", choices=["custom", "10M", "50M", "125M", "350M"], default="custom")
    p_slm.add_argument("--vocab-size", type=_positive_int, default=512)
    p_slm.add_argument("--d-model", type=_positive_int, default=64)
    p_slm.add_argument("--n-layers", type=_positive_int, default=2)
    p_slm.add_argument("--n-heads", type=_positive_int, default=4)
    p_slm.add_argument("--d-ff", type=_positive_int, default=128)
    p_slm.add_argument("--max-seq-len", type=_positive_int, default=128)
    p_slm.add_argument("--learning-rate", type=_positive_float, default=0.05)
    p_slm.add_argument("--steps", type=_positive_int, required=True, help="Number of training optimization steps")
    p_slm.add_argument("--batch-size", type=_positive_int, default=4)
    p_slm.add_argument("--seed", type=int, default=42)
    p_slm.add_argument("--domain", default="swe")
    p_slm.add_argument("--license", default="Apache-2.0")
    p_slm.add_argument("--backend", choices=["auto", "stdlib", "mlx", "torch"], default="auto")
    p_slm.add_argument("--limit", type=_positive_int, required=True, help="Maximum corpus lines/texts to load")
    p_slm.add_argument("--output", required=True, help="Output JSON report path")

    p_gen = sub.add_parser("generate", help="Generate sample text from a trained SLM manifest")
    p_gen.add_argument("--manifest", required=True, help="Path to <model_id>.manifest.json")
    p_gen.add_argument("--prompt", required=True, help="Prompt string to complete")
    p_gen.add_argument("--limit", type=_positive_int, required=True, help="Maximum new tokens to generate")
    p_gen.add_argument("--output", required=True, help="Output JSON result path")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "train-tokenizer":
            data = _handle_train_tokenizer(args)
        elif args.command == "train-slm":
            data = _handle_train_slm(args)
        elif args.command == "generate":
            data = _handle_generate(args)
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
