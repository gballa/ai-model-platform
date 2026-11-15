"""Layer 1 Serving Infrastructure — SGLang RadixAttention Prefix Cache & vLLM Configs.

Implements Section 3.1, 7, & BL-02:
- Models SGLang v0.5.19's unified RadixAttention prefix tree across multi-turn agent
  trajectories and parallel Best-of-N (`TTS@4` / `TTS@8`) rollouts.
- Tracks prefix cache hit ratios (targeting >= 70% hit rate on multi-turn agent loops)
  and Time-to-First-Token (TTFT <= 120ms on 27B models).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .models import ModelSpec


@dataclass(frozen=True)
class ServingEndpointConfig:
    """Configuration for SGLang v0.5.19 or vLLM v0.28 serving engines."""

    engine: str  # "sglang" or "vllm"
    engine_version: str
    model_id: str
    quantization: str  # "fp8", "mxfp4", "awq_int4", "bf16"
    tensor_parallel_size: int
    max_context_len: int
    enable_radix_prefix_cache: bool = True
    enable_chunked_prefill: bool = True
    gpu_memory_utilization: float = 0.90
    port: int = 30000

    def to_launch_args(self) -> list[str]:
        """Generate deterministic CLI launch arguments for container orchestration."""
        if self.engine == "sglang":
            args = [
                "python3",
                "-m",
                "sglang.launch_server",
                "--model-path",
                self.model_id,
                "--tp-size",
                str(self.tensor_parallel_size),
                "--context-length",
                str(self.max_context_len),
                "--quantization",
                self.quantization,
                "--mem-fraction-static",
                f"{self.gpu_memory_utilization:.2f}",
                "--port",
                str(self.port),
            ]
            if not self.enable_radix_prefix_cache:
                args.append("--disable-radix-cache")
            if self.enable_chunked_prefill:
                args.append("--chunked-prefill-size=8192")
            return args

        if self.engine == "vllm":
            args = [
                "vllm",
                "serve",
                self.model_id,
                "--tensor-parallel-size",
                str(self.tensor_parallel_size),
                "--max-model-len",
                str(self.max_context_len),
                "--quantization",
                self.quantization,
                "--gpu-memory-utilization",
                f"{self.gpu_memory_utilization:.2f}",
                "--port",
                str(self.port),
            ]
            if self.enable_radix_prefix_cache:
                args.append("--enable-prefix-caching")
            if self.enable_chunked_prefill:
                args.append("--enable-chunked-prefill")
            return args

        if self.engine == "mlx_lm":
            return [
                "python3",
                "-m",
                "mlx_lm.server",
                "--model",
                self.model_id,
                "--port",
                str(self.port),
                "--max-tokens",
                str(min(self.max_context_len, 32768)),
            ]

        if self.engine == "llama_cpp":
            return [
                "llama-server",
                "-hf",
                self.model_id,
                "--ctx-size",
                str(self.max_context_len),
                "--port",
                str(self.port),
            ]

        raise ValueError(f"Unsupported serving engine '{self.engine}'.")


class ServingHealthChecker:
    """Probes local or remote OpenAI-compatible serving endpoints before routing."""

    @staticmethod
    def probe_endpoint(base_url: str, timeout_sec: float = 2.0) -> dict[str, Any]:
        parsed = urlparse(base_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Invalid serving endpoint URL: {base_url!r}")
        models_url = f"{base_url.rstrip('/')}/v1/models"
        req = Request(models_url, headers={"Accept": "application/json"}, method="GET")
        try:
            with urlopen(req, timeout=timeout_sec) as resp:  # nosec - scheme validated above
                payload = json.loads(resp.read().decode("utf-8"))
                model_ids = [m.get("id") for m in payload.get("data", []) if isinstance(m, dict)]
                return {"healthy": True, "status_code": resp.status, "models": model_ids}
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            return {"healthy": False, "error": str(exc), "models": []}


class RadixPrefixCacheSimulator:
    """Simulates SGLang RadixAttention token block caching across branching agent turns."""

    def __init__(self, block_size_tokens: int = 16) -> None:
        if block_size_tokens <= 0:
            raise ValueError("block_size_tokens must be positive.")
        self.block_size_tokens = block_size_tokens
        self._cached_prefixes: set[tuple[str, ...]] = set()
        self.total_prompt_tokens: int = 0
        self.cached_prompt_tokens: int = 0
        self.requests_served: int = 0

    def record_request(self, token_blocks: list[str], active_params_b: float = 27.8) -> dict[str, float]:
        """Process a sequence of token blocks through the radix tree and estimate TTFT."""
        if not token_blocks:
            return {"prefix_hit_ratio": 0.0, "estimated_ttft_ms": 15.0}

        matched_blocks = 0
        for i in range(1, len(token_blocks) + 1):
            prefix = tuple(token_blocks[:i])
            if prefix in self._cached_prefixes:
                matched_blocks = i
            else:
                self._cached_prefixes.add(prefix)

        total_tokens = len(token_blocks) * self.block_size_tokens
        hit_tokens = matched_blocks * self.block_size_tokens
        miss_tokens = total_tokens - hit_tokens

        self.total_prompt_tokens += total_tokens
        self.cached_prompt_tokens += hit_tokens
        self.requests_served += 1

        hit_ratio = hit_tokens / total_tokens if total_tokens > 0 else 0.0
        # Base scheduling latency (~18ms on SGLang zero-overhead CPU scheduler) + prefill cost
        base_ms = 18.0 + (active_params_b * 0.85)
        prefill_ms = (miss_tokens / 1000.0) * (active_params_b * 1.1)
        estimated_ttft_ms = round(base_ms + prefill_ms, 2)

        return {
            "prefix_hit_ratio": round(hit_ratio, 4),
            "cumulative_hit_ratio": round(self.cumulative_hit_ratio(), 4),
            "estimated_ttft_ms": estimated_ttft_ms,
        }

    def cumulative_hit_ratio(self) -> float:
        if self.total_prompt_tokens == 0:
            return 0.0
        return self.cached_prompt_tokens / self.total_prompt_tokens

    @staticmethod
    def build_default_pool_configs(models: list[ModelSpec]) -> list[ServingEndpointConfig]:
        """Create SGLang/vLLM serving configurations for all registered models."""
        configs: list[ServingEndpointConfig] = []
        base_port = 30000
        for idx, spec in enumerate(models):
            is_large_moe = spec.total_params_b >= 100.0
            quant = "mxfp4" if is_large_moe else "fp8"
            tp_size = 2 if spec.vram_4bit_gb > 192.0 else 1
            configs.append(
                ServingEndpointConfig(
                    engine="sglang",
                    engine_version="0.5.19",
                    model_id=spec.model_id,
                    quantization=quant,
                    tensor_parallel_size=tp_size,
                    max_context_len=spec.context_window,
                    enable_radix_prefix_cache=True,
                    enable_chunked_prefill=True,
                    port=base_port + idx,
                )
            )
        return configs
