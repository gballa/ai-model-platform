"""Layer 1 Live Inference Runtime, Memory Residency Guard, and Model Download Manager.

Provides unified, vendor-neutral inference across:
- Local Apple Silicon (`mlx-lm` / `mlx-vlm`) protected by `MemoryResidencyGuard`
- Any OpenAI-compatible HTTP endpoint (`mlx_lm.server`, `llama-server`, `Ollama`, `vLLM`, `SGLang`)
- Deterministic offline mock backend for reproducible testing and CI verification.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import base64
from collections import OrderedDict
from dataclasses import dataclass
import json
from pathlib import Path
import threading
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from platform_core.deploy_security.governance import (
    LicenseComplianceAuditor,
    LicenseVerdict,
    SafetensorsValidator,
)


@dataclass(frozen=True)
class ToolDefinition:
    """JSON-Schema tool definition exposed to an inference model."""

    name: str
    description: str
    parameters: dict[str, Any]

    def to_openai_tool(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class ToolCall:
    """Structured tool call emitted by a model."""

    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ChatMessage:
    """Single message in a multi-turn or multimodal conversation."""

    role: str  # "system", "user", "assistant", "tool"
    content: str
    image_paths: tuple[str, ...] = ()
    tool_call_id: str | None = None
    name: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()

    def to_openai_dict(self) -> dict[str, Any]:
        if self.image_paths and self.role == "user":
            blocks: list[dict[str, Any]] = [{"type": "text", "text": self.content}]
            for img_path in self.image_paths:
                path = Path(img_path)
                if path.is_symlink() or not path.is_file():
                    raise FileNotFoundError(f"Invalid image path for multimodal message: {img_path}")
                suffix = path.suffix.lower()
                mime = {
                    ".png": "image/png",
                    ".jpg": "image/jpeg",
                    ".jpeg": "image/jpeg",
                    ".webp": "image/webp",
                }.get(suffix, "image/png")
                b64 = base64.b64encode(path.read_bytes()).decode("ascii")
                blocks.append({"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}})
            return {"role": self.role, "content": blocks}

        msg: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_call_id is not None:
            msg["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            msg["name"] = self.name
        if self.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.call_id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in self.tool_calls
            ]
        return msg


@dataclass(frozen=True)
class InferenceRequest:
    """Unified inference request across local MLX and OpenAI-compatible servers."""

    model_id: str
    messages: tuple[ChatMessage, ...]
    tools: tuple[ToolDefinition, ...] = ()
    max_tokens: int = 2048
    max_thinking_tokens: int = 1024
    temperature: float = 0.1
    json_mode: bool = False


@dataclass(frozen=True)
class InferenceResponse:
    """Unified inference response with content, tool calls, and telemetry."""

    model_id: str
    content: str
    tool_calls: tuple[ToolCall, ...] = ()
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    raw_reasoning: str = ""
    backend_name: str = "unknown"


class MemoryResidencyGuard:
    """Thread-safe LRU memory budget manager preventing OOM on unified-memory hosts."""

    def __init__(self, max_budget_gb: float = 27.0) -> None:
        if max_budget_gb <= 0:
            raise ValueError("max_budget_gb must be positive.")
        self.max_budget_gb = float(max_budget_gb)
        self._lock = threading.RLock()
        self._resident: OrderedDict[str, float] = OrderedDict()

    def current_usage_gb(self) -> float:
        with self._lock:
            return round(sum(self._resident.values()), 3)

    def resident_models(self) -> list[str]:
        with self._lock:
            return list(self._resident.keys())

    def acquire(
        self,
        model_id: str,
        required_gb: float,
        on_evict: Callable[[str], None] | None = None,
    ) -> list[str]:
        """Reserve memory for `model_id`, evicting LRU models if budget would be exceeded."""
        if required_gb <= 0:
            raise ValueError("required_gb must be positive.")
        if required_gb > self.max_budget_gb:
            raise MemoryError(
                f"Model '{model_id}' requires {required_gb:.1f} GB, exceeding safe budget "
                f"{self.max_budget_gb:.1f} GB."
            )
        evicted: list[str] = []
        with self._lock:
            if model_id in self._resident:
                self._resident.move_to_end(model_id)
                return evicted
            while sum(self._resident.values()) + required_gb > self.max_budget_gb and self._resident:
                victim_id, _ = self._resident.popitem(last=False)
                evicted.append(victim_id)
                if on_evict is not None:
                    on_evict(victim_id)
            self._resident[model_id] = required_gb
        return evicted


class InferenceBackend(ABC):
    """Abstract base interface for live and mocked LLM/VLM backends."""

    @abstractmethod
    def generate(self, request: InferenceRequest) -> InferenceResponse:
        """Execute a chat/tool-calling/multimodal completion request."""

    def embed(self, model_id: str, texts: list[str]) -> list[list[float]]:
        """Compute embedding vectors for a list of strings."""
        raise NotImplementedError(f"{type(self).__name__} does not implement embeddings.")


class OpenAICompatibleClient(InferenceBackend):
    """OpenAI-compatible HTTP client for mlx_lm.server, llama-server, Ollama, vLLM, and SGLang."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        api_key: str | None = None,
        timeout_sec: float = 120.0,
    ) -> None:
        parsed = urlparse(base_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Invalid base_url: {base_url!r}")
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive.")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_sec = timeout_sec

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = json.dumps(payload).encode("utf-8")
        req = Request(url, data=body, headers=headers, method="POST")
        try:
            with urlopen(req, timeout=self.timeout_sec) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
            raise RuntimeError(f"Inference HTTP {exc.code} from {url}: {err_body}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"Failed to connect to inference endpoint {url}: {exc}") from exc

    def generate(self, request: InferenceRequest) -> InferenceResponse:
        start = time.perf_counter()
        payload: dict[str, Any] = {
            "model": request.model_id,
            "messages": [m.to_openai_dict() for m in request.messages],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        if request.tools:
            payload["tools"] = [t.to_openai_tool() for t in request.tools]
            payload["tool_choice"] = "auto"
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}
        if request.max_thinking_tokens <= 0:
            payload["chat_template_kwargs"] = {"enable_thinking": False}

        data = self._post_json("/v1/chat/completions", payload)
        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError(f"Empty choices returned by inference endpoint: {data}")
        msg = choices[0].get("message") or {}
        content = str(msg.get("content") or "")
        reasoning = str(msg.get("reasoning_content") or "")

        parsed_calls: list[ToolCall] = []
        for idx, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            raw_args = fn.get("arguments", "{}")
            if isinstance(raw_args, str):
                try:
                    args_dict = json.loads(raw_args) if raw_args.strip() else {}
                except json.JSONDecodeError:
                    args_dict = {"_raw": raw_args}
            elif isinstance(raw_args, dict):
                args_dict = raw_args
            else:
                args_dict = {}
            parsed_calls.append(
                ToolCall(
                    call_id=str(tc.get("id") or f"call-{idx + 1}"),
                    name=str(fn.get("name") or ""),
                    arguments=args_dict,
                )
            )

        usage = data.get("usage") or {}
        return InferenceResponse(
            model_id=str(data.get("model") or request.model_id),
            content=content,
            tool_calls=tuple(parsed_calls),
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            latency_ms=latency_ms,
            raw_reasoning=reasoning,
            backend_name="openai_compatible_http",
        )

    def embed(self, model_id: str, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        data = self._post_json("/v1/embeddings", {"model": model_id, "input": texts})
        rows = sorted(data.get("data") or [], key=lambda r: int(r.get("index", 0)))
        return [[float(x) for x in r["embedding"]] for r in rows]


class MLXLocalBackend(InferenceBackend):
    """Apple Silicon local MLX backend (`mlx-lm` / `mlx-vlm`) with MemoryResidencyGuard."""

    def __init__(
        self,
        residency_guard: MemoryResidencyGuard | None = None,
        model_footprints_gb: dict[str, float] | None = None,
    ) -> None:
        self.guard = residency_guard or MemoryResidencyGuard(max_budget_gb=27.0)
        self.model_footprints_gb = dict(model_footprints_gb or {})
        self._loaded: dict[str, tuple[Any, Any, bool]] = {}  # model_id -> (model, tokenizer_or_proc, is_vlm)
        self._lock = threading.RLock()

    def _evict(self, victim_id: str) -> None:
        self._loaded.pop(victim_id, None)

    def _ensure_loaded(self, model_id: str, has_images: bool) -> tuple[Any, Any, bool]:
        footprint = self.model_footprints_gb.get(model_id, 18.0 if "35B" in model_id or "27B" in model_id else 5.5)
        with self._lock:
            self.guard.acquire(model_id, footprint, on_evict=self._evict)
            if model_id in self._loaded:
                return self._loaded[model_id]

            if has_images:
                try:
                    import mlx_vlm  # type: ignore[import-not-found]
                except ImportError as exc:
                    raise RuntimeError(
                        "mlx-vlm is not installed. Install optional extra '[mlx]' or run an OpenAI-compatible server."
                    ) from exc
                model, processor = mlx_vlm.load(model_id)
                entry = (model, processor, True)
            else:
                try:
                    import mlx_lm  # type: ignore[import-not-found]
                except ImportError as exc:
                    raise RuntimeError(
                        "mlx-lm is not installed. Install optional extra '[mlx]' or run an OpenAI-compatible server."
                    ) from exc
                model, tokenizer = mlx_lm.load(model_id)
                entry = (model, tokenizer, False)

            self._loaded[model_id] = entry
            return entry

    def generate(self, request: InferenceRequest) -> InferenceResponse:
        start = time.perf_counter()
        image_paths = [p for m in request.messages for p in m.image_paths]
        model, processor, is_vlm = self._ensure_loaded(request.model_id, has_images=bool(image_paths))

        if is_vlm:
            import mlx_vlm  # type: ignore[import-not-found]

            prompt_text = "\n".join(f"{m.role}: {m.content}" for m in request.messages)
            output = mlx_vlm.generate(
                model,
                processor,
                prompt_text,
                image=image_paths,
                max_tokens=request.max_tokens,
                temp=request.temperature,
            )
            text = str(getattr(output, "text", output))
        else:
            import mlx_lm  # type: ignore[import-not-found]

            chat_dicts = [{"role": m.role, "content": m.content} for m in request.messages]
            if hasattr(processor, "apply_chat_template"):
                prompt = processor.apply_chat_template(
                    chat_dicts, tokenize=False, add_generation_prompt=True
                )
            else:
                prompt = "\n".join(f"{m.role}: {m.content}" for m in request.messages)
            text = mlx_lm.generate(
                model,
                processor,
                prompt=prompt,
                max_tokens=request.max_tokens,
            )

        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return InferenceResponse(
            model_id=request.model_id,
            content=str(text),
            latency_ms=latency_ms,
            backend_name="mlx_local",
        )


class DeterministicMockBackend(InferenceBackend):
    """Programmable deterministic backend for offline testing and CI workflows."""

    def __init__(
        self,
        responder: Callable[[InferenceRequest], InferenceResponse] | None = None,
        scripted_responses: list[InferenceResponse] | None = None,
    ) -> None:
        self._responder = responder
        self._scripted = list(scripted_responses or [])
        self.recorded_requests: list[InferenceRequest] = []

    def generate(self, request: InferenceRequest) -> InferenceResponse:
        self.recorded_requests.append(request)
        if self._scripted:
            return self._scripted.pop(0)
        if self._responder is not None:
            return self._responder(request)
        last_user = next((m.content for m in reversed(request.messages) if m.role == "user"), "")
        return InferenceResponse(
            model_id=request.model_id,
            content=json.dumps({"status": "mock_ok", "echo_prompt": last_user[:160]}),
            prompt_tokens=max(1, len(last_user) // 4),
            completion_tokens=24,
            latency_ms=1.0,
            backend_name="deterministic_mock",
        )

    def embed(self, model_id: str, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            buckets = [0.0] * 16
            for idx, ch in enumerate(text.encode("utf-8")):
                buckets[(ch + idx) % 16] += 1.0
            norm = sum(v * v for v in buckets) ** 0.5 or 1.0
            vectors.append([round(v / norm, 6) for v in buckets])
        return vectors


class ModelDownloadManager:
    """License-gated, Safetensors-verified model downloader and local directory auditor."""

    def __init__(self) -> None:
        self._auditor = LicenseComplianceAuditor()
        self._st_validator = SafetensorsValidator()

    def audit_local_model_dir(self, model_dir: str | Path, license_id: str, model_id: str) -> dict[str, Any]:
        """Verify license compliance and validate all .safetensors files in a local model directory."""
        audit = self._auditor.audit(model_id, license_id)
        if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
            raise PermissionError(
                f"Model '{model_id}' ({license_id}) failed license gate: {audit.rationale}"
            )
        root = Path(model_dir)
        if root.is_symlink() or not root.is_dir():
            raise FileNotFoundError(f"Invalid model directory: {root}")

        forbidden = [
            p.name
            for p in root.iterdir()
            if p.is_file() and p.suffix.lower() in self._st_validator.FORBIDDEN_EXTENSIONS
        ]
        if forbidden:
            raise PermissionError(
                f"Unsafe pickle-based checkpoint files detected in {root}: {forbidden}"
            )

        st_files = sorted(p for p in root.iterdir() if p.is_file() and p.suffix.lower() == ".safetensors")
        if not st_files:
            raise FileNotFoundError(f"No .safetensors files found in {root}")

        validated = [self._st_validator.validate_file(p) for p in st_files]
        return {
            "model_id": model_id,
            "license_id": license_id,
            "safetensors_files": len(validated),
            "total_tensors": sum(v["tensor_count"] for v in validated),
            "sha256_manifest": {v["artifact_name"]: v["sha256"] for v in validated},
        }

    def download_from_huggingface(
        self,
        repo_id: str,
        license_id: str,
        local_dir: str | Path,
        revision: str = "main",
    ) -> dict[str, Any]:
        """Download Safetensors-only weights from HuggingFace after passing the license gate."""
        audit = self._auditor.audit(repo_id, license_id)
        if audit.verdict != LicenseVerdict.APPROVED_COMMERCIAL:
            raise PermissionError(
                f"Download blocked for '{repo_id}' ({license_id}): {audit.rationale}"
            )
        try:
            from huggingface_hub import snapshot_download  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "huggingface_hub is not installed. Install optional extra '[mlx]' or '[train]' to download models."
            ) from exc

        target = Path(local_dir).resolve()
        target.mkdir(parents=True, exist_ok=True)
        snapshot_download(
            repo_id=repo_id,
            revision=revision,
            local_dir=str(target),
            allow_patterns=["*.safetensors", "*.json", "*.txt", "*.jinja", "*.model"],
            ignore_patterns=["*.bin", "*.pt", "*.pth", "*.pkl", "*.ckpt", "*.joblib"],
        )
        return self.audit_local_model_dir(target, license_id=license_id, model_id=repo_id)
