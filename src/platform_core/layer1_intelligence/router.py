"""Layer 1 Adaptive Model Gateway, Entropy-Aware Thinking Scaling, and Best-of-N (`TTS@N`) Pruning.

Implements Section 1.7 & 3.1:
- Routes requests across the Four-Pool Specialized Model Lineup.
- Prevents the "Overthinking Trap" ($r = -0.56$ accuracy drop on unconstrained CoT) via
  Switchable Thinking Modes (`NON_THINK`, `THINK_HIGH`, `THINK_MAX`) bounded per turn.
- Executes Parallel Best-of-N (`TTS@4` / `TTS@8`) candidate selection pruned by deterministic
  execution verifiers (`SecVerifier`, compiler, unit tests).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import ModelPool, ModelRegistry, ModelSpec, ThinkingMode


@dataclass(frozen=True)
class RoutingRequest:
    """Incoming task routing request for Layer 1."""

    task_id: str
    task_domain: str  # "architecture", "swe", "cyber", "binrev", "visual_ocr", "data_protocol"
    prompt_tokens: int
    has_visual_input: bool = False
    is_routine_tool_lookup: bool = False
    uncertainty_entropy: float = 0.35  # Normalized [0.0, 1.0]
    retry_attempt: int = 0
    require_best_of_n: bool = False
    preferred_model_id: str | None = None


@dataclass(frozen=True)
class RoutingDecision:
    """Routing and inference-time scaling decision emitted by AdaptiveModelRouter."""

    task_id: str
    selected_pool: ModelPool
    primary_model: ModelSpec
    pre_parser_model: ModelSpec | None
    thinking_mode: ThinkingMode
    max_thinking_tokens_per_turn: int
    best_of_n_rollouts: int
    enforce_interleaved_react: bool
    use_prefix_cache: bool
    rationale: str


@dataclass(frozen=True)
class CandidateRollout:
    """A single trajectory candidate generated during Best-of-N (`TTS@N`) sampling."""

    candidate_id: str
    output_artifact: str
    thinking_tokens_used: int
    tool_steps_taken: int
    compiled_cleanly: bool
    passed_primary_tests: bool
    passed_regression_tests: bool
    verifier_score: float


class AdaptiveModelRouter:
    """Routes tasks to specialized model pools and calibrates thinking token budgets."""

    # Hard cap on thinking tokens per turn to avoid the Overthinking Trap (Section 1.7)
    NON_THINK_BUDGET: int = 0
    THINK_HIGH_MIN_BUDGET: int = 512
    THINK_HIGH_MAX_BUDGET: int = 1024
    THINK_MAX_BUDGET: int = 2048

    def __init__(self, registry: ModelRegistry | None = None) -> None:
        self.registry = registry or ModelRegistry()

    def _resolve_first_available(self, model_ids: list[str]) -> ModelSpec | None:
        for mid in model_ids:
            try:
                return self.registry.get_model(mid)
            except KeyError:
                continue
        return None

    def route(self, request: RoutingRequest) -> RoutingDecision:
        """Select optimal model pool, pre-parser, thinking budget, and TTS@N rollout factor."""
        if request.prompt_tokens < 0:
            raise ValueError("prompt_tokens must be non-negative.")
        if not (0.0 <= request.uncertainty_entropy <= 1.0):
            raise ValueError("uncertainty_entropy must be in [0.0, 1.0].")

        domain = request.task_domain.lower().strip()
        pre_parser = self._resolve_first_available(
            ["OmniParser-V2-UI-TARS-GOT-OCR", "Qwen/Qwen3-VL-8B-Thinking"]
        ) if (request.has_visual_input or domain == "visual_ocr") else None

        # 1. Pool & Model Selection
        if request.preferred_model_id is not None:
            primary_model = self.registry.get_model(request.preferred_model_id)
            selected_pool = primary_model.pool
        else:
            if request.prompt_tokens > 200_000 or domain == "architecture":
                selected_pool = ModelPool.POOL_1_ORCHESTRATOR
                candidates = (
                    ["Qwen3.5-397B-A17B", "Qwen/Qwen3.5-35B-A3B", "zai-org/GLM-4.7-Flash"]
                    if request.has_visual_input
                    else ["DeepSeek-V4-Flash", "Qwen/Qwen3.5-35B-A3B", "zai-org/GLM-4.7-Flash"]
                )
            elif domain == "binrev":
                selected_pool = ModelPool.POOL_3_BINREV
                candidates = ["Qwen3.8-27B-BinRev", "Qwen/Qwen3.8-27B"]
            elif domain in {"cyber", "forensics", "vuln_intel"}:
                selected_pool = ModelPool.POOL_2_SWE_CYBER
                candidates = [
                    "Qwen3.8-27B-SWE-Cyber",
                    "fdtn-ai/Foundation-Sec-8B-Reasoning",
                    "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                    "mistralai/Devstral-Small-24B",
                ]
            elif domain in {"swe", "data_protocol"}:
                selected_pool = ModelPool.POOL_2_SWE_CYBER
                candidates = [
                    "Qwen3.8-27B-SWE-Cyber",
                    "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                    "mistralai/Devstral-Small-24B",
                ]
            elif domain == "visual_ocr":
                selected_pool = ModelPool.POOL_4_VISUAL_OCR
                candidates = ["OmniParser-V2-UI-TARS-GOT-OCR", "Qwen/Qwen3-VL-8B-Thinking"]
            else:
                selected_pool = ModelPool.POOL_2_SWE_CYBER
                candidates = [
                    "Qwen3.8-27B-SWE-Cyber",
                    "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                    "mistralai/Devstral-Small-24B",
                ]

            pool_override = self.registry.get_pool_override(selected_pool)
            if pool_override is not None:
                primary_model = pool_override
            else:
                resolved = self._resolve_first_available(candidates)
                if resolved is not None:
                    primary_model = resolved
                else:
                    pool_models = self.registry.list_by_pool(selected_pool)
                    primary_model = pool_models[0] if pool_models else self.registry.all_models()[0]

        # 2. Entropy-Aware Thinking Mode Selection (preventing Overthinking Trap)
        if request.is_routine_tool_lookup or selected_pool == ModelPool.POOL_4_VISUAL_OCR:
            thinking_mode = ThinkingMode.NON_THINK
            thinking_budget = self.NON_THINK_BUDGET
        elif domain == "architecture" and request.uncertainty_entropy >= 0.75:
            thinking_mode = ThinkingMode.THINK_MAX
            thinking_budget = self.THINK_MAX_BUDGET
        elif request.uncertainty_entropy >= 0.25 or request.retry_attempt > 0:
            thinking_mode = ThinkingMode.THINK_HIGH
            scaled = int(
                self.THINK_HIGH_MIN_BUDGET
                + (self.THINK_HIGH_MAX_BUDGET - self.THINK_HIGH_MIN_BUDGET)
                * request.uncertainty_entropy
            )
            thinking_budget = min(self.THINK_HIGH_MAX_BUDGET, max(self.THINK_HIGH_MIN_BUDGET, scaled))
        else:
            thinking_mode = ThinkingMode.NON_THINK
            thinking_budget = self.NON_THINK_BUDGET

        # 3. Best-of-N (TTS@4 / TTS@8) Escalation
        if request.require_best_of_n:
            best_of_n = 8 if request.uncertainty_entropy >= 0.7 else 4
        elif request.retry_attempt >= 2:
            # Step 9 of lifecycle: switch to parallel TTS@4 rollouts on final retry attempt
            best_of_n = 4
        else:
            best_of_n = 1

        return RoutingDecision(
            task_id=request.task_id,
            selected_pool=selected_pool,
            primary_model=primary_model,
            pre_parser_model=pre_parser,
            thinking_mode=thinking_mode,
            max_thinking_tokens_per_turn=thinking_budget,
            best_of_n_rollouts=best_of_n,
            enforce_interleaved_react=True,
            use_prefix_cache=True,
            rationale=(
                f"Routed domain='{domain}' ({request.prompt_tokens} toks) to {primary_model.model_id} "
                f"in {selected_pool.value} with {thinking_mode.value} (cap={thinking_budget} toks/turn, "
                f"TTS@{best_of_n})."
            ),
        )


class BestOfNVerifierPruner:
    """Filters parallel `TTS@N` candidate trajectories using deterministic verifiers (SecVerifier)."""

    @staticmethod
    def select_best_candidate(
        candidates: list[CandidateRollout],
        custom_verifier: Callable[[CandidateRollout], float] | None = None,
    ) -> CandidateRollout:
        """Prune invalid rollouts and select the optimal verified candidate.

        Prioritizes:
        1. Full dual-gate verification pass (`compiled_cleanly` AND `passed_primary_tests`
           AND `passed_regression_tests`).
        2. Highest deterministic verifier score.
        3. Lowest step count and thinking token usage (anti-overthinking tie-breaker).
        """
        if not candidates:
            raise ValueError("Cannot select from an empty candidate rollout list.")

        def rank_key(c: CandidateRollout) -> tuple[int, int, float, int, int]:
            dual_gate_pass = int(
                c.compiled_cleanly and c.passed_primary_tests and c.passed_regression_tests
            )
            compiled_and_primary = int(c.compiled_cleanly and c.passed_primary_tests)
            score = custom_verifier(c) if custom_verifier is not None else c.verifier_score
            return (
                dual_gate_pass,
                compiled_and_primary,
                round(score, 6),
                -c.tool_steps_taken,
                -c.thinking_tokens_used,
            )

        return max(candidates, key=rank_key)
