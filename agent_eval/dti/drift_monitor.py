"""Layer 1: Semantic Drift Monitor.

Tracks monotonically increasing divergence between user intent and agent
behavior across a multi-step trajectory. Asynchronous, non-blocking.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .embedder import BaseEmbedder


@dataclass
class DriftResult:
    """Per-step drift analysis result."""

    step_idx: int
    d_t: float  # per-step drift: 1 - cos_sim(user, tool)
    D_t: float  # cumulative weighted drift
    is_triggered: bool  # whether Layer 2 should be invoked
    monotonic_count: int  # consecutive steps with increasing d_t


class DriftMonitor:
    """Semantic drift monitor over agent trajectories.

    Computes per-step drift d_t between user intent and tool output,
    accumulates weighted drift D_t, and triggers when cumulative drift
    exceeds threshold AND d_t has been monotonically increasing for k steps.
    """

    def __init__(
        self,
        embedder: BaseEmbedder,
        theta_cumul: float = 0.5,
        k: int = 3,
    ):
        self.embedder = embedder
        self.theta_cumul = theta_cumul
        self.k = k

    def compute_step_drift(self, user_input: str, tool_output: str) -> float:
        """Compute per-step drift: d_t = 1 - cos_sim(u_t, a_t)."""
        u = self.embedder.embed(user_input)
        a = self.embedder.embed(tool_output)
        sim = self.embedder.cosine_similarity(u, a)
        return float(1.0 - sim)

    def analyze_trajectory(
        self, user_inputs: List[str], tool_outputs: List[str]
    ) -> List[DriftResult]:
        """Analyze an entire trajectory, returning per-step DriftResults.

        Args:
            user_inputs: user_input text for each step (ordered by step_idx)
            tool_outputs: tool_output text for each step (empty string if none)

        Returns:
            List of DriftResult, one per step.
        """
        n = len(user_inputs)
        results: List[DriftResult] = []

        d_values: List[float] = []
        monotonic_count = 0

        for t in range(n):
            # Skip drift if tool_output is empty (no tool content at this step)
            if not tool_outputs[t]:
                d_t = 0.0
            else:
                d_t = self.compute_step_drift(user_inputs[t], tool_outputs[t])

            d_values.append(d_t)

            # Monotonic increase tracking
            if t > 0 and d_t > d_values[t - 1] and d_values[t - 1] > 0:
                monotonic_count += 1
            elif t > 0:
                monotonic_count = 0

            # Cumulative weighted drift: w_i = i / sum(1..t+1)
            total_steps = t + 1
            weight_sum = total_steps * (total_steps + 1) / 2
            D_t = sum(
                (i + 1) / weight_sum * d_values[i] for i in range(total_steps)
            )

            # Trigger: cumulative exceeds threshold AND sustained monotonic increase
            is_triggered = D_t > self.theta_cumul and monotonic_count >= self.k

            results.append(
                DriftResult(
                    step_idx=t + 1,  # 1-indexed to match dataset convention
                    d_t=d_t,
                    D_t=D_t,
                    is_triggered=is_triggered,
                    monotonic_count=monotonic_count,
                )
            )

        return results
