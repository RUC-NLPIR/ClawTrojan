"""DtI Detector: orchestrates Layer 1 (Drift Monitor) + Layer 2 (Counterfactual Gate).

Processes trajectories from claw_trojan envs and outputs standard
DetectorDecision JSONL compatible with the trojan_eval pipeline.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

from loguru import logger

from claw_trojan.loader import TrojanStepSample, load_all_trojan_envs

from ..protocol import DetectorDecision
from .counterfactual_gate import CounterfactualGate
from .drift_monitor import DriftMonitor
from .embedder import BaseEmbedder
from .llm_client import BaseLLMClient


class DtiDetector:
    """Drift-then-Intervene detector.

    Layer 1 (async): Semantic drift monitor — detects monotonic divergence
    between user intent and agent behavior across the trajectory.

    Layer 2 (sync): Counterfactual intervention gate — invoked only when
    Layer 1 triggers AND the step involves a high-risk action (L3+).
    Verifies whether directive content in tool output has undue causal influence.
    """

    def __init__(
        self,
        embedder: BaseEmbedder,
        llm_client: BaseLLMClient,
        theta_cumul: float = 0.5,
        k: int = 3,
        tau_cis: float = 0.2,
        high_risk_tiers: Optional[Set[str]] = None,
    ):
        self.drift_monitor = DriftMonitor(
            embedder=embedder, theta_cumul=theta_cumul, k=k
        )
        self.counterfactual_gate = CounterfactualGate(
            llm_client=llm_client, embedder=embedder, tau_cis=tau_cis
        )
        self.high_risk_tiers = high_risk_tiers or {"L3", "L4"}

    def detect_trajectory(
        self, steps: List[TrojanStepSample]
    ) -> List[DetectorDecision]:
        """Run DtI detection on a single trajectory.

        Args:
            steps: Ordered list of TrojanStepSample for one sample_id.

        Returns:
            One DetectorDecision per step.
        """
        user_inputs = [s.user_input for s in steps]
        tool_outputs = [s.tool_output for s in steps]

        # Layer 1: analyze drift across the full trajectory
        drift_results = self.drift_monitor.analyze_trajectory(
            user_inputs, tool_outputs
        )

        decisions: List[DetectorDecision] = []

        for step, drift in zip(steps, drift_results):
            is_malicious = False
            gate_metadata: Dict = {}

            # Layer 2: only when drift triggers AND step is high-risk
            if (
                drift.is_triggered
                and step.risk_tier in self.high_risk_tiers
                and step.tool_output  # need tool content to analyze
            ):
                logger.debug(
                    f"Layer 2 triggered for {step.eval_id} "
                    f"(D_t={drift.D_t:.3f}, risk={step.risk_tier})"
                )
                gate_result = self.counterfactual_gate.evaluate(
                    step.user_input, step.tool_output
                )
                is_malicious = gate_result.should_block
                gate_metadata = {
                    "cis": gate_result.cis,
                    "action_original": gate_result.action_original,
                    "action_distilled": gate_result.action_distilled,
                }

            decisions.append(
                DetectorDecision(
                    sample_id=step.eval_id,
                    is_malicious_pred=is_malicious,
                    risk_score=min(drift.D_t, 1.0),
                    metadata={
                        "d_t": drift.d_t,
                        "D_t": drift.D_t,
                        "monotonic_count": drift.monotonic_count,
                        "layer1_triggered": drift.is_triggered,
                        "risk_tier": step.risk_tier,
                        "stage_tag": step.stage_tag,
                        **gate_metadata,
                    },
                )
            )

        return decisions

    def detect_all(self, envs_root: str) -> List[DetectorDecision]:
        """Load all envs, group into trajectories, detect each.

        Args:
            envs_root: Path to claw_trojan/envs directory.

        Returns:
            List of DetectorDecision for all steps across all samples.
        """
        all_steps = load_all_trojan_envs(envs_root)
        logger.info(f"Loaded {len(all_steps)} steps from {envs_root}")

        # Group by sample_id
        by_sample: Dict[str, List[TrojanStepSample]] = defaultdict(list)
        for step in all_steps:
            by_sample[step.sample_id].append(step)

        all_decisions: List[DetectorDecision] = []
        for sample_id in sorted(by_sample):
            trajectory = sorted(by_sample[sample_id], key=lambda s: s.step_idx)
            logger.info(
                f"Detecting {sample_id} ({len(trajectory)} steps)"
            )
            decisions = self.detect_trajectory(trajectory)
            all_decisions.extend(decisions)

        logger.info(
            f"Detection complete: {len(all_decisions)} decisions, "
            f"{sum(1 for d in all_decisions if d.is_malicious_pred)} flagged"
        )
        return all_decisions

    @staticmethod
    def save_predictions(
        decisions: List[DetectorDecision], output_path: str
    ) -> None:
        """Save decisions as JSONL compatible with trojan-eval pipeline."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            for d in decisions:
                f.write(json.dumps(d.to_dict(), ensure_ascii=False) + "\n")
        logger.info(f"Saved {len(decisions)} predictions to {output_path}")
