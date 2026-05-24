"""DASGuard detector entry points."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from claw_trojan.loader import TrojanStepSample, load_all_trojan_envs

from agent_eval.llm_client import BaseLLMClient

from ..protocol import DetectorDecision
from .assessment import assess_text, build_context, review_assessment
from .embedder import BaseDasGuardEmbedder, create_dasguard_embedder
from .scanner import scan_workspace
from .schema import DasGuardFinding


class DasGuardDetector:
    """Detect-Attribute-Sanitize detector skeleton.

    The current implementation is deterministic and focuses on the paper's
    core object: untrusted control-bearing content flowing into sensitive
    persistent sinks. It emits the existing DetectorDecision contract so the
    trojan evaluation pipeline can run unchanged.
    """

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        embedder: Optional[BaseDasGuardEmbedder] = None,
        use_embedding: bool = True,
        use_memory_context: bool = True,
    ):
        self.llm_client = llm_client
        self.embedder = embedder or create_dasguard_embedder()
        self.use_embedding = use_embedding
        self.use_memory_context = use_memory_context
        self._defense_memory: Dict[str, List[Dict[str, Any]]] = {}

    def detect_step(
        self,
        step: TrojanStepSample,
        *,
        memory_context: Optional[List[Dict[str, Any]]] = None,
    ) -> DetectorDecision:
        text, source_label = self._observable_step_text_and_source(step)
        sink_path = f"{step.sample_id}/step_{step.step_idx}/{step.metadata.get('tool_name', 'tool_output')}"
        context = build_context(
            mode="static_detect",
            tool_name=str(step.metadata.get("tool_name", "tool_output")),
            sink_path=sink_path,
            source_label=source_label,
            payload=text,
        )
        assessment = assess_text(
            text,
            context=context,
            finding_prefix=step.eval_id,
            memory_context=memory_context if self.use_memory_context else None,
            embedder=self.embedder,
            use_embedding=self.use_embedding,
        )
        review_assessment(assessment, llm_client=self.llm_client)
        findings = assessment.findings
        risky_findings = [f for f in findings if f.action != "preserve"]
        return DetectorDecision(
            sample_id=step.eval_id,
            is_malicious_pred=bool(risky_findings),
            risk_score=assessment.risk_score,
            char_spans_pred=[
                {"start": f.start, "end": f.end}
                for f in risky_findings
            ],
            metadata={
                "method": "dasguard",
                "risk_tier": step.risk_tier,
                "stage_tag": step.stage_tag,
                "sample_id": step.sample_id,
                "step_idx": step.step_idx,
                "defense_memory_used": len(memory_context or []),
                "use_embedding": self.use_embedding,
                "use_memory_context": self.use_memory_context,
                "assessment": assessment.to_dict(),
                "findings": [f.to_dict() for f in findings],
            },
        )

    @staticmethod
    def _observable_step_text_and_source(step: TrojanStepSample) -> tuple[str, str]:
        """Return detector-visible text without consulting gold attack labels.

        `TrojanStepSample.is_malicious` and `injection_text` are benchmark
        annotations. They must not affect detector inference. Static
        dasguard-detect observes tool output when present; otherwise it falls
        back to the direct user request.
        """
        if step.tool_output:
            return step.tool_output, "tool_untrusted"
        return step.user_input, "trusted_user"

    def detect_all(self, envs_root: str) -> List[DetectorDecision]:
        steps = load_all_trojan_envs(envs_root)
        logger.info(f"Loaded {len(steps)} steps from {envs_root}")
        decisions: List[DetectorDecision] = []
        self._defense_memory = {}
        for step in steps:
            memory_context = self._defense_memory.get(step.sample_id, [])
            decision = self.detect_step(step, memory_context=memory_context)
            decisions.append(decision)
            self._update_defense_memory(step, decision)
        flagged = sum(1 for decision in decisions if decision.is_malicious_pred)
        logger.info(f"DASGuard detection complete: {len(decisions)} steps, {flagged} flagged")
        return decisions

    @staticmethod
    def save_predictions(decisions: List[DetectorDecision], output_path: str) -> None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            for decision in decisions:
                f.write(json.dumps(decision.to_dict(), ensure_ascii=False) + "\n")
        logger.info(f"Saved {len(decisions)} predictions to {output_path}")

    def scan_workspace(
        self, workspace_root: str, source_label: str | None = None
    ) -> List[DasGuardFinding]:
        return scan_workspace(workspace_root, source_label=source_label, embedder=self.embedder)

    def _update_defense_memory(
        self,
        step: TrojanStepSample,
        decision: DetectorDecision,
    ) -> None:
        findings = decision.metadata.get("findings", [])
        suspicious = [
            finding for finding in findings
            if finding.get("action") != "preserve"
        ]
        if not suspicious:
            return
        sample_memory = self._defense_memory.setdefault(step.sample_id, [])
        for finding in suspicious:
            sample_memory.append({
                "sample_id": step.sample_id,
                "step_idx": step.step_idx,
                "finding_id": finding.get("finding_id"),
                "span": finding.get("span", ""),
                "classification": finding.get("classification"),
                "control_role": finding.get("control_role"),
                "risk_score": finding.get("risk_score"),
            })
        del sample_memory[:-20]
