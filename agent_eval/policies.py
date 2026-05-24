from __future__ import annotations

from typing import Dict

from .protocol import DetectorDecision, PolicyDecision


class BasePolicy:
    name = "base"

    def apply(self, sample: dict, detector_output: DetectorDecision) -> PolicyDecision:
        return PolicyDecision(
            sample_id=sample["sample_id"],
            action="pass",
            sanitized_tool_output=sample["tool_output"],
            reason="default pass-through",
        )


class BlockPolicy(BasePolicy):
    name = "block"

    def apply(self, sample: dict, detector_output: DetectorDecision) -> PolicyDecision:
        if detector_output.is_malicious_pred:
            return PolicyDecision(
                sample_id=sample["sample_id"],
                action="block",
                sanitized_tool_output="[BLOCKED_TOOL_OUTPUT]",
                reason="detector flagged malicious content",
                metadata={"risk_score": detector_output.risk_score},
            )
        return PolicyDecision(
            sample_id=sample["sample_id"],
            action="pass",
            sanitized_tool_output=sample["tool_output"],
            reason="detector did not flag sample",
            metadata={"risk_score": detector_output.risk_score},
        )


class SanitizePolicy(BasePolicy):
    name = "sanitize"

    def apply(self, sample: dict, detector_output: DetectorDecision) -> PolicyDecision:
        sanitized = sample["tool_output"]
        if detector_output.char_spans_pred:
            spans = sorted(detector_output.char_spans_pred, key=lambda x: x["char_start"], reverse=True)
            for span in spans:
                sanitized = sanitized[: span["char_start"]] + "[REDACTED]" + sanitized[span["char_end"] :]
            return PolicyDecision(
                sample_id=sample["sample_id"],
                action="sanitize",
                sanitized_tool_output=sanitized,
                reason="redacted predicted malicious spans",
                metadata={"risk_score": detector_output.risk_score, "num_spans": len(spans)},
            )
        if detector_output.is_malicious_pred:
            return PolicyDecision(
                sample_id=sample["sample_id"],
                action="sanitize",
                sanitized_tool_output=sample["clean_output"],
                reason="fallback to clean output because no spans were predicted",
                metadata={"risk_score": detector_output.risk_score},
            )
        return PolicyDecision(
            sample_id=sample["sample_id"],
            action="pass",
            sanitized_tool_output=sample["tool_output"],
            reason="detector did not flag sample",
            metadata={"risk_score": detector_output.risk_score},
        )
