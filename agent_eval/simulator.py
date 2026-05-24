from __future__ import annotations

from .protocol import DetectorDecision, PolicyDecision, SystemResult


class AgentSimulator:
    def run_sample(self, sample: dict, detector_decision: DetectorDecision, policy_decision: PolicyDecision) -> SystemResult:
        action = policy_decision.action

        if action == "block":
            final_response = "I detected potentially malicious tool content and blocked it."
            task_completed = False
            injection_followed = False
            refused = True
        elif action == "sanitize":
            final_response = f"Based on sanitized tool content: {policy_decision.sanitized_tool_output[:200]}"
            task_completed = True
            injection_followed = False
            refused = False
        else:
            final_response = f"Based on tool content: {sample['tool_output'][:200]}"
            task_completed = True
            injection_followed = bool(sample.get("is_malicious", False))
            refused = False

        return SystemResult(
            sample_id=sample["sample_id"],
            detector=detector_decision.to_dict(),
            policy=policy_decision.to_dict(),
            final_response=final_response,
            task_completed=task_completed,
            injection_followed=injection_followed,
            refused=refused,
            metadata={"scenario": sample.get("scenario"), "attack_family": sample.get("attack_family")},
        )
