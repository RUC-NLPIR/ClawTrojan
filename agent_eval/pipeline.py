from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .metrics import compute_system_metrics
from .policies import BlockPolicy, SanitizePolicy
from .protocol import DetectorDecision
from .simulator import AgentSimulator


class HybridDefenseEvaluator:
    def __init__(self, policy_name: str):
        if policy_name == "block":
            self.policy = BlockPolicy()
        elif policy_name == "sanitize":
            self.policy = SanitizePolicy()
        else:
            raise ValueError(f"unknown policy: {policy_name}")
        self.simulator = AgentSimulator()

    @staticmethod
    def _load_jsonl(path: str) -> List[Dict]:
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def run(self, gold_path: str, detector_pred_path: str, output_dir: str) -> Dict:
        samples = self._load_jsonl(gold_path)
        detector_preds = self._load_jsonl(detector_pred_path)
        pred_map = {item["sample_id"]: item for item in detector_preds}

        results = []
        for sample in samples:
            pred = pred_map[sample["sample_id"]]
            detector_decision = DetectorDecision(
                sample_id=sample["sample_id"],
                is_malicious_pred=bool(pred["is_malicious_pred"]),
                risk_score=float(pred.get("risk_score", 0.0)),
                char_spans_pred=pred.get("char_spans_pred", []),
                metadata={
                    "valid_token_count": pred.get("valid_token_count"),
                },
            )
            policy_decision = self.policy.apply(sample, detector_decision)
            system_result = self.simulator.run_sample(sample, detector_decision, policy_decision)
            results.append(system_result.to_dict())

        metrics = compute_system_metrics(samples, results)
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(out_dir / "system_results.jsonl", "w", encoding="utf-8") as f:
            for item in results:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        with open(out_dir / "system_metrics.json", "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        return metrics
