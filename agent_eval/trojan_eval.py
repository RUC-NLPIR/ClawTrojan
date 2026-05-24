"""claw_trojan evaluation pipeline

静态标注模式：基于 env 中的 injection.json 构造 tool_output，
跑 detector → policy → judge 全流程。
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from loguru import logger

from claw_trojan.loader import load_all_trojan_envs

from .policies import BlockPolicy, SanitizePolicy
from .protocol import DetectorDecision, PolicyDecision
from .trojan_judge import judge_step_detection, judge_trajectory
from .trojan_metrics import compute_trojan_metrics


class TrojanEvaluator:
    def __init__(self, policy_name: str):
        if policy_name == "block":
            self.policy = BlockPolicy()
        elif policy_name == "sanitize":
            self.policy = SanitizePolicy()
        else:
            raise ValueError(f"unknown policy: {policy_name}")

    @staticmethod
    def _load_preds(path: str) -> Dict[str, dict]:
        preds = {}
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    preds[item["sample_id"]] = item
        return preds

    def run(self, envs_root: str, detector_pred_path: str, output_dir: str) -> Dict:
        # 1. 加载所有 step 样本
        step_samples = load_all_trojan_envs(envs_root)
        logger.info(f"加载了 {len(step_samples)} 个 step 样本")

        # 2. 加载 detector predictions
        pred_map = self._load_preds(detector_pred_path)
        logger.info(f"加载了 {len(pred_map)} 条 detector 预测")

        # 3. 逐步评测
        step_results = []
        for sample in step_samples:
            eval_id = sample.eval_id
            gold_record = sample.to_gold_record()

            pred = pred_map.get(eval_id)
            if pred is None:
                logger.warning(f"缺少预测: {eval_id}, 跳过")
                continue

            # 构造 detector decision
            detector_decision = DetectorDecision(
                sample_id=eval_id,
                is_malicious_pred=bool(pred.get("is_malicious_pred", False)),
                risk_score=float(pred.get("risk_score", 0.0)),
                char_spans_pred=pred.get("char_spans_pred", []),
            )

            # 应用 policy
            policy_decision = self.policy.apply(gold_record, detector_decision)

            # 判断
            step_info = {
                "eval_id": eval_id,
                "sample_id": sample.sample_id,
                "step_idx": sample.step_idx,
                "stage_tag": sample.stage_tag,
                "is_malicious": sample.is_malicious,
                "is_last_chance": sample.is_last_chance,
            }
            result = judge_step_detection(step_info, policy_decision.action)
            result["detector"] = detector_decision.to_dict()
            result["policy"] = policy_decision.to_dict()
            step_results.append(result)

        # 4. 按 sample_id 分组，计算 trajectory-level 结果
        by_sample: Dict[str, List[dict]] = defaultdict(list)
        for r in step_results:
            by_sample[r["sample_id"]].append(r)

        trajectory_results = []
        for sample_id, results in sorted(by_sample.items()):
            traj = judge_trajectory(results)
            trajectory_results.append(traj)

        # 5. 计算指标
        metrics = compute_trojan_metrics(trajectory_results, step_results)

        # 6. 输出
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        with open(out_dir / "step_results.jsonl", "w", encoding="utf-8") as f:
            for r in step_results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        with open(out_dir / "trajectory_results.jsonl", "w", encoding="utf-8") as f:
            for r in trajectory_results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        with open(out_dir / "trojan_metrics.json", "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)

        logger.info(f"评测结果已写入 {out_dir}")
        return metrics
