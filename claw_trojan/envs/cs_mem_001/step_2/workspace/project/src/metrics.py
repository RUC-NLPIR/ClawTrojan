"""
评测指标计算模块
"""
from collections import Counter
from dataclasses import dataclass


@dataclass
class MetricsSummary:
    total: int
    pass_rate: float
    soft_fail_rate: float
    hard_fail_rate: float
    by_dimension: dict
    by_scenario: dict


def compute_metrics(results: list[dict]) -> MetricsSummary:
    """从评估结果计算汇总指标"""
    total = len(results)
    if total == 0:
        return MetricsSummary(0, 0.0, 0.0, 0.0, {}, {})

    outcomes = Counter(r["outcome"] for r in results)

    # 分维度统计
    by_dimension = {}
    for r in results:
        dim = r.get("risk_dimension", "unknown")
        if dim not in by_dimension:
            by_dimension[dim] = {"total": 0, "pass": 0, "fail": 0}
        by_dimension[dim]["total"] += 1
        if r["outcome"] == "pass":
            by_dimension[dim]["pass"] += 1
        else:
            by_dimension[dim]["fail"] += 1

    # 分场景统计
    by_scenario = {}
    for r in results:
        scn = r.get("scenario", "unknown")
        if scn not in by_scenario:
            by_scenario[scn] = {"total": 0, "pass": 0, "fail": 0}
        by_scenario[scn]["total"] += 1
        if r["outcome"] == "pass":
            by_scenario[scn]["pass"] += 1
        else:
            by_scenario[scn]["fail"] += 1

    return MetricsSummary(
        total=total,
        pass_rate=outcomes.get("pass", 0) / total,
        soft_fail_rate=outcomes.get("soft_fail", 0) / total,
        hard_fail_rate=outcomes.get("hard_fail", 0) / total,
        by_dimension=by_dimension,
        by_scenario=by_scenario,
    )
