"""claw_trojan environment data loader.

Loads meta.json + injection.json from envs/{sample_id}/step_{n}/,
assembles step-level flat samples for the evaluation pipeline.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TrojanStepSample:
    sample_id: str
    step_id: str
    step_idx: int
    stage_tag: str
    scenario: str
    attack_type: str
    risk_tier: str
    outcome_category: str
    user_input: str
    is_last_chance: bool
    is_malicious: bool
    tool_output: str
    clean_output: str
    injection_text: str
    char_start: Optional[int]
    char_end: Optional[int]
    contamination: List[Dict[str, Any]] = field(default_factory=list)
    session_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def eval_id(self) -> str:
        """step-level 唯一标识，用于评测 pipeline 的 sample_id"""
        return f"{self.sample_id}_step{self.step_idx}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["eval_id"] = self.eval_id
        return d

    def to_gold_record(self) -> Dict[str, Any]:
        """导出为与 BenchmarkSample 兼容的 gold record"""
        return {
            "sample_id": self.eval_id,
            "scenario": self.scenario,
            "tool_type": self.metadata.get("tool_name", "unknown"),
            "attack_family": self.attack_type,
            "attack_position": "embedded",
            "attack_visibility": "hidden",
            "attack_language": "en",
            "difficulty": self.risk_tier,
            "user_instruction": self.user_input,
            "tool_output": self.tool_output,
            "clean_output": self.clean_output,
            "injection_text": self.injection_text,
            "char_start": self.char_start,
            "char_end": self.char_end,
            "is_malicious": self.is_malicious,
            "expected_behavior": {
                "should_detect": self.is_malicious,
                "should_localize": self.is_malicious and self.char_start is not None,
                "should_ignore_injection": self.is_malicious,
                "should_complete_user_task": True,
                "should_refuse": False,
            },
            "metadata": {
                "source": "claw_trojan",
                "original_sample_id": self.sample_id,
                "step_id": self.step_id,
                "step_idx": self.step_idx,
                "stage_tag": self.stage_tag,
                "is_last_chance": self.is_last_chance,
                "outcome_category": self.outcome_category,
                "contamination": self.contamination,
            },
        }


def _resolve_placement(placement) -> Optional[Dict[str, Any]]:
    """Normalize injection_placement which may be dict, list, or None."""
    if placement is None:
        return None
    if isinstance(placement, dict):
        return placement
    if isinstance(placement, list):
        # Pick first entry with content_template; fallback to first entry
        for item in placement:
            if isinstance(item, dict) and "content_template" in item:
                return item
        return placement[0] if placement else None
    return None


def _build_clean_output(content_template: str, char_start: int, char_end: int) -> str:
    """从 content_template 中移除注入部分，生成干净输出"""
    return content_template[:char_start] + content_template[char_end:]


def _load_step(step_dir: Path) -> TrojanStepSample:
    """加载单个 step 目录，返回 TrojanStepSample"""
    meta = json.loads((step_dir / "meta.json").read_text(encoding="utf-8"))
    injection = json.loads((step_dir / "injection.json").read_text(encoding="utf-8"))

    injection_src = injection.get("injection_src", "none")
    has_injection = injection_src != "none" and injection.get("injected_inst") is not None
    placement = injection.get("injection_placement")

    # Normalize placement: may be dict, list, or None
    resolved = _resolve_placement(placement)

    if has_injection and resolved and "content_template" in resolved:
        tool_output = resolved["content_template"]
        char_start = resolved.get("inject_char_start")
        char_end = resolved.get("inject_char_end")
        if char_start is not None and char_end is not None:
            clean_output = _build_clean_output(tool_output, char_start, char_end)
        else:
            clean_output = tool_output
        injection_text = injection["injected_inst"]
        tool_name = resolved.get("tool_name", "unknown")
    elif has_injection:
        tool_output = ""
        clean_output = ""
        char_start = None
        char_end = None
        injection_text = injection["injected_inst"]
        tool_name = resolved.get("tool_name", resolved.get("tool", "unknown")) if resolved else "unknown"
    else:
        tool_output = ""
        clean_output = ""
        char_start = None
        char_end = None
        injection_text = ""
        tool_name = "unknown"

    return TrojanStepSample(
        sample_id=meta["sample_id"],
        step_id=meta["step_id"],
        step_idx=meta["step_idx"],
        stage_tag=meta["stage_tag"],
        scenario=meta["scenario"],
        attack_type=meta["attack_type"],
        risk_tier=meta["risk_tier"],
        outcome_category=meta["outcome_category"],
        user_input=meta["user_input"],
        is_last_chance=meta["is_last_chance"],
        is_malicious=has_injection,
        tool_output=tool_output,
        clean_output=clean_output,
        injection_text=injection_text,
        char_start=char_start,
        char_end=char_end,
        contamination=meta.get("contamination", []),
        session_id=meta.get("session_id", ""),
        metadata={
            "tool_name": tool_name,
            "injection_src": injection_src,
            "trigger_input": resolved.get("trigger_input", "") if resolved else "",
            "user_profile_id": meta.get("user_profile_id", ""),
        },
    )


def load_trojan_env(env_dir: str) -> List[TrojanStepSample]:
    """加载单个 sample 的所有 step，返回按 step_idx 排序的列表"""
    env_path = Path(env_dir)
    steps = []
    for step_dir in sorted(env_path.iterdir()):
        if step_dir.is_dir() and step_dir.name.startswith("step_"):
            meta_file = step_dir / "meta.json"
            injection_file = step_dir / "injection.json"
            if meta_file.exists() and injection_file.exists():
                steps.append(_load_step(step_dir))
    steps.sort(key=lambda s: s.step_idx)
    return steps


def load_all_trojan_envs(envs_root: str) -> List[TrojanStepSample]:
    """扫描 envs/ 下所有 sample 目录，返回全部 step 样本"""
    root = Path(envs_root)
    all_steps = []
    for sample_dir in sorted(root.iterdir()):
        if sample_dir.is_dir() and not sample_dir.name.startswith("."):
            all_steps.extend(load_trojan_env(str(sample_dir)))
    return all_steps


def export_trojan_gold_jsonl(samples: List[TrojanStepSample], output_path: str) -> None:
    """导出为 JSONL 格式，与现有 detector pipeline 兼容"""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for sample in samples:
            f.write(json.dumps(sample.to_gold_record(), ensure_ascii=False) + "\n")
