"""Parse and summarize AgentDojo benchmark output."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


UTILITY_RE = re.compile(r"Average utility:\s*([0-9.]+)%")
SECURITY_RE = re.compile(r"Average security:\s*([0-9.]+)%")
SUITE_RE = re.compile(r"Results for suite\s+(.+)")


def parse_stdout_summary(stdout: str) -> Dict[str, Any]:
    """Parse the stable human-readable summary printed by AgentDojo."""
    current_suite: Optional[str] = None
    suites: Dict[str, Dict[str, float]] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        suite_match = SUITE_RE.search(line)
        if suite_match:
            current_suite = suite_match.group(1).strip()
            suites.setdefault(current_suite, {})
            continue
        utility_match = UTILITY_RE.search(line)
        if utility_match and current_suite:
            suites.setdefault(current_suite, {})["utility"] = float(utility_match.group(1)) / 100.0
            continue
        security_match = SECURITY_RE.search(line)
        if security_match and current_suite:
            targeted_asr = float(security_match.group(1)) / 100.0
            suites.setdefault(current_suite, {})["security"] = targeted_asr
            suites[current_suite]["targeted_asr"] = targeted_asr
            suites[current_suite]["defense_success_rate"] = 1.0 - targeted_asr
    return {"suites": suites}


def summarize_records(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    completed = [record for record in records if record.get("returncode") == 0]
    failed = [record for record in records if record.get("returncode") != 0]
    by_condition: Dict[str, Dict[str, Any]] = {}
    for record in records:
        condition = str(record.get("condition", "unknown"))
        parsed = record.get("parsed_stdout", {})
        by_condition.setdefault(condition, {"runs": 0, "suites": {}, "failures": 0})
        by_condition[condition]["runs"] += 1
        if record.get("returncode") != 0:
            by_condition[condition]["failures"] += 1
        for suite, metrics in parsed.get("suites", {}).items():
            by_condition[condition]["suites"][suite] = metrics
    return {
        "runs": len(list(records)) if not isinstance(records, list) else len(records),
        "completed": len(completed),
        "failed": len(failed),
        "by_condition": by_condition,
    }


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
