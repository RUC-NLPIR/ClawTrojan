"""Shared DASGuard skill package path helpers."""

from __future__ import annotations

from pathlib import Path


SKILL_PACKAGE_SCAN_NAMES = {
    "SKILL.md",
    "README.md",
    "README.txt",
    "_meta.json",
    "skill.json",
    "package.json",
    "tools.json",
    "schema.json",
    "tool_schema.json",
}

SKILL_PACKAGE_SCAN_NAME_PARTS = ("schema", "tool", "prompt", "workflow")


def skill_dir(rel_path: str) -> Path:
    parts = Path(str(rel_path).replace("\\", "/")).parts
    for idx, part in enumerate(parts):
        if part == "skills" and idx + 1 < len(parts):
            return Path(*parts[: idx + 2])
    return Path(".")


def skill_manifest_paths(root: Path, rel_path: str) -> list[str]:
    package_dir = skill_dir(rel_path)
    return [
        str(package_dir / name)
        for name in ("_meta.json", "skill.json", "package.json")
    ]


def is_skill_package_scan_file(rel_path: str) -> bool:
    normalized = str(rel_path).replace("\\", "/")
    package_dir = skill_dir(normalized)
    if str(package_dir) == ".":
        return False
    path = Path(normalized)
    if path.name in SKILL_PACKAGE_SCAN_NAMES:
        return True
    return path.suffix.lower() in {".md", ".json"} and any(
        part in path.name.lower()
        for part in SKILL_PACKAGE_SCAN_NAME_PARTS
    )
