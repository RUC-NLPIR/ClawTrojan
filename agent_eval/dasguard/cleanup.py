"""DASGuard cleanup helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .embedder import BaseDasGuardEmbedder, create_dasguard_embedder
from .scanner import classify_sink, classify_source
from .skill_package import is_skill_package_scan_file, skill_manifest_paths


def cleanup_source_label(rel_path: str, *, suspected_compromise: bool = False) -> str:
    if suspected_compromise:
        sink_class = classify_sink(str(rel_path))
        if sink_class in {"memory", "agent_instruction", "skill", "policy", "template"}:
            return "compromised_artifact"
    return classify_source(str(rel_path))


SKILL_CAPABILITY_PATTERNS = {
    "external_message": re.compile(r"\b(send|email|message|notify|forward)\b", re.IGNORECASE),
    "external_share": re.compile(r"\b(share|upload|export|publish|webhook)\b", re.IGNORECASE),
    "credential_access": re.compile(r"\b(secret|credential|token|api[_ -]?key|password)\b", re.IGNORECASE),
    "memory_write": re.compile(r"\b(remember|save to memory|persist|memory preference)\b", re.IGNORECASE),
    "policy_update": re.compile(r"\b(policy|approval|exception|runbook|checklist|permission)\b", re.IGNORECASE),
}

CAPABILITY_ALIASES = {
    "external_message": ("email", "message", "notify", "send", "smtp"),
    "external_share": ("share", "upload", "export", "publish", "webhook"),
    "credential_access": ("secret", "credential", "token", "api-key", "api_key", "password"),
    "memory_write": ("memory", "remember", "persist"),
    "policy_update": ("policy", "approval", "exception", "runbook", "permission"),
}

SKILL_CAPABILITY_EMBEDDING_THRESHOLD = 0.34

SKILL_CAPABILITY_PROTOTYPES = [
    ("external_message", "send email"),
    ("external_message", "dispatch notification"),
    ("external_message", "message recipient"),
    ("external_share", "share file"),
    ("external_share", "upload artifact"),
    ("external_share", "sync external destination"),
    ("external_share", "publish webhook"),
    ("credential_access", "access secret"),
    ("credential_access", "use configured credential"),
    ("credential_access", "read api key"),
    ("memory_write", "remember preference"),
    ("memory_write", "persist memory"),
    ("memory_write", "save default workflow"),
    ("policy_update", "update policy"),
    ("policy_update", "approval exception"),
    ("policy_update", "modify runbook checklist"),
]


def skill_supply_chain_guard(
    root: Path,
    rel_path: str,
    text: str,
    *,
    embedder: Optional[BaseDasGuardEmbedder] = None,
    use_embedding: bool = True,
) -> Dict[str, Any]:
    normalized = str(rel_path).replace("\\", "/")
    if not is_skill_package_scan_file(normalized):
        return {}

    active_embedder = None
    if use_embedding:
        active_embedder = embedder or create_dasguard_embedder()
    required, evidence = _required_skill_capabilities(
        text,
        embedder=active_embedder,
        use_embedding=use_embedding,
    )
    declared = _declared_skill_capabilities(root, normalized)
    missing = [
        capability
        for capability in required
        if not _declares_capability(capability, declared)
    ]
    return {
        "enabled": True,
        "required_capabilities": required,
        "declared_capabilities": declared,
        "missing_capabilities": missing,
        "manifest_paths": _skill_manifest_paths(root, normalized),
        "capability_evidence": evidence,
    }


def _required_skill_capabilities(
    text: str,
    *,
    embedder: Optional[BaseDasGuardEmbedder],
    use_embedding: bool,
) -> tuple[List[str], Dict[str, List[Dict[str, Any]]]]:
    required: set[str] = set()
    evidence: Dict[str, List[Dict[str, Any]]] = {}
    for capability, pattern in SKILL_CAPABILITY_PATTERNS.items():
        if pattern.search(text or ""):
            required.add(capability)
            evidence.setdefault(capability, []).append({"detector": "regex"})
    if use_embedding and embedder is not None:
        embedding_required, embedding_evidence = _embedding_skill_capabilities(text, embedder)
        required.update(embedding_required)
        for capability, items in embedding_evidence.items():
            evidence.setdefault(capability, []).extend(items)
    return sorted(required), evidence


def _skill_capability_prototype_embeddings(
    embedder: BaseDasGuardEmbedder,
) -> List[tuple[str, str, List[float]]]:
    cached = getattr(embedder, "_dasguard_skill_capability_prototypes", None)
    if cached is not None:
        return cached
    vectors = embedder.embed_batch([text for _, text in SKILL_CAPABILITY_PROTOTYPES])
    prototypes = [
        (capability, text, vector)
        for (capability, text), vector in zip(SKILL_CAPABILITY_PROTOTYPES, vectors)
    ]
    setattr(embedder, "_dasguard_skill_capability_prototypes", prototypes)
    return prototypes


def _embedding_skill_capabilities(
    text: str,
    embedder: BaseDasGuardEmbedder,
) -> tuple[set[str], Dict[str, List[Dict[str, Any]]]]:
    prototypes = _skill_capability_prototype_embeddings(embedder)
    capabilities: set[str] = set()
    evidence: Dict[str, List[Dict[str, Any]]] = {}
    for span in _skill_capability_spans(text):
        vec = embedder.embed(span)
        if not any(vec):
            continue
        for capability, proto, proto_vec in prototypes:
            score = embedder.cosine(vec, proto_vec)
            if score < SKILL_CAPABILITY_EMBEDDING_THRESHOLD:
                continue
            capabilities.add(capability)
            evidence.setdefault(capability, []).append({
                "detector": "embedding",
                "similarity": round(score, 4),
                "prototype": proto,
                "span": span[:200],
            })
    return capabilities, evidence


def _skill_capability_spans(text: str) -> Iterable[str]:
    for line in str(text or "").splitlines():
        span = line.strip()
        if span:
            yield span


def _declared_skill_capabilities(root: Path, rel_path: str) -> List[str]:
    declarations: List[str] = []
    for path in _skill_manifest_paths(root, rel_path):
        manifest_path = root / path
        if not manifest_path.exists():
            continue
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        declarations.extend(_collect_capability_strings(data))
    return sorted(set(declarations))


def _skill_manifest_paths(root: Path, rel_path: str) -> List[str]:
    return skill_manifest_paths(root, rel_path)


def _collect_capability_strings(data: Any) -> List[str]:
    values: List[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in {"capabilities", "capability", "permissions", "permission", "tools"}:
                values.extend(_flatten_declaration_strings(str(key).lower(), value))
            elif isinstance(value, (dict, list)):
                values.extend(_collect_capability_strings(value))
    elif isinstance(data, list):
        for item in data:
            values.extend(_collect_capability_strings(item))
    return [_normalize_capability(value) for value in values if value]


def _flatten_declaration_strings(key: str, value: Any) -> Iterable[str]:
    if key == "tools" and isinstance(value, list) and any(isinstance(item, dict) for item in value):
        for item in value:
            if isinstance(item, dict):
                for nested_key in ("capabilities", "capability", "permissions", "permission"):
                    if nested_key in item:
                        yield from _flatten_strings(item[nested_key])
            else:
                yield from _flatten_strings(item)
        return
    yield from _flatten_strings(value)


def _flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, bool) and item:
                yield str(key)
            else:
                yield from _flatten_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _flatten_strings(item)


def _declares_capability(capability: str, declared: List[str]) -> bool:
    aliases = CAPABILITY_ALIASES.get(capability, ())
    return any(
        alias in item
        for item in declared
        for alias in aliases
    )


def _normalize_capability(value: str) -> str:
    return re.sub(r"[^a-z0-9_+-]+", "-", str(value).strip().lower()).strip("-")
