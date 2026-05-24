"""Lightweight DASGuard provenance graph.

The graph is intentionally deterministic and compact. It records trusted
control nodes, untrusted data nodes, side-effect payload nodes, and sink nodes,
then attaches simple text-overlap evidence for source-to-sink attribution.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


UNTRUSTED_LABELS = {
    "tool_untrusted",
    "external_source",
    "skill_metadata",
    "memory_persistent",
    "derived_untrusted",
    "compromised_artifact",
}


@dataclass
class ProvenanceNode:
    node_id: str
    kind: str
    label: str
    text_hash: str
    text_preview: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    src: str
    dst: str
    kind: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0


@dataclass
class SpanAttribution:
    start: int
    end: int
    source_node_id: str
    source_label: str
    method: str
    score: float
    evidence: Dict[str, Any] = field(default_factory=dict)


class ProvenanceGraph:
    """In-memory source-to-sink graph for one sandbox run."""

    def __init__(self) -> None:
        self.nodes: Dict[str, ProvenanceNode] = {}
        self.edges: List[ProvenanceEdge] = []
        self._counter = 0

    def add_node(
        self,
        kind: str,
        label: str,
        text: str,
        *,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        self._counter += 1
        prefix = re.sub(r"[^a-z0-9]+", "_", kind.lower()).strip("_") or "node"
        node_id = f"{prefix}_{self._counter:04d}"
        self.nodes[node_id] = ProvenanceNode(
            node_id=node_id,
            kind=kind,
            label=label,
            text_hash=_hash_text(text),
            text_preview=_preview(text),
            metadata=metadata or {},
        )
        return node_id

    def add_edge(
        self,
        src: str,
        dst: str,
        kind: str,
        *,
        evidence: Optional[Dict[str, Any]] = None,
        score: float = 0.0,
    ) -> None:
        self.edges.append(
            ProvenanceEdge(
                src=src,
                dst=dst,
                kind=kind,
                evidence=evidence or {},
                score=round(float(score), 4),
            )
        )

    def add_source(
        self,
        *,
        kind: str,
        label: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        return self.add_node(kind, label, text, metadata=metadata)

    def add_sink_flow(
        self,
        *,
        tool_name: str,
        sink_path: str,
        payload: str,
        source_matches: List[SpanAttribution],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, str]:
        payload_id = self.add_node(
            "tool_input",
            "derived_untrusted" if any(m.source_label in UNTRUSTED_LABELS for m in source_matches) else "workspace_clean",
            payload,
            metadata={"tool_name": tool_name, **(metadata or {})},
        )
        sink_id = self.add_node(
            "sink",
            "side_effect",
            payload,
            metadata={"tool_name": tool_name, "sink_path": sink_path},
        )
        self.add_edge(payload_id, sink_id, "written_to", evidence={"sink_path": sink_path}, score=1.0)
        for match in source_matches:
            self.add_edge(
                match.source_node_id,
                payload_id,
                "derived_from",
                evidence={
                    "method": match.method,
                    "start": match.start,
                    "end": match.end,
                    **match.evidence,
                },
                score=match.score,
            )
        return payload_id, sink_id

    def find_sources_for_text(self, text: str, *, min_score: float = 0.18) -> List[SpanAttribution]:
        """Return source nodes whose text appears to contribute to payload."""
        matches: List[SpanAttribution] = []
        payload_tokens = set(_tokens(text))
        if not payload_tokens:
            return matches

        marker_labels = re.findall(
            r"BEGIN_DASGUARD_SOURCE label=([a-z_]+)",
            text,
            flags=re.IGNORECASE,
        )
        for node in self.nodes.values():
            node_tokens = set(_tokens(node.text_preview))
            if not node_tokens:
                continue
            overlap = payload_tokens.intersection(node_tokens)
            score = len(overlap) / max(1, min(len(payload_tokens), len(node_tokens)))
            method = "token_overlap"
            if node.text_preview and node.text_preview in text:
                score = max(score, 1.0)
                method = "substring"
            if marker_labels and node.label in marker_labels:
                score = max(score, 0.95)
                method = "dasguard_marker"
            if score < min_score:
                continue
            start, end = _best_span_bounds(text, overlap)
            matches.append(
                SpanAttribution(
                    start=start,
                    end=end,
                    source_node_id=node.node_id,
                    source_label=node.label,
                    method=method,
                    score=score,
                    evidence={"overlap_terms": sorted(overlap)[:12]},
                )
            )
        matches.sort(key=lambda item: item.score, reverse=True)
        return matches[:8]

    def infer_label_for_text(self, text: str) -> tuple[str, List[SpanAttribution]]:
        matches = self.find_sources_for_text(text)
        if any(match.source_label in UNTRUSTED_LABELS for match in matches):
            return "derived_untrusted", matches
        if matches:
            return matches[0].source_label, matches
        return "workspace_clean", []

    def export_json(self) -> Dict[str, Any]:
        return {
            "nodes": [asdict(node) for node in self.nodes.values()],
            "edges": [asdict(edge) for edge in self.edges],
        }


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _preview(text: str, limit: int = 600) -> str:
    return " ".join(str(text).split())[:limit]


def _tokens(text: str) -> List[str]:
    return [tok for tok in re.findall(r"[a-z0-9_@./-]+", str(text).lower()) if len(tok) > 2]


def _best_span_bounds(text: str, overlap: set[str]) -> tuple[int, int]:
    lower = text.lower()
    positions = [lower.find(term) for term in overlap if lower.find(term) >= 0]
    if not positions:
        return 0, min(len(text), 240)
    start = max(0, min(positions) - 80)
    end = min(len(text), max(positions) + 160)
    return start, end


def graph_to_metadata(graph: Optional[ProvenanceGraph]) -> Dict[str, Any]:
    if graph is None:
        return {}
    data = graph.export_json()
    return json.loads(json.dumps(data, ensure_ascii=False))
