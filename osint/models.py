from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EntityKind(str, Enum):
    telegram = "telegram"
    username = "username"
    email = "email"
    phone = "phone"
    domain = "domain"
    url = "url"
    ip = "ip"
    text = "text_query"
    image_url = "image_url"
    pdf_url = "pdf_url"


class Entity(BaseModel):
    kind: EntityKind
    value: str
    normalized: str
    confidence: float = 0.8
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchHit(BaseModel):
    title: str
    url: str
    snippet: str = ""
    engine: str
    query: str = ""
    domain: str = ""
    final_url: str | None = None
    status_code: int | None = None
    score: float = 0.0
    confidence: float = 0.5
    relevance_score: float = 0.0
    risk_score: float = 0.0
    is_noisy: bool = False
    is_official_profile: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str
    title: str
    source: str
    description: str = ""
    source_url: str | None = None
    confidence: float = 0.5
    data: dict[str, Any] = Field(default_factory=dict)
    entities: list[Entity] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    label: str
    group: str
    title: str = ""
    value: int = 1
    icon: str = ""


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str = ""
    confidence: float = 0.5


class GraphData(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class ScanResult(BaseModel):
    query: str
    entity: Entity
    mode: str = "basic"
    status: str = "completed"
    confidence: float = 0.0
    refusal_reason: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    search_hits: list[SearchHit] = Field(default_factory=list)
    graph: GraphData = Field(default_factory=GraphData)
    summary: dict[str, Any] = Field(default_factory=dict)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def recompute_summary(self) -> None:
        self.confidence = round(
            max([self.entity.confidence, *[finding.confidence for finding in self.findings], 0.0]),
            2,
        )
        entity_counter: dict[str, int] = {}
        risk_scores: list[float] = []
        for finding in self.findings:
            for entity in finding.entities:
                entity_counter[entity.kind.value] = entity_counter.get(entity.kind.value, 0) + 1
            risk = finding.data.get("risk_score") if isinstance(finding.data, dict) else None
            if isinstance(risk, (int, float)):
                risk_scores.append(float(risk))
        for hit in self.search_hits:
            if hit.risk_score:
                risk_scores.append(hit.risk_score)
        self.summary = {
            "entity_type": self.entity.kind.value,
            "findings": len(self.findings),
            "search_hits": len(self.search_hits),
            "confidence": self.confidence,
            "risk_score": round(max(risk_scores) if risk_scores else 0.0, 2),
            "entity_counters": entity_counter,
            "mode": self.mode,
        }
